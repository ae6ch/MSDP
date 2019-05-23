/* msdp.c - A Really Poor implementation of MSDP... but its getting better! 		
 * 4/15/99 Steve Rubin (ser@tch.org)			
*/

/* 5/06    (ser) - Added the code to dump SA to pgsql */
/* 6/7/99  (ser) - Got rid of the troublesome alignment problems (I suck), 
		   added SA-REQUEST(receive and respond) and SA-RESPONSE 	
		   (receive and send) */
/* 5/29/99 (ser) - I think I fixed the SIGPIPE problem!! yay! */
/* 5/26/99 (ser) - cleaned up main(), added a peer state mech. */
/* 5/25/99 (ser) - fixed disconnect/reconnect problem, made some changes to the 		   way peers are added */
/* 5/21/99 (ser) - fixed sa-cache msdp-sa-loop() memory leak */
/* 5/10/99 (ser) - added support for multiple peers, select(), and recv keepalives, SA Cache */

/* Todo
 	* Currently will not listen for a connection
	* Some sort of tunable RPF filter since we don't really have an easy
	  way of doing this?  Perhaps call an external function that could
	  interface with "some other code".  Otherwise I suppose we could just
	  dump the SA's too all other peers and let them figure it out :).
	* Fix the nasty nslookup()
	* Create some sort of config file for peer configuration + other options
 	* Create a cisco-like(tm) UI
	* Do something productive with encaps'd SA data (forward to PEERS!)
	* more command line intelligence
*/

/* Features */
#define PG_BACKEND		/* PostgresSQL backend */
#define DB "dbname=somedb user=someuser password=somepass";
/* #define SA_CACHE		/* Keep an SA Cache */
/* #define DNSLOOKUP		/* attempt to resolv things, not recommended */
/* #define FORWARD_SA		/* Forward SA messages */
/* #define SA_REQ_RESPOND		/* Respond to SA Request Messages */

/* Debug / (not)Usefull stuff you may want to know */
/* #define DEBUG_STATE		/* Print out peer state changes */
/* #define DEBUG_SOCKET 	/* Print out socket debuging details */
/* #define DEBUG_MSDP		/* Print out Generic MSDP Info */
/* #define DEBUG_SA		/* Print out SA Messages  */
/* #define DEBUG_SA_ENCAPS	/* Print out info about encapsed SA data */
/* #define DEBUG_SELECT		/* Print outs of useless select debugs */
/* #define CACHE_UPDATES	/* Print out Cache creates/updates/deletes */
#define KEEPALIVE_INFO		/* Display Sent/Recvd keepalives */
/* #define PEER_POINTER_MAGIC	/* Useless pointer info for msdp peers */

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#ifdef PG_BACKEND
#include <libpq-fe.h>
PGconn	*dbh;
#endif
#include "msdp.h"



/* struct peer *p,*h; */
struct peer *h;

unsigned int cache_size=0;

struct sa_cache *sa_p,*sa_h;

uint8_t read8(struct peer *p) {
	uint8_t d;

	if(recv(p->s,&d,1,MSG_WAITALL) == 1) 
		return(d);
	else 
	open_peer(p);
	return(0);	
		
}

uint16_t read16(struct peer *p) {
        uint16_t d;  
 
        if(recv(p->s,&d,2,MSG_WAITALL) == 2)
                return(d);
        else
        open_peer(p);
	return(0);
}

uint32_t read32(struct peer *p) {
        uint32_t d;  
 
        if(recv(p->s,&d,4,MSG_WAITALL) == 4)
                return(d);
        else
        open_peer(p);
	return(0);
}


char *nslookup(u_long addr) {
        struct hostent *h;
        static char hostname[255];
	struct in_addr i;

	hostname[0]='\0';

        strcpy(hostname,"");
#ifdef DNSLOOKUP
        if (h=gethostbyaddr(&addr,sizeof(addr),AF_INET))
                strcpy(hostname,h->h_name);

#endif DNSLOOKUP

	if(!strlen(hostname)) {
		i.s_addr = addr;
		strcpy(hostname,inet_ntoa(i));	
	}

        return(&hostname);
}


int connect_socket(char *hostname, int portnum) { 
  struct sockaddr_in sa;
  struct hostent *hp;
  int a, s;

/*
  printf("Opening connection to: %s:%d...",hostname,portnum);
*/
   if ((hp=gethostbyname(hostname)) == NULL) { /* do we know the host's */
     errno=ECONNREFUSED;                       /* address? */
     return(-1);                                /* no */
   }

   bzero(&sa,sizeof(sa));
   bcopy(hp->h_addr,(char *)&sa.sin_addr,hp->h_length); /* set address */
   sa.sin_family= hp->h_addrtype;
   sa.sin_port= htons((u_short)portnum);

   if ((s= socket(hp->h_addrtype,SOCK_STREAM,0)) < 0)   /* get socket */
     return(-1);
   if (connect(s,&sa,sizeof sa) < 0) {                  /* connect */
     close(s);
     return(-1);
   }
   return(s);
}

int msdp_sa_loop(struct peer *p, uint8_t *msgbuf, uint8_t count, uint16_t ourlen)  {

#ifdef SA_CACHE
	struct sa_cache *new_sa;
#endif SA_CACHE

	struct h_msdp sa;
	struct msdp_sg sg;
	char dbstring[255];
	char rp[255];
	char src[255];
	char grp[255];
	int i=1;
	int c,enc;
	size_t r;
	void *sabuf;
	uint8_t *buf;
	uint32_t ourp;
	uint16_t encread;

	c=count;
	ourp=*((uint32_t *) (msgbuf+1));		/* get rp */
	buf=msgbuf+(20-3);		/* skip initial SA */

#ifdef  DEBUG_MSDP
	/* if (c > 1) printf("Getting %d more SA's...\n",c-1); */
#endif	DEBUG_MSDP

	while(i < c) {
		sg.res=*((uint16_t *) buf);
		sg.glen=*((uint8_t *) (buf+2));
		sg.slen=*((uint8_t *) (buf+3));
		sg.group=*((uint32_t *) (buf+4));
		sg.source=*((uint32_t *) (buf+8));

#ifdef  FORWARD_SA
	        /* Forward SA message to all peers but current */
		memcpy(&sa.sg,&sg,sizeof(struct msdp_sg));
		sa.rp = ourp;
       		msdp_forward_sa(p,&sa);
#endif  FORWARD_SA

		strcpy(src,nslookup(sg.source));
		strcpy(grp,nslookup(sg.group));	
		strcpy(rp,nslookup(ourp));

#ifdef 		DEBUG_SA		
		printf("%s: (%s, %s), RP %s\n",nslookup(p->ip),src,grp,rp);
#endif		DEBUG_SA
		
#ifdef		PG_BACKEND
		/* Write SA to database */
		sprintf(dbstring, "INSERT into entry (timestamp,peer,src,grp,rp) values (CURRENT_TIMESTAMP,'%s','%s','%s','%s')",nslookup(p->ip),src,grp,rp);
		PQexec(dbh, dbstring);
	
#endif

#ifdef	SA_CACHE
		new_sa=malloc(sizeof(struct sa_cache));
/*		printf("MALLOC %p\n",new_sa); */
		new_sa->rp=ourp;
		new_sa->grp=sg.group;
		new_sa->src=sg.source;
		new_sa->glen=sg.glen;
		new_sa->slen=sg.slen;
		new_sa->create=time(NULL);
		new_sa->update=new_sa->create;
		if (update_sa(new_sa)) insert_sa(new_sa);
		else
			free(new_sa);
#endif	SA_CACHE
		i++;
		buf += 12;
	} 
	

	if (enc=ourlen - (8+(12*count))) { /* Look for encaps SA data */

		sabuf=malloc(enc);
#ifdef DEBUG_SA_ENCAPS
		printf("<DEBUG_SA_ENCAPS> Reading %d bytes of encapsulated data to %p\n",enc,sabuf);

#endif DEBUG_SA_ENCAPS

		for(encread=0; encread < enc; encread=encread+r) {
			printf("reading...");
			r=recv(p->s,sabuf,enc,MSG_WAITALL);
			printf("got %d - errno %d\n",r,errno);
		}



/*	
		r=recv(p->s,sabuf,enc,MSG_WAITALL);
		if (r < enc) { 
			free(sabuf);
			open_peer(p);	
			return(1);
		}
*/

		/* do something with the data here */

#ifdef  FORWARD_SA
        /* Forward SA encapsed data to all peers but current */
        msdp_send_msg_all(p,sabuf,enc);
#endif  FORWARD_SA

		free(sabuf);
	}

	return(0);
}

int msdp_msg_loop(struct peer *p) {	/* return 0 if no errors in proccess */
#ifdef SA_CACHE         
        struct sa_cache *new_sa;
#endif SA_CACHE  
	uint16_t unklen;
	uint8_t msgtype;
	uint8_t *msgbuf;
	struct msdp_sareq sar; 
	struct h_msdp m;
	struct msdp_keepalive k;
	size_t r;			/* bytes read from socket */
	int sd;			/* bytes of sa data */
	int i;			/* whatever */
	unsigned int x,y;	/* used for type 1 sa-data size calc */
	char rp[255];
	char src[255];
	char grp[255];

		msgtype=read8(p);
		if (p->st != STATE_CONNECTED) return(1);
/*		printf("MSGTYPE = %d\n",msgtype);   */
		/***** received keepalive *****/
		if (msgtype == MSDP_TYPE_KEEPALIVE) {
			msgbuf=malloc(2);
			r=recv(p->s,msgbuf,2,MSG_WAITALL);
			if (r < 2) {
				 free(msgbuf);
				 open_peer(p); 
				 return(1);
			}
		
			k.type=msgtype;
			k.len=*msgbuf;
			free(msgbuf);

			
#ifdef	KEEPALIVE_INFO
			printf("%s: received keepalive\n",nslookup(p->ip));
#endif	KEEPALIVE_INFO
			return(0);
		}

#ifdef  SA_REQ_RESPOND
		/***** received SA REQUEST *****/
	 	if (msgtype == MSDP_TYPE_SA_REQUEST) {
			sar.type=msgtype;
			sar.len=ntohs(read16(p));
			if (p->st != STATE_CONNECTED) return(1);
			msgbuf=malloc(sar.len);
			r=recv(p->s,msgbuf,(sar.len-3),MSG_WAITALL);
                        if (r < (sar.len-3)) {
				 free(msgbuf);
                                 open_peer(p);
				 return(1);
                        }

			sar.glen=*((uint8_t *) (msgbuf));
			sar.group=*((uint32_t *) (msgbuf+1));
			free(msgbuf);
	
			printf("Received SA Request %s len %d\n",nslookup(sar.group),sar.len);		
			msdp_send_sar(p, sar.group);	  
			return(0); 
		}
#endif	SA_REQ_RESPOND

		/**** received SA ****/
		if (msgtype == MSDP_TYPE_SA_ACTIVE || MSDP_TYPE_SA_RESPONSE) {
			m.type=msgtype;			/* first 8 byte */
			m.len=ntohs(read16(p));
			if (p->st != STATE_CONNECTED) return(1);
			msgbuf=malloc(m.len);
                        r=recv(p->s,msgbuf,(m.len-3),MSG_WAITALL); 
                        if (r < (m.len-3)) {
                                free(msgbuf);  
				open_peer(p); 
				return(1);
                        }

			m.count=*((uint8_t *) msgbuf);
			m.rp=*((uint32_t *) (msgbuf+1));
			m.sg.res=*((uint16_t *) (msgbuf+5));
			m.sg.glen=*((uint8_t *) (msgbuf+7));
			m.sg.slen=*((uint8_t *) (msgbuf+8));
			m.sg.group=*((uint32_t *) (msgbuf+9));
			m.sg.source=*((uint32_t *) (msgbuf+13));

#ifdef			DEBUG_SOCKET
			printf("<DEBUG_SOCKET> read in %d from socket\n");
#endif			DEBUG_SOCKET
		

#ifdef			DEBUG_MSDP
			strcpy(rp,nslookup(m.rp));
	
			printf("%s: type/length/count/rp %d/%d/%d/%s\n", 
			nslookup(p->ip),m.type,m.len,m.count,rp);	

#endif			DEBUG_MSDP

#ifdef 	DEBUG_SA		
			strcpy(src,nslookup(m.sg.source));
			strcpy(grp,nslookup(m.sg.group));	
			strcpy(rp,nslookup(m.rp));
			printf("%s: (%s, %s), RP %s\n",nslookup(p->ip),src,grp,rp);
#endif	DEBUG_SA

#ifdef			FORWARD_SA 
			msdp_forward_sa(p,&m);		/* forward first sa */
#endif			FORWARD_SA 
#ifdef  SA_CACHE
		        new_sa=malloc(sizeof(struct sa_cache));
			/*      printf("MALLOC %p\n",new_sa); */
        		new_sa->rp=m.rp;
        		new_sa->grp=m.sg.group;
        		new_sa->src=m.sg.source;
        		new_sa->src=m.sg.glen;
        		new_sa->src=m.sg.slen;
        		new_sa->create=time(NULL);
        		new_sa->update=new_sa->create;
        		if (update_sa(new_sa)) insert_sa(new_sa);
        		else
                		free(new_sa);
#endif  SA_CACHE

			if (m.count > 1) {
				if (msdp_sa_loop(p,msgbuf,m.count,m.len)) {
					free(msgbuf);
					return(1);
				}
			}
			free(msgbuf);		/* this was up a line..
						probably not right */
			return(0);
		}			

		/******  Attempt to recover from unknown type **********
		 * This works because atleast as of now, all the TLV's *
		 * have the length of the TLV right after the type     *
  		 *******************************************************/
		unklen=ntohs(read16(p));
		if (p->st != STATE_CONNECTED) return(1);

#ifdef		DEBUG_MSDP
		printf("Unknown type %d of len %d\n",msgtype,unklen);
#endif		DEBUG_MSDP

		msgbuf=malloc(unklen);
		r=recv(p->s,msgbuf,(unklen-3),MSG_WAITALL);			
		if (r < (unklen-3)) {
			free(msgbuf);
			open_peer(p);
			return(1);
                        }

		return(0);	
}

int msdp_send_keepalive(struct peer *p) {
	uint8_t k[3];

        *k=MSDP_TYPE_KEEPALIVE;
        *((uint16_t *) (k+1))=htons(3);

	msdp_send_msg(p,k,3); 
}

int msdp_forward_sa(struct peer *p, struct h_msdp *t) {
	uint8_t sa[SIZE_RESPONSE];
	*((uint8_t *) (sa+O_SA_TYPE)) = MSDP_TYPE_SA_ACTIVE;
	*((uint16_t *) (sa+O_SA_LEN)) = htons(SIZE_RESPONSE);
	*((uint8_t *) (sa+O_SA_COUNT)) = 1;
	*((uint32_t *) (sa+O_SA_RP)) = t->rp;
	*((uint8_t *) (sa+O_SA_GLEN)) = t->sg.glen;
	*((uint8_t *) (sa+O_SA_SLEN)) = t->sg.slen;
	*((uint32_t *) (sa+O_SA_GROUP)) = t->sg.group;
	*((uint32_t *) (sa+O_SA_SOURCE)) = t->sg.source;
	msdp_send_msg_all(p,&sa,SIZE_RESPONSE);
}


int msdp_send_sar(struct peer *p, long g) {
	struct sa_cache *t;
	uint8_t sar[SIZE_RESPONSE];
	int c=0;


	if(sa_h==NULL) return(0);
	t=sa_h;
	while(t->n) {
		if (t->grp == g) {		
			/* printf("sending %p...\n",t); */
			*((uint8_t *) (sar+O_SA_TYPE)) = MSDP_TYPE_SA_RESPONSE;
			*((uint16_t *) (sar+O_SA_LEN)) = htons(SIZE_RESPONSE);
			*((uint8_t *) (sar+O_SA_COUNT)) = 1;
			*((uint32_t *) (sar+O_SA_RP)) = t->rp;
			*((uint8_t *) (sar+O_SA_GLEN)) = t->glen;
			*((uint8_t *) (sar+O_SA_SLEN)) = t->slen;
			*((uint32_t *) (sar+O_SA_GROUP)) = t->grp;
			*((uint32_t *) (sar+O_SA_SOURCE)) = t->src;
			msdp_send_msg(p,&sar,SIZE_RESPONSE);	 
		}
		t=t->n;
	}
}

int msdp_send_msg(struct peer *p, void *msg, size_t sz) {

	if (p->s == -1) {
		open_peer(p);
		return(1);
	}

	if(send(p->s,msg,sz,0) == -1) open_peer(p);
}

int msdp_send_msg_all(struct peer *rpf, void *msg, size_t sz) {
	struct peer *p;

	p=h;
	while(p) {
		if ( (p != rpf) && (p->s) ) {
/*			printf("Sending Message to %s\n",nslookup(p->ip)); */
			msdp_send_msg(p,msg,sz);
		}
		p=p->n;
	}
}

int msdp_sigkeepalive(int sig, int code, struct sigcontext *scp) {
	struct peer *p;

	msdp_print_peers();
	p=h;
        while(p) {
		if (p->s) {
#ifdef KEEPALIVE_INFO
			printf("%s: Sending keepalive\n",nslookup(p->ip));
#endif KEEPALIVE_INFO
			msdp_send_keepalive(p); 
		} else open_peer(p);
                p=p->n;
        }

#ifdef SA_CACHE	
/*	printf("Firing off SA CACHE Cleaner\n"); 	*/
	/* expire_sa(); */
#endif SA_CACHE

	alarm(MSDP_KEEPALIVE_TIMER);
}


#ifdef SA_CACHE

int expire_sa() {
	struct sa_cache *t;
	time_t extime;
	
	if (sa_h==NULL) return(1);
	t=sa_h;
	extime=time(NULL);
	while(t->n) {
		if (extime - t->update >= MSDP_SA_CACHE_EXPIRE) {
			delete_sa(t);
		}
		t=t->n;
	}
	return(0);
}

int count_sa() {
	struct sa_cache *t;
	int c=0;

	if (sa_h==NULL) return(0);
        t=sa_h;
	while(t->n) {
		t=t->n;
		++c;
	}
	return(c);	
}

int update_sa(struct sa_cache *sa) {
	struct sa_cache *t;
	time_t extime;

	if (sa_h==NULL) return(1);
	t=sa_h;
	extime=time(NULL);
	while(t->n) {
		if (t->rp == sa->rp)
		 if (t->grp == sa->grp)
		  if (t->src == sa->src)
		   if (t->glen == sa->glen)
		    if (t->slen == sa->slen) {
#ifdef	CACHE_UPDATES 
				printf("Updating %p Cache Size %d(%d bytes)\n",t,cache_size,cache_size*sizeof(struct sa_cache));
#endif	CACHE_UPDATES 
		    		t->update=time(NULL);
				return(0);
			}
		if (extime - t->update >= MSDP_SA_CACHE_EXPIRE)
			delete_sa(t);

		t=t->n;
	}
	return(1);
}

int insert_sa(struct sa_cache *sa) {

	sa->n=sa_h;
	sa_h=sa;

#ifdef	CACHE_UPDATES
	printf("Inserting %p next %p Cache Size %d(%d bytes)\n",sa,sa->n,cache_size,cache_size*sizeof(struct sa_cache));
#endif	CACHE_UPDATES
	cache_size++;
}

int delete_sa(struct sa_cache *sa) {
	struct sa_cache *f;

#ifdef	CACHE_UPDATES   
	/* printf("Expiring %p next %p Cache Size %d(%d bytes) Walk Count %d\n",sa,sa->n,cache_size,cache_size*sizeof(struct sa_cache),count_sa());*/
	printf("Expiring %p next %p Cache Size %d(%d bytes)\n",sa,sa->n,cache_size,cache_size*sizeof(struct sa_cache));
#endif	CACHE_UPDATES  

	f=sa_h;
	if (sa_h == sa) sa_h = sa->n;
	else {
		while(f->n != sa) f=f->n; 
		f->n=sa->n;
	}

	cache_size--;	
	/*	printf("FREE %p\n",sa);	*/
	free(sa);
}
#endif SA_CACHE

int print_state_change(struct peer *p) {
#ifdef  DEBUG_STATE
	printf("%s: state change to %s\n",nslookup(p->ip), msdp_states[p->st]);
#endif  DEBUG_STATE
}

int open_peer(struct peer *c) {
	time_t oldtime;
	unsigned char oldstate;

	/* dont want to be active if we are suppose to listen */
	if (c->st == STATE_LISTEN) return(0); 

	/* Some day we will have some sort of 'console' where this might be
           useful to know 
	*/
	oldtime=c->uptime;
	oldstate=c->st;


	if (c->s) {				/* close any existing socket */
		c->st=STATE_IDLE;
		print_state_change(c);
		close(c->s);
	}

 	c->st=STATE_ACTIVE;	
	print_state_change(c);

#ifdef DEBUG_SOCKET
	printf("opening connection to %s\n",nslookup(c->ip));
#endif DEBUG_SOCKET

	c->s=connect_socket(nslookup(c->ip),639);
	/* connect_socket() should return 0 or -1 if it cant open a connection
	   so we should periodicly try to rerun open_peer on that socket ?
        */
	/* printf(" new %d\n",c->s); */


	/* Like I said, someday this might be useful to know.  Eventually
	   there will be a loop that periodicly open_peer()'s anything that
	   has been idle for a while 
 	*/

	if(c->s) { 
		c->st=STATE_CONNECTED;
		c->uptime=time(NULL);
		c->reset++;
		print_state_change(c);
	}

	if(c->s == -1) { 
		c->st=STATE_IDLE;
		print_state_change(c);
	}
	if( (oldstate == STATE_IDLE) && (c->st == STATE_IDLE)) 
		c->uptime=oldtime;
}
struct peer *add_peer(char *name) {
	struct peer *new, *p;

	if(!(new=malloc(sizeof(struct peer)))) {		
		perror("msdp - ");			/* malloc error? */
		exit(1);
	}
	
	/* printf("Adding peer[%s] @ %p\n",name, new);  */
		
	new->s=0;					/* init peer data */
	new->ip=inet_addr(name);
	new->n=0;
	new->st=STATE_IDLE;
	new->reset=0;
	new->uptime=time(NULL);

	if (!h)	{					/* init if needed */
		p=new;		
		h=new;
		return(new);
	} 

	/* printf("p=%p h=%p\n",p,h);  */

	p=h;						/* Icky Global */
	while(p->n) {
	/* 	printf("next=%p p=%p h=%p\n",p->n,p,h);  */
		p=p->n;					/* now p is end of list */
	}
	p->n=new;					/* insert at end */
	return(new);
}

int msdp_block_alarm() {
	sigset_t newmask,oldmask;

	sigemptyset(&oldmask);
	sigemptyset(&newmask);
	sigaddset(&newmask, SIGALRM);
	sigprocmask(SIG_BLOCK, &newmask, &oldmask);
}

int msdp_unblock_alarm() {
	sigset_t newmask,oldmask;

	sigemptyset(&oldmask);
	sigemptyset(&newmask);
	sigaddset(&newmask, SIGALRM);
	sigprocmask(SIG_UNBLOCK, &newmask, &oldmask);
}

int msdp_init() {
	struct sigaction sig;

	/* Initialize various data structs */	
	h=0;					/* Peer's */

	/* Richard Steven's says its safe to do this as long as the RST
           is caught by the next read to the socket.  This is desirable
	   because we have no other way to tell which socket caused the
	   SIGPIPE.   (unix network programming volume 1 second edition)
        */
	sig.sa_handler = SIG_IGN;	
	sigaction(SIGPIPE,&sig,0);

	/* This is not how I want to do this in the long run, but its an
           easy way for now.  I also need some other timers, so until I
 	   put together a better way, we live with SIGALRM 
 	*/
	sigaction(SIGALRM,0,&sig);		
	sig.sa_handler = &msdp_sigkeepalive;
	sigaction(SIGALRM,&sig,0);
	alarm(MSDP_KEEPALIVE_TIMER);


	/* init db */
	#ifdef PG_BACKEND
	dbh = db_init();
	#endif	
}

/* msdp_print_peers() - Prints out a list of all peers in a human readable
			format.  
 */

int msdp_print_peers() {		
	struct peer *p;
	
	/* 
		TODO: Make pointer data an optional define
		 Add pkt (sa?) in/out counter
		 Add last keep alive received/sent display
	*/

	printf("%-25s %-4s %-10s %s\n","Peer","Sock","State","Last");
	printf("------------------------- ---- ---------- ---------------------------\n"); 
	

	p=h;				/* This should be passed instead of a 
					   global variable... ack! */
	while(p) {
		printf("%-25s %-4d %-10s %s",nslookup(p->ip),p->s,msdp_states[p->st],ctime(&p->uptime)); 
		p=p->n;
	}			

}

int msdp_loop() {
	fd_set rfd;
	struct timeval wait;
	struct peer *p;
	
	wait.tv_sec = 0;
	wait.tv_usec = 100;

	while(1) {				/* I hate never ending loops,
						   we should have some way of
						   getting out of this */

	p=h;					/* should be passed to loop,
						   not a global variable! */

	FD_ZERO(&rfd);
	msdp_block_alarm();
	while(p) {				/* Init the read fd set "rfd" */

#ifdef DEBUG_SELECT
		printf("FD_SET for %s\n",nslookup(p->ip));
#endif DEBUG_SELECT

		if (p->s >= 1)  { 
			FD_SET(p->s,&rfd);
		}
		p=p->n;
	} 

	if(select(FD_SETSIZE,&rfd,NULL,NULL,&wait) < 0)  {	
      /*  	printf("error in select()\n");
        	exit(1);  
      */   /* lets ignore that for now and try to live with it */
    	}

	p=h;					/* ack not this again! */
	
	do {					/* service sockets */

#ifdef DEBUG_SELECT
		printf("FD_ISSET for %s\n",nslookup(p->ip));
#endif DEBUG_SELECT

		if(p->s >= 1) {
			if(FD_ISSET(p->s,&rfd)) {

#ifdef DEBUG_SELECT
				printf("Calling msdp_msg_loop for %s\n",nslookup(p->ip));
#endif DEBUG_SELECT

				msdp_block_alarm();
				msdp_msg_loop(p);
				msdp_unblock_alarm();
			}
		}
		p=p->n;
	} while(p);
     msdp_unblock_alarm();
 } 
}


#ifdef PG_BACKEND 

static void
exit_nicely(PGconn *conn)
{
    PQfinish(conn);
    exit(1);
}

PGconn *db_init() {
	PGconn     *dbh;
	const char *conninfo;
	conninfo = DB;
	dbh = PQconnectdb(conninfo);
	if (PQstatus(dbh) != CONNECTION_OK) {
	        fprintf(stderr, "Connection to database failed: %s",
       		PQerrorMessage(dbh));
       		exit_nicely(dbh);
	}
	return(dbh);
}
#endif

int main(int argc, char *argv[]) {
	int x;
	struct peer *new;


	printf("Steve's MSDP v0.7 (http://www.tch.org/~ser/ [ser@tch.org])\n");
	
	if (argc <= 1) {
		printf("usage: %s <peer> [peers...]\n",argv[0]);
		exit(1);
	}	

	/* 
 	   If I wasnt so lazy I'd check to make sure the arg's made some
	   sense  	
	*/

	msdp_init();				/* Init Routines */

	for(x=1; x <= argc-1;++x) {		/* Install peers frm cmd line */
		/* it would be clever to figure if if they should be listen
		   at this point */

		/* add error checking */
		open_peer(add_peer(argv[x]));	
	}

	msdp_print_peers();			/* gratuitous :) */

	msdp_loop();				/* should never end ... */

	return(0);
}

