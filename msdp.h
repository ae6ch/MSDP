

#define STATE_CONNECTED		1	/* Connection Established */
#define STATE_ACTIVE		2	/* Trying to Connect */
#define STATE_LISTEN		3	/* Listening for connection */
#define STATE_IDLE		4	/* Not able to connect, waiting */

char *msdp_states[] = {"foo","Connected","Active","Listen","Idle"};


#define MSDP_TYPE_SA_ACTIVE	1	
#define MSDP_TYPE_SA_REQUEST	2
#define MSDP_TYPE_SA_RESPONSE	3
#define MSDP_TYPE_KEEPALIVE	4

#define MSDP_KEEPALIVE_TIMER	60 	/* in seconds */
#define MSDP_SA_CACHE_EXPIRE	300	/* in seconds */

struct sa_cache {		/* 1 SA Entry */
	uint32_t rp;
	uint32_t grp;
	uint32_t src;
	uint8_t glen;
	uint8_t slen;

	time_t	create;
	time_t	update;

	void *n;
};

#define O_SA_TYPE	0
#define O_SA_LEN	1
#define	O_SA_COUNT	3
#define O_SA_RP		4
#define O_SA_RESERVED	2
#define	O_SA_GLEN	10
#define O_SA_SLEN	11
#define O_SA_GROUP	12
#define O_SA_SOURCE	16

#define SIZE_RESPONSE	20

struct msdp_sg {		/* Additional SA's */
	uint16_t res:16;
	uint16_t glen:8;
	uint16_t slen:8;
	uint32_t group:32;
	uint32_t source:32;
};

struct h_msdp {			/* MSDP type 1 packet with 1 SA */
	uint8_t type:8;		
	uint16_t len:16;
 	uint8_t count:8;
	uint32_t rp:32;
	struct msdp_sg sg;
};

struct msdp_sareq {		
	uint8_t type:8;				
	uint16_t len:16;
	uint8_t glen:8;
	uint32_t group:32;
};

struct msdp_keepalive {		/* Keepalive Packet */
	uint8_t  type:8;
	uint16_t len:16;
};

struct peer {			/* Peering Sessions */
	int	s;		/* Socket, should be sock_t */
	long	ip;		/* ip address of peer */
	unsigned char st;	/* state */
	time_t	uptime;		/* uptime */
	unsigned int reset;	/* reset count */
	
	void *n;
};

/* proto's */
PGconn *db_init();
int msdp_send_keepalive(struct peer *p);
int msdp_send_msg(struct peer *p, void *msg, size_t sz);
int msdp_send_msg_all(struct peer *rpf, void *msg, size_t sz);
int msdp_sigkeepalive(int sig, int code, struct sigcontext *scp);
int msdp_print_peers();                        
int msdp_loop();
int connect_socket(char *hostname, int portnum); 
int msdp_sa_loop(struct peer *p, uint8_t *msgbuf, uint8_t count, uint16_t ourlen);
 int msdp_msg_loop(struct peer *p);
int expire_sa();
int count_sa();
int update_sa(struct sa_cache *sa);
int insert_sa(struct sa_cache *sa);
int delete_sa(struct sa_cache *sa);
int open_peer(struct peer *c);
int msdp_init();
char *nslookup(u_long addr);
uint8_t read8(struct peer *p);
uint16_t read16(struct peer *p);
uint32_t read32(struct peer *p);


