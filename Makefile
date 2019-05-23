CC=gcc
CFLAGS=-g -I/usr/local/include -L/usr/local/lib
LIB=-lpq

msdp: msdp.c msdp.h
	$(CC) $(CFLAGS) $(LIB) msdp.c -o msdp

