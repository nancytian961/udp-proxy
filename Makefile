#Makefile for qc_proxy
#Author: ntian@fortinet.com

CC=gcc
CFLAGS=-g -I./
LDFLAGS=

PROG=qc_proxy
SRCS=qc_proxy_sock.c qc_proxy_conf.c
OBJS=$(SRCS:.c=.o)

all: $(SRCS) $(PROG)

$(PROG): $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o $@

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(PROG)

