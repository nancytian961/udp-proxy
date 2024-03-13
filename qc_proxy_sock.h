#ifndef __QC_PROXY_SOCK_H__
#define __QC_PROXY_SOCK_H__

#include <arpa/inet.h>
#include "qc_proxy_conf.h"

#define REAL_SERV_ADDR 0
#define LISTEN_ADDR 1

#define MSG_DATA_SIZE 2048

#define MAX_EVENTS 20

#define DIR_C2S 0
#define DIR_S2C 1

#define ARRAY_SIZE(array)    (sizeof(array)/sizeof(array[0]))

typedef struct _qc_proxy_conf { 
    unsigned char listen_ip[40];
    unsigned short listen_port;
    unsigned short lip_type;

    unsigned char server_ip[40];
    unsigned short server_port;
    unsigned short sip_type;
} qc_proxy_conf_t;

typedef struct _msg {
    void *sess;
    int len;
    char data[MSG_DATA_SIZE];
    short dir; 
	/* 
	 * 1. read_from lfd, mgrt = 0, means to connect backend, back1 is ready
	 * 2. after connect backend, mgrt = 1, waiting for handshakdone
	 * 3. handshake done, mgrt =2, connect backend, back2 is ready
	 * 4. if USE_OLD_PATH, send C2S through back2, mgrt = 3, swich back1
	 * */
    short mgrt;
    short back_ready;
}msg_t;

typedef struct _conn {
    struct sockaddr_in me_addr;
    struct sockaddr_in peer_addr;
    int fd;
    void *sess;  //
}conn_t;

typedef struct _sess{
    conn_t front;
    conn_t back1;
    conn_t back2;
}sess_t;


#endif
