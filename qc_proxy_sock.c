#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/epoll.h>

#include "qc_proxy_sock.h"
#include "qc_proxy_conf.h"

int nalloc_msg =0;
int nfree_msg = 0;

char default_listen_ip[] = "127.0.0.1";
int  default_listen_port = 14433;
char default_server_ip[] = "30.30.30.100";
int  default_server_port = 443;

qc_proxy_conf_t qproxy_conf;
char qc_proxy_help_msg[] = "qc_proxy Help:\n";

static conf_parse_t globle_conf_parser[256] = {
    ['l'] = {
        .parser = qc_proxy_parse_laddr,
        .must = 0,
        .help_msg = "Local Listener IP address",
    },
    ['s'] = {
        .parser = qc_proxy_parse_sport,
        .must = 0,
        .help_msg = "Local Listener Port",
    },
    ['r'] = {
        .parser = qc_proxy_parse_raddr,
        .must = 0,
        .help_msg = "Real Server IP Address",
    },
    ['d'] = {
        .parser = qc_proxy_parse_dport,
        .must = 0,
        .help_msg = "Real Server Port",
    },
    ['h'] = {
        .parser = NULL, //qc_proxy_parse_help,
        .must = 0,
        .help_msg = qc_proxy_help_msg,
    },
    ['v'] = {
        .parser = NULL, // qc_proxy_parse_version,
        .must = 0,
        .help_msg = "Author: Nancy Tian, Version 1.0.0",
    }
};

static const char *optstring = "hvl:s:r:d:";
static const struct option long_opts[] = {
    {"help", 0, 0, 'h'},
    {"version", 0, 0, 'v'},
    {"local_lstn_ip", 0, 0, 'l'},
    {"local_lstn_port", 0, 0, 's'},
    {"real_serv_ip", 0, 0, 'r'},
    {"real_serv_port", 0, 0, 'd'},
    {0, 0, 0, 0}
};

static const char *options[] = {
    "--help             -h  Print help information\n",
    "--version          -v  Print version information\n",
    "--listen_ip        -l  IP address for listening\n",
    "--listen_port      -s  Port for listening\n",
    "--rserver_ip       -r  IP address for QC real server\n",
    "--rserver_port     -d  Port for QC real server\n",
};

static int qc_proxy_parse_conf(int argc, char**argv)
{
    int i = 0;
    int c = 0;
    unsigned char ch = 0;
    conf_parse_t *handle_parser = NULL;

    /*set default*/
    qproxy_conf.lip_type = 0;
    strcpy(qproxy_conf.listen_ip, default_listen_ip); 
    qproxy_conf.listen_port = default_listen_port;

    qproxy_conf.sip_type = 0;
    strcpy(qproxy_conf.server_ip, default_server_ip);
    qproxy_conf.server_port = default_server_port;

    int num = ARRAY_SIZE(globle_conf_parser);
    while ((c = getopt_long(argc, argv, optstring, long_opts, NULL)) != -1) {

        handle_parser = &globle_conf_parser[c];
        if (handle_parser->parser == NULL){
            printf("%s\n", handle_parser->help_msg);
            if(c=='h')
            {
                for(i = 0; i<ARRAY_SIZE(options); i++)
                    printf("%s", options[i]);
            }
            return -1;
        }
        handle_parser->parser(&qproxy_conf, optarg);

    }//end while
    printf("Listener %s %s:%d\n", (qproxy_conf.lip_type ? "ipv6" : "ipv4"), qproxy_conf.listen_ip, qproxy_conf.listen_port);
    printf("Server   %s %s:%d\n", (qproxy_conf.sip_type ? "ipv6" : "ipv4"), qproxy_conf.server_ip, qproxy_conf.server_port);

    return 0;
}

int qc_proxy_epoll_create()
{
    int efd;
    efd = epoll_create1(0);
    if (efd == -1) {
        perror("epoll_create1");
        return -1;
    }
    return efd;
}

/*add/del fd from epool*/
static int qc_proxy_mod_fd_into_efd(int fd, int efd, int act)
{
    if (fd < 0)
        return 0;

    if (act == 0) {
        struct epoll_event ev;

        ev.events = EPOLLIN;
        ev.data.fd = fd;
        if (epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev) == -1) {
            perror("epoll_ctl: sockfd");
            return -1;
        }
    }
    else {
        epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
        close(fd);
    }
    return 0;
}

static void qc_proxy_free(msg_t *msg, int efd)
{
    if (!msg || efd < 0)
        return;

    sess_t *sess = msg->sess;
    if (sess) {
        conn_t *f  = &sess->front;
        conn_t *b1 = &sess->back1;
        conn_t *b2 = &sess->back2;
        qc_proxy_mod_fd_into_efd(f->fd, efd, 1);
        qc_proxy_mod_fd_into_efd(b1->fd, efd, 1);
        qc_proxy_mod_fd_into_efd(b2->fd, efd, 1);
        free(msg->sess);
    }

    free(msg);
    msg = NULL;
    nfree_msg++;
    printf("Info: free whole session alloc %d, free %d \n", nalloc_msg, nfree_msg);

    return;
}


// Set port and IP:
static void qc_proxy_set_addr(struct sockaddr_in *addr, int listen)
{
    addr->sin_family = AF_INET;
    if (listen) {
        addr->sin_port = htons(qproxy_conf.listen_port);
        addr->sin_addr.s_addr = inet_addr(qproxy_conf.listen_ip);
    } else {
        addr->sin_port = htons(qproxy_conf.server_port);
        addr->sin_addr.s_addr = inet_addr(qproxy_conf.server_ip);
    }

    return;
}

int qc_proxy_listen_create()
{
    int sockfd = -1;
    int sockopt = 1;
    struct sockaddr_in bind_addr;

    // new socket
    sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(sockfd < 0){
        printf("Err: creating listen socket failed\n");
        return -1;
    }
    printf("Info: creating listen socket %d successfully\n", sockfd);

    /*set ip/port */
    qc_proxy_set_addr(&bind_addr, LISTEN_ADDR);

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
               &sockopt, sizeof(sockopt)))
    {
        printf("Err: setting listen socket %d reuse addr failed.\n", sockfd);
        close(sockfd);
        return -1;
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT,
                &sockopt, sizeof(sockopt)))
    {
        printf("Err: setting listen socket %d reuse port failed.\n", sockfd);
        close(sockfd);
        return -1;
    }

    /*bind*/
    if (bind(sockfd, (struct sockaddr*)&bind_addr, sizeof(bind_addr)) < 0) {
        printf("Err: bind to the addr %s:%d failed\n", qproxy_conf.listen_ip, qproxy_conf.listen_port);
        return -1;
    }
    printf("Info: binding socket with listen address successfully\n");

    return sockfd;
}

int qc_proxy_recv_from_lfd(int fd, int efd, msg_t** r_msg)
{ 
    struct sockaddr_in src_addr;
    struct sockaddr_in dst_addr;
    int client_struct_length = sizeof(src_addr);
    int cfd;
    int one_flag = 1;

    msg_t *msg;
    sess_t *sess;
    conn_t *conn;

    msg = malloc(sizeof(msg_t));
    if (!msg) {
        printf("Err: creating msg_t failed \n");
        return -1;
    }

    nalloc_msg++;
    memset(msg->data, '\0', MSG_DATA_SIZE);

    //read data on listen fd
    msg->len = recvfrom(fd, msg->data, sizeof(msg->data), 0,
         (struct sockaddr*)&src_addr, &client_struct_length);
    if (msg->len < 0) {
        printf("Err: read data on listen fd failed.\n");
        return -1;
    }
    printf("Info: a new QC connection from %s:%d\n",
           inet_ntoa(src_addr.sin_addr), ntohs(src_addr.sin_port));

    qc_proxy_set_addr(&dst_addr, LISTEN_ADDR);

    /*bind, connect fd*/
    cfd = socket(src_addr.sin_family, SOCK_DGRAM, 0);
    if (cfd < 0) {
        printf("Err: creating connect_fd faild\n");
        return -1;
    }
    if (setsockopt(cfd, SOL_SOCKET, SO_REUSEADDR, &one_flag, sizeof(one_flag)) < 0
            || bind(cfd, (struct sockaddr *)&dst_addr, sizeof(struct sockaddr)) < 0
            || connect(cfd, (struct sockaddr*)&src_addr, sizeof(struct sockaddr)) < 0) {
        printf("Err: connecting to connect_fd %d failed\n", cfd);
        close(cfd);
        goto failed;
    }

    /*add cfd into efd*/
    if (qc_proxy_mod_fd_into_efd(cfd, efd, 0)) {
        printf("Err: add connect fd into epoll_fd failed \n");
        return -1;
    }

    /*alloc session*/
    sess = malloc(sizeof(sess_t));
    conn = &sess->front;
    memcpy(&conn->peer_addr, &src_addr, sizeof(src_addr));
    memcpy(&conn->me_addr, &dst_addr, sizeof(dst_addr));
    printf("Info setting front  %p peer addr %s:%d \n",
            conn,
            inet_ntoa(conn->peer_addr.sin_addr), ntohs(conn->peer_addr.sin_port));
    conn->fd = cfd;
    conn->sess = sess;
    sess->back1.fd = -1;
    sess->back2.fd = -1;

    msg->dir = DIR_C2S;
    msg->sess = sess;
    msg->mgrt = 0; // new request, need to create back1
				   /* 
	 * 1. read_from lfd, mgrt = 0, means to connect backend, back1 is ready
	 * 2. after connect backend, mgrt = 1, waiting for handshakdone
	 * 3. handshake done, mgrt =2, connect backend, back2 is ready
	 * 4. if USE_OLD_PATH, send C2S through back2, mgrt = 3, swich back1
	 * */

    msg->back_ready = 0;
    *r_msg = msg;

    return 0;

failed:
    return -1;
}

int qc_proxy_conn_to_back(msg_t *msg, int efd)
{
    int sockfd;
    sess_t *sess = msg->sess;
    conn_t *conn;

    if(msg->back_ready == 1 || msg->mgrt == 2)
        return 0;
    else if(msg->mgrt == 0)
        conn = &sess->back1;
    else
        conn = &sess->back2;

    if (!msg || !sess || !conn) {
        printf("Err: msg is NULL \n");
        return -1;
    }

    //new backend socket
    sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sockfd < 0) {
        printf("Err: creating backend socket\n");
        qc_proxy_free(msg, efd);
        return -1;
    }

    //add epoll
    qc_proxy_mod_fd_into_efd(sockfd, efd, 0);
    printf("Info: creating backend socket successfully\n");

    qc_proxy_set_addr(&conn->peer_addr, REAL_SERV_ADDR);
    conn->fd = sockfd;

    msg->back_ready = 1;
    if (msg->mgrt == 1) {
        msg->mgrt = 2;
#if 0
    sess_t *s = msg->sess;
    conn_t *f = &s->front;
    conn_t *b1 = &s->back1;
    conn_t *b2 = &s->back2;
    printf("----00000000000000 msg %p sess %p front %p[%d %s:%d] ============  back %p[%d->%d %s:%d]\n",
            msg, s, f, f->fd,
            inet_ntoa(f->peer_addr.sin_addr), ntohs(f->peer_addr.sin_port),
            b1, b1->fd, b2->fd,
            inet_ntoa(b2->peer_addr.sin_addr), ntohs(b2->peer_addr.sin_port)
          );
#endif
    }

    return 0;
}

int qc_proxy_recv_from_peer(int fd, msg_t *msg, int efd)
{
    struct sockaddr_in src_addr;
    int client_struct_length = sizeof(src_addr);
    sess_t *sess = msg->sess;
    conn_t *front = &sess->front;
    conn_t *b1 = &sess->back1;
    conn_t *b2 = &sess->back2;

    if (!msg)
        return 0;

    memset(msg->data, '\0', MSG_DATA_SIZE);

    //read data on listen fd
    msg->len = recvfrom(fd, msg->data, sizeof(msg->data), 0,
         (struct sockaddr*)&src_addr, &client_struct_length);
    if (msg->len <= 0) {
        qc_proxy_free(msg, efd);
        printf("Err: read data on connect fd failed.\n");
        return -1;
    }

    //if (src_addr.sin_port == b1->peer_addr.sin_port) {
    if(fd == b1->fd || fd == b2->fd) {
        /*from QUIC Server*/
        msg->dir = DIR_S2C;
        if (msg->len == 0) {
            qc_proxy_mod_fd_into_efd(fd, efd, 1);
            printf("Info: close backend fd %d, b1.fd %d \n", fd, b1->fd);
        }
        char *ptr = msg->data;
        if (!(*ptr & 0x80)) {
            if (msg->mgrt == 0) {
                printf("Info: handshake done from QC server\n");
                msg->mgrt = 1;
            }
            else
                msg->mgrt = 2;
        }
    } else {
        /*from QUIC Client*/
        msg->dir = DIR_C2S;
        if (msg->len == 0) {
            printf("Info: msglen is 0, close all session\n");
        }
        unsigned char *ptr = msg->data;
        if ( !(*ptr & 0x80)) {
            if (msg->mgrt == 1) {
                printf("Info: %s changing backend ---->>>>\n",
                        (msg->dir == DIR_S2C) ? "<<<S2C":">>>C2S"
                      );
                msg->back_ready = 0;
            }
        }
    }
    printf("Info: %s read data from fd %d saddr %s:%d\n",
            (msg->dir == DIR_S2C) ? "<<<S2C":">>>C2S",
            fd, inet_ntoa(src_addr.sin_addr), ntohs(src_addr.sin_port));
    return 0;
}

int qc_proxy_send_to_peer(msg_t *msg, int efd)
{
    sess_t *sess = msg->sess;
    conn_t *end = NULL;

    if (!msg)
        return 0;

    if (msg->dir == DIR_S2C) {
        end = &sess->front;
    }
    else if(msg->mgrt == 2) {
        end = &sess->back2;
    } else {
        end = &sess->back1;
    }

    if (sendto(end->fd, msg->data, msg->len, 0,
         (struct sockaddr*)&(end->peer_addr), sizeof(struct sockaddr_in)) < 0) {
        printf("Err: %s send data to %s:%d failed \n",
                (msg->dir == DIR_S2C) ? "<<<S2C" : ">>>C2S",
                inet_ntoa(end->peer_addr.sin_addr), ntohs(end->peer_addr.sin_port));
        qc_proxy_free(msg, efd);
        return -1;
    }
    printf("Info: %s send data to   fd %d daddr %s:%d \n", 
            (msg->dir == DIR_S2C) ? "<<<S2C" : ">>>C2S", end->fd,
            inet_ntoa(end->peer_addr.sin_addr), ntohs(end->peer_addr.sin_port));

    return 0;
}

int main(int argc, char **argv)
{
    struct epoll_event events[MAX_EVENTS];
    int lfd, efd;
    int nfds, n;
    msg_t *msg;

    /*parse conf/cmd */
    if (qc_proxy_parse_conf(argc, argv))
        return 0;


    efd = qc_proxy_epoll_create();
    if (efd < 0) {
        printf("Err: epoll create failed \n");
        return -1;
    }

    /*listener*/
    lfd = qc_proxy_listen_create();
    if (lfd < 0) {
        printf("Err: listen on the %s:%d failed \n", qproxy_conf.listen_ip, qproxy_conf.listen_port);
        return -1;
    }

    /*add listen fd into epoll*/
    if(qc_proxy_mod_fd_into_efd(lfd, efd, 0)) {
        printf("Err: add listen_fd into epoll_fd failed \n");
        return -1;
    }

    /*read - write data*/
    while(1)
    {
        nfds = epoll_wait(efd, events, MAX_EVENTS, -1);
        if (nfds == -1) {
            perror("epoll_wait");
            return -1;
        }
        for (n = 0; n < nfds; ++n) {
            printf("=================================================== \n");
            if (events[n].data.fd == lfd) {
                qc_proxy_recv_from_lfd(lfd, efd, &msg);
            } else {
                if(msg && qc_proxy_recv_from_peer(events[n].data.fd, msg, efd)) {
                    continue;
                }
            }

            if (qc_proxy_conn_to_back(msg, efd))
                continue;

            if (qc_proxy_send_to_peer(msg, efd)) 
                continue;
        }//end for

    }//end while

    return 0;
}
