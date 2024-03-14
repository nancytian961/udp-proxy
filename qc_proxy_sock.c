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
            if (c=='h') {
                for(i = 0; i<ARRAY_SIZE(options); i++)
                    printf("%s", options[i]);
            }
            return -1;
        }
        handle_parser->parser(&qproxy_conf, optarg);

    }//end while
    printf("Listener %s [%s]:[%d]\n", (qproxy_conf.lip_type ? "ipv6" : "ipv4"), qproxy_conf.listen_ip, qproxy_conf.listen_port);
    printf("Server   %s [%s]:[%d]\n", (qproxy_conf.sip_type ? "ipv6" : "ipv4"), qproxy_conf.server_ip, qproxy_conf.server_port);

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
static void qc_proxy_set_addr(void *addr, int listen)
{
	addr_info *dst = (addr_info*)addr;
	if (listen) {
		if (qproxy_conf.lip_type == 0) {
			dst->is_ipv6 = 0;
			struct sockaddr_in *in4 = &dst->u.in4;
			in4->sin_family = AF_INET;
			in4->sin_port = htons(qproxy_conf.listen_port);
			in4->sin_addr.s_addr = inet_addr(qproxy_conf.listen_ip);
		} else{
			dst->is_ipv6 = 1;
			struct sockaddr_in6 *in6 = &dst->u.in6; 
			in6->sin6_family = AF_INET6;
			in6->sin6_port = htons(qproxy_conf.listen_port);
			inet_pton(AF_INET6, qproxy_conf.listen_ip, &in6->sin6_addr);
		}
		sprintf(dst->str, "[%s]:[%d] \n", qproxy_conf.listen_ip, qproxy_conf.listen_port);
	} else {
		if (qproxy_conf.sip_type == 0) {
			dst->is_ipv6 = 0;
			struct sockaddr_in *in4 = &dst->u.in4;
			in4->sin_family = AF_INET;
			in4->sin_port = htons(qproxy_conf.server_port);
			in4->sin_addr.s_addr = inet_addr(qproxy_conf.server_ip);
		}
		else {
			dst->is_ipv6 = 1;
			struct sockaddr_in6 *in6 = &dst->u.in6; 
			in6->sin6_family = AF_INET6;
			in6->sin6_port = htons(qproxy_conf.server_port);
			inet_pton(AF_INET6, qproxy_conf.server_ip, &in6->sin6_addr);
		}

		sprintf(dst->str, "[%s]:[%d] \n",qproxy_conf.server_ip, qproxy_conf.server_port);
	}

	return;
}

int qc_proxy_listen_create()
{
    int sockfd = -1;
    int sockopt = 1;
	int addr_len = 0;
	struct sockaddr *bind_addr;

	addr_info laddr;
	qc_proxy_set_addr(&laddr, LISTEN_ADDR);

	if (qproxy_conf.lip_type)	{
		sockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		addr_len = sizeof(laddr.u.in6);
		bind_addr = (struct sockaddr*)&laddr.u.in6;
	}
	else{
		sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		addr_len = sizeof(laddr.u.in4);
		bind_addr = (struct sockaddr*)&laddr.u.in4;
	}
	if(sockfd < 0){
		printf("Err: creating listen socket failed\n");
		return -1;
	}
    printf("Info: creating listen socket %d successfully\n", sockfd);


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
    if (bind(sockfd, bind_addr, addr_len) < 0) {
        printf("Err: bind to the addr %s:%d failed\n", qproxy_conf.listen_ip, qproxy_conf.listen_port);
        return -1;
    }
    printf("Info: binding socket with listen address successfully\n");

    return sockfd;
}

int qc_proxy_recv_from_lfd(int fd, int efd, msg_t** r_msg)
{ 
    struct sockaddr_in src_in4;
    struct sockaddr_in6 src_in6;
    struct sockaddr *src_addr;
    struct sockaddr *dst_addr;

    int addr_len = 0;
    int cfd;
    int one_flag = 1;

    msg_t *msg;
    sess_t *sess;
	conn_t *f;

	msg = malloc(sizeof(msg_t));
	if (!msg) {
		printf("Err: creating msg_t failed \n");
		return -1;
	}

    nalloc_msg++;
	memset(msg->data, '\0', MSG_DATA_SIZE);

	/*alloc session*/
	sess = malloc(sizeof(sess_t));
	f = &sess->front;
    f->sess = sess;
	qc_proxy_set_addr(&f->me, LISTEN_ADDR);

	if (f->me.is_ipv6) {
		cfd = socket(AF_INET6, SOCK_DGRAM, 0);
		addr_len = sizeof(struct sockaddr_in6);
		msg->len = recvfrom(fd, msg->data, sizeof(msg->data), 0,
				(struct sockaddr*)&src_in6, &addr_len);
		dst_addr = (struct sockaddr*)&f->me.u.in6;
		src_addr = (struct sockaddr*)&src_in6;
		memcpy(&f->peer.u.in6, &src_in6, sizeof(src_in6));
		f->peer.is_ipv6 = 1;
		char ip_str[40] = {0};
		inet_ntop(AF_INET6, &(src_in6), ip_str, sizeof(ip_str));
		sprintf(f->peer.str, "[%s]:[%d]", ip_str, ntohs(f->peer.u.in6.sin6_port));
	}
	else{
		cfd = socket(AF_INET, SOCK_DGRAM, 0);
		addr_len = sizeof(struct sockaddr_in);
		msg->len = recvfrom(fd, msg->data, sizeof(msg->data), 0,
				(struct sockaddr*)&src_in4, &addr_len);
		dst_addr = (struct sockaddr*)&f->me.u.in4;
		src_addr = (struct sockaddr*)&src_in4;
		memcpy(&f->peer.u.in4, &src_in4, sizeof(src_in4));
		f->peer.is_ipv6 = 0;
		sprintf(f->peer.str, "[%s]:[%d]",inet_ntoa(src_in4.sin_addr), ntohs(src_in4.sin_port) );
	}

	if (cfd < 0) {
		printf("Err: creating connect_fd faild\n");
		return -1;
	}

	printf("Info: a new QC connection from %s\n", f->peer.str);
	if (msg->len < 0) {
		printf("Err: read data on listen fd failed.\n");
		close(cfd);
		return -1;
	}


    if (setsockopt(cfd, SOL_SOCKET, SO_REUSEADDR, &one_flag, sizeof(one_flag)) < 0
            || bind(cfd, dst_addr, addr_len) < 0
            || connect(cfd, src_addr, addr_len) < 0) {
        printf("Err: connecting to connect_fd %d failed\n", cfd);
        close(cfd);
        goto failed;
    }

    /*add cfd into efd*/
    if (qc_proxy_mod_fd_into_efd(cfd, efd, 0)) {
        printf("Err: add connect fd into epoll_fd failed \n");
        return -1;
    }
    f->fd = cfd;

    printf("Info setting front  %p  addr %s <-->%s \n",
            f, f->me.str, f->peer.str
            );
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

    qc_proxy_set_addr(&conn->peer, REAL_SERV_ADDR);

    //new backend socket
	if (qproxy_conf.sip_type) {
		sockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	}
	else{
		sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	}

    if (sockfd < 0) {
        printf("Err: creating backend socket\n");
        qc_proxy_free(msg, efd);
        return -1;
    }

    //add epoll
    qc_proxy_mod_fd_into_efd(sockfd, efd, 0);
    printf("Info: creating backend socket successfully\n");

    conn->fd = sockfd;

    msg->back_ready = 1;
    if (msg->mgrt == 1) {
        msg->mgrt = 2;
#if 1
    sess_t *s = msg->sess;
    conn_t *f = &s->front;
    conn_t *b1 = &s->back1;
    conn_t *b2 = &s->back2;
    printf("----00000000000000 msg %p sess %p front %p %d %s ============  back %p[%d->%d] %s\n",
            msg, s, f, f->fd,
            f->peer.str,
            b1, b1->fd, b2->fd,
			conn->peer.str);
#endif
    }

    return 0;
}

static int qc_proxy_recv_from_backend(int fd, msg_t *msg, int efd)
{
    sess_t *sess = msg->sess;
    conn_t *b1 = &sess->back1;
    conn_t *b2 = &sess->back2;
	conn_t *end = NULL;
	end = (b1->fd == fd) ? b1 : b2;
	char buf[128] = {0};

	memset(msg->data, '\0', MSG_DATA_SIZE);
	msg->dir = DIR_S2C;
	msg->len = recv(fd, msg->data, MSG_DATA_SIZE, 0);
	if (msg->len < 0) {
		qc_proxy_free(msg, efd);
		printf("Err: read data on connect fd failed.\n");
		return -1;
	}
	if (msg->len == 0) {
		qc_proxy_mod_fd_into_efd(fd, efd, 1);
		printf("Info: close backend fd %d, b1.fd %d \n", fd, b1->fd);
		qc_proxy_free(msg, efd);
		return -1;
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


    printf("Info: %s read data from fd %d saddr %s\n",
            (msg->dir == DIR_S2C) ? "<<<S2C":">>>C2S",
            fd, end->peer.str);
	return 0;

}

 /*from QUIC Client*/
static int qc_proxy_recv_from_front(int fd, msg_t *msg, int efd)
{
    sess_t *sess = msg->sess;
    conn_t *end = &sess->front;
    memset(msg->data, '\0', MSG_DATA_SIZE);
	char buf[128] = {0};

	msg->dir = DIR_C2S;
	msg->len = recv(fd, msg->data, MSG_DATA_SIZE, 0);
	if (msg->len <= 0) {
		qc_proxy_free(msg, efd);
		printf("Err: read data on connect fd failed.\n");
		return -1;
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

	if(end->peer.is_ipv6) {
		struct sockaddr_in6 *peer = (struct sockaddr_in6*)&(end->peer.u.in6);
		strcpy(buf, "[");
		inet_ntop(AF_INET6, &(peer->sin6_addr), buf+strlen(buf), sizeof(buf)-strlen(buf));
		sprintf(buf+strlen(buf), "]:[%d]", ntohs(peer->sin6_port));
	} else {
		struct sockaddr_in *peer = (struct sockaddr_in *) &(end->peer.u.in4);
		sprintf(buf, "[%s]:[%d]", 
				inet_ntoa(peer->sin_addr), ntohs(peer->sin_port));
	}

    printf("Info: %s read data from fd %d saddr %s \n",
            (msg->dir == DIR_S2C) ? "<<<S2C":">>>C2S",
            fd, end->peer.str);
	return 0;
}

int qc_proxy_recv_from_peer(int fd, msg_t *msg, int efd)
{
	if (!msg)
		return 0;

    sess_t *sess = msg->sess;
	conn_t *b1 = &sess->back1;
	conn_t *b2 = &sess->back2;


	if(fd == b1->fd || fd == b2->fd) {
		return qc_proxy_recv_from_backend(fd, msg, efd);
	} else {
		return qc_proxy_recv_from_front(fd, msg, efd);

	}
	return 0;
}

int qc_proxy_send_to_peer(msg_t *msg, int efd)
{
	struct sockaddr* dst;
	sess_t *sess = msg->sess;
	conn_t *end = NULL;
	size_t addr_len = 0;

	if (!msg)
        return 0;

    if (msg->dir == DIR_S2C) {
		/*send to front*/
		end = &sess->front;
	} else {
		/*send to backend*/
		if(msg->mgrt == 2) {
			end = &sess->back2;
		} else {
			end = &sess->back1;
		}

		qc_proxy_set_addr(&end->peer, REAL_SERV_ADDR);
	}

	addr_len = end->peer.is_ipv6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);;
	dst = end->peer.is_ipv6 ?  (struct sockaddr*)&(end->peer.u.in6) : (struct sockaddr*)&(end->peer.u.in4); 


    if (sendto(end->fd, msg->data, msg->len, 0,
		 dst, addr_len) < 0) {
        printf("Err: %s send data to %s addr_len %ld failed \n",
                (msg->dir == DIR_S2C) ? "<<<S2C" : ">>>C2S", end->peer.str, addr_len);
        qc_proxy_free(msg, efd);
        return -1;
    }
    printf("Info: %s send data to fd %d daddr %s \n", 
            (msg->dir == DIR_S2C) ? "<<<S2C" : ">>>C2S", end->fd,
			end->peer.str);

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
