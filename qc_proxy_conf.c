#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "qc_proxy_conf.h"
#include "qc_proxy_sock.h"

static int ip_version(char *ip_str)
{
	if (!strstr(ip_str, ":"))
		return 4;
	else 
		return 6;
}

int qc_proxy_parse_laddr(void *conf, char *arg)
{
    qc_proxy_conf_t *dst = conf;
    if (ip_version(arg) == 4) {
        dst->lip_type = 0;
        memset(dst->listen_ip, 0, sizeof(dst->listen_ip));
        strcpy(dst->listen_ip, arg);
        return 0;
    }

	else if (ip_version(arg) == 6) {
        dst->lip_type = 1;
        memset(dst->listen_ip, 0, sizeof(dst->listen_ip));
        strcpy(dst->listen_ip, arg);
        return 0;
    }

    return -1;
}

int qc_proxy_parse_sport(void *conf, char *arg)
{
    qc_proxy_conf_t *dst = conf;
    int port = atoi(arg);
    if(port <=0 && port >65535)
        return -1;

    dst->listen_port = port;

    return 0;
}

int qc_proxy_parse_raddr(void *conf, char *arg)
{
    qc_proxy_conf_t *dst = conf;
    if (ip_version(arg) == 4) {
        dst->sip_type = 0;
        strcpy(dst->server_ip, arg);
        return 0;
    }

	else if (ip_version(arg) == 6) {
        dst->sip_type = 1;
        strcpy(dst->server_ip, arg);
        return 0;
    }

    return 0;
}

int qc_proxy_parse_dport(void *conf, char *arg)
{
    qc_proxy_conf_t *dst = conf;
    int port = atoi(arg);
    if (port <=0 && port >65535)
        return -1;

    dst->server_port = port;
    return 0;
}

