#ifndef _QC_PROXY_CONF_H_
#define _QC_PROXY_CONF_H_

#include "qc_proxy_sock.h"

typedef struct _conf_parse {
     int (*check)(char *arg);
    int (*parser)(void *conf, char *opt);
    char *help_msg;
    int must;
}conf_parse_t;

int qc_proxy_parse_laddr(void *conf, char *opt);
int qc_proxy_parse_sport(void *conf, char *opt);
int qc_proxy_parse_raddr(void *conf, char *opt);
int qc_proxy_parse_dport(void *conf, char *opt);

#endif
