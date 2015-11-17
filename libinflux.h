/* Copyright © 2015, Pittsburgh Supercomputing Center.  All Rights Reserved. */

#include <curl/curl.h>
#ifndef libinflux__h
#define libinflux__h

typedef struct {
    CURL *curl;
    CURLcode resCode;
    char *host_url;
    char *db;
    char *user;
    char *pass;
    int ssl; // 1: ssl enabled & verify peer; 0: insecure ssl - don't verify peer; -1: ssl disabled
} influxConn;
extern void rest_init();
extern void rest_cleanup();
extern influxConn* create_conn(char *, char *,char *, char *, int);
extern char* build_write_url(influxConn*);
extern char* build_query_url(influxConn*);
extern CURLcode sendPost(influxConn *, char *, char *);
extern CURLcode sendGet(influxConn *, char *, char *);
extern CURLcode influxQuery(influxConn *, char *);
extern CURLcode influxWrite(influxConn *, char *);

#endif
