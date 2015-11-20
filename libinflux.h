/* Copyright © 2015, Pittsburgh Supercomputing Center.  All Rights Reserved. */

#include <curl/curl.h>
#include <stdbool.h>
#ifndef libinflux__h
#define libinflux__h

typedef struct {
    CURL *curl;
    CURLcode result_code;
    int (*on_data_ready)(char *); //user-defined callback function. Should return 0 unless error.
    char *host_url;
    char *db;
    char *user;
    char *pass;
    int ssl; // 1: ssl enabled & verify peer; 0: insecure ssl - don't verify peer; -1: ssl disabled
} influxConn;
extern void libinflux_init();
extern void libinflux_cleanup();
extern influxConn* create_conn(char *, char *,char *, char *, int);
extern void free_conn(influxConn *);
extern void set_callback(influxConn *, int (*)(char*));
extern char* build_write_url(influxConn*);
extern char* build_query_url(influxConn*);
extern void set_debug(bool);
extern CURLcode sendPost(influxConn *, char *, char *);
extern CURLcode sendGet(influxConn *, char *, char *);
extern size_t writeCallback(char *, size_t, size_t, influxConn *);
extern CURLcode influxQuery(influxConn *, char *);
extern CURLcode influxWrite(influxConn *, char *);
extern bool influxCheck(influxConn *);
extern bool influx_debug;

#endif
