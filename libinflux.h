/* Copyright © 2015, Pittsburgh Supercomputing Center.  All Rights Reserved. */

#include <curl/curl.h>
#ifndef libinflux__h
#define libinflux__h

extern CURL *curl;
extern void rest_init(char *, char *);
extern void rest_cleanup();
extern CURLcode sendPost(char *, char *);
extern CURLcode sendGet(char *, char *);
extern CURLcode influxQuery(char *);
extern CURLcode influxWrite(char *);

#endif
