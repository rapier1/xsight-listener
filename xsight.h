/*
 * Copyright (c) 2013 The Board of Trustees of Carnegie Mellon University.
 *
 *  Author: Chris Rapier <rapier@psc.edu>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT License.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the MIT License for more details.
 *
 * You should have received a copy of the MIT License along with this library;
 * if not, see http://opensource.org/licenses/MIT.
 *
 */

#ifndef MAIN_H
#define MAIN_H
#define GNU_SOURCE 1
#ifdef HAVE_LIBJSONC
#include <json-c/json.h>
#else
#include <json/json.h>
#endif
#include <uuid/uuid.h>
#include "estats/estats.h"
#include "uthash.h"
#include "string-funcs.h"
#include "version.h"
#include "debug.h"
#include "curl/curl.h"
#include "scripts.h"
#include "stdint.h"
#include "libconfig.h"
#include "parse.h"

typedef struct CmdLineCID {
	int cid;
	char cmdline[256];
	UT_hash_handle hh;
} CmdLineCID;

typedef struct ConnectionHash {
	int cid;
	int lastpoll;
	int seen;
	uuid_t flowid;
	UT_hash_handle hh;
} ConnectionHash;

typedef struct Options {
	int metric_interval;
	int conn_interval;
	int debugflag;
	int printjson;
        int in_ips_count;
        int ex_ips_count;
        int in_apps_count;
        int ex_apps_count;
	const char *domain_name;
	const char *dtn_id;
	const char *influx_host_url;
	char *influx_service_url;
        const char *influx_database;
        const char *influx_password;
        char **include_ips;
        char **exclude_ips;
        char **include_apps;
        char **exclude_apps; 
} Options;

int get_config(char *);
struct ConnectionHash *add_connection (struct estats_connection_info *);
void replace_array_in_json_object (json_object *, char *, char *, char *, char **);
void add_flow_influx(uuid_t flowid, struct estats_connection_info *conn);
void add_time(uuid_t, char *);
int delete_flow (int);
void clear_hash();
void read_metrics (struct ConnectionHash *, struct estats_nl_client *);

#endif


