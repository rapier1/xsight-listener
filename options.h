/*
 * Copyright (c) 2015 The Board of Trustees of Carnegie Mellon University.
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

#ifndef OPTIONS_H
#define OPTIONS_H
#define GNU_SOURCE 1
#include <string.h>
#include <stdlib.h>
#include "libconfig.h"
#include "debug.h"
#include "uthash.h"
#include "hash.h"

extern int debugflag;

typedef struct Options {
	unsigned int metric_interval;
	int conn_interval;
        int in_ips_count;
        int ex_ips_count;
        int in_apps_count;
        int ex_apps_count;
	int network_count;
	const char *netname;
	const char *domain_name;
	const char *dtn_id;
	const char *influx_host_url;
	const char *influx_database;
	const char *influx_password;
	const char *influx_user;
        char **include_ips;
        char **exclude_ips;
        char **include_apps;
        char **exclude_apps; 
} Options;

void options_freeoptions ();
int options_get_config(char *, int);

#endif
