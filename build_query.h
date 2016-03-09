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

#ifndef BUILD_QUERY_H
#define BUILD_QUERY_H
#include <stdlib.h>
#include <string.h>

#include "hash.h"
#include "libinflux.h"
#include "options.h"
#include "parse.h"
#include "thpool.h"
#include "tracer.h"
#include "safe_malloc.h"

struct ThreadWrite {
	char action[32];
	influxConn *conn;
	char *data;
} ThreadWrite;

struct PathBuild {
	struct estats_connection_info *conn;
	const char *netname;
	const char *domain_name;
	char *local_addr;
	char *rem_addr;
	const char *flowid_char;
	int cid;
	influxConn *influx_conn;
	threadpool mythread;
} PathBuild;

void add_flow_influx(threadpool, struct ConnectionHash *, struct estats_connection_info *);
void add_path_trace(threadpool, threadpool, struct ConnectionHash *, struct estats_connection_info *);
void add_time(threadpool, struct ConnectionHash *, struct estats_nl_client *, int, char *);
void read_metrics (threadpool, struct ConnectionHash *, struct estats_nl_client *);
uint64_t get_start_time(struct ConnectionHash *, struct estats_nl_client *, int);
void generate_flow_id (struct ConnectionHash *, struct estats_connection_tuple_ascii, char *);
#endif
