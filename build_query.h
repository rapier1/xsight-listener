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
#include "hash.h"
#include "libinflux.h"
#include "options.h"
#include "parse.h"
#include "thpool.h"
#include "tracer.h"

struct ThreadWrite {
	char action[32];
	influxConn *conn;
	char *data;
} ThreadWrite;

struct PathBuild {
	struct estats_connection_info *conn;
	struct ConnectionHash *flow;
} PathBuild;

void add_flow_influx(threadpool, struct ConnectionHash *, struct estats_connection_info *);
void add_path_trace(threadpool, struct ConnectionHash *, struct estats_connection_info *);
//void add_path_trace(struct estats_connection_info *);
void add_time(threadpool, struct ConnectionHash *, struct estats_nl_client *, int, char *);
void read_metrics (threadpool, struct ConnectionHash *, struct estats_nl_client *);
void threaded_influx_write (struct ThreadWrite *); 	

#endif
