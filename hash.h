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

#ifndef HASH_H
#define HASH_H
#include <uuid/uuid.h>
#include "uthash.h"
#include "debug.h"
#include "scripts.h"
#include "libinflux.h"
#include "parse.h"

typedef struct ConnectionHash {
	int cid;
	uint64_t lastpoll;
	int seen;
	int closed; 
	uuid_t flowid;
	const char *group;
	const char *domain_name;
	influxConn *conn;
	UT_hash_handle hh;
} ConnectionHash;

typedef struct NetworksHash {
	int network_id; /*key*/
	int net_addrs_count; /* number of networks in net_addrs */
	int precedence; /* we want to sort the hash so 'interior' is always first */
	const char *group;
	const char *domain_name;
	const char *influx_host_url;
	const char *influx_database;
	const char *influx_password;
	const char *influx_user;
	char **net_addrs;
	influxConn *conn;
	UT_hash_handle hh;
} NetworksHash;

influxConn *hash_find_curl_handle(const char *);
void hash_close_curl_handles();
int hash_get_tags(struct estats_connection_tuple_ascii *, struct ConnectionHash *);
void hash_sort_by_precedence ();
int hash_get_curl_handles ();
void hash_add_network(NetworksHash *, int);
struct ConnectionHash *hash_find_cid (int);
struct ConnectionHash *hash_add_connection (struct estats_connection_info *);
int hash_delete_flow (int);
void hash_clear_hash();
int hash_count_hash();
#endif
