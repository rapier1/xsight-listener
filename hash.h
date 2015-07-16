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
#include <curl/curl.h>
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
	CURL *curl;
	UT_hash_handle hh;
} NetworksHash;

int hash_get_tags(struct estats_connection_tuple_ascii *, struct ConnectionHash *);
void hash_sort_by_precedence ();
int hash_get_curl_handles ();
void add_network(NetworksHash *, int);
struct ConnectionHash *find_cid (int);
struct ConnectionHash *add_connection (struct estats_connection_info *);
int delete_flow (int);
void clear_hash();
int count_hash();
#endif
