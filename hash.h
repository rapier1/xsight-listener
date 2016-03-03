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
#include <stdbool.h>
#include <openssl/sha.h>
#include "uthash.h"
#include "debug.h"
#include "scripts.h"
#include "libinflux.h"
#include "parse.h"


#define SHA256_TEXT SHA256_DIGEST_LENGTH * 2

typedef struct ConnectionHash {
	int cid;            /* connection id from estats*/
	uint64_t lastpoll;  /* last polling period in seconds */
	int age;            /* age of flow in seconds (maximum age of ~68 years) */
        bool seen;          /* boolean - have we seen this previously */
	bool closed;        /* connection state */
	bool added;         /* already added to db */
	bool exclude;       /* this flow is filtered out based on the rules if true */
	const char flowid_char[SHA256_TEXT+1]; /* char representation of sha256 hash*/
	const char *netname;     /* name of associated network 0 */
	const char *domain_name; /* name of asscoiated admin domain */
	influxConn *conn;        /* curl connection handle */
	UT_hash_handle hh;       /* hash handle */
} ConnectionHash;

typedef struct NetworksHash {
	int network_id; /*key*/
	int net_addrs_count; /* number of networks in net_addrs */
	int precedence; /* we want to sort the hash so 'interior' is always first */
	int verify_ssl; /* default to true */
	const char *netname;
	const char *domain_name;
	const char *influx_host_url;
	const char *influx_database;
	const char *influx_password;
	const char *influx_user;
	char **net_addrs;
	influxConn *conn;
	UT_hash_handle hh;
} NetworksHash;

typedef struct DeadFlowHash {
	char *flow; 
	NetworksHash *network;
	UT_hash_handle hh;
} DeadFlowHash;

influxConn *hash_find_curl_handle(const char *);
void hash_close_curl_handles();
int hash_get_tags(struct estats_connection_tuple_ascii *, struct ConnectionHash *);
void hash_sort_by_precedence ();
int hash_get_curl_handles ();
void hash_add_network(NetworksHash *, int);
struct ConnectionHash *hash_find_cid (int);
struct ConnectionHash *hash_add_connection (struct estats_connection_info *);
void hash_init_flow(struct ConnectionHash *);
int hash_delete_flow (int);
void hash_clear_hash();
int hash_count_hash();
#endif
