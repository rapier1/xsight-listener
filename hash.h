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

typedef struct ConnectionHash {
	int cid;
	int lastpoll;
	int seen;
	uuid_t flowid;
	UT_hash_handle hh;
} ConnectionHash;

struct ConnectionHash *find_cid (int);
struct ConnectionHash *add_connection (struct estats_connection_info *);
int delete_flow (int);
void clear_hash();
int count_hash();
#endif
