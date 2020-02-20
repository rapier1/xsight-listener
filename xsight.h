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

#ifndef MAIN_H
#define MAIN_H
#define GNU_SOURCE 1
#include <sys/stat.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include "scripts.h"
#include "curl/curl.h"
#include "debug.h"
#include "hash.h"
#include "build_query.h"
#include "parse.h"
#include "version.h"
#include "thpool.h"
#include "dead_flow_check.h"

#define NUM_THREADS 12 /* number of threads in pool */

typedef struct CmdLineCID {
	int cid;
	char cmdline[256];
	UT_hash_handle hh;
} CmdLineCID;

#endif


