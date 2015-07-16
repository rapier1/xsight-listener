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

#ifndef JSON_INFLUX_H
#define JSON_INFLUX_H
#define GNU_SOURCE 1
#ifdef HAVE_LIBJSONC
#include <json-c/json.h>
#else
#include <json/json.h>
#endif
#include "hash.h"
#include "libinflux.h"
#include "options.h"

void add_flow_influx(uuid_t, struct estats_connection_info *);
void add_time(uuid_t, struct estats_nl_client *, int, char *);
void read_metrics (struct ConnectionHash *, struct estats_nl_client *);
void replace_array_in_json_object (json_object *, char *, char *, char *, char **);
	
#endif
