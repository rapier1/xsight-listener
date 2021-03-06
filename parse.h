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

#ifndef PARSE_H
#define PARSE_H
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#define _GNU_SOURCE 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "scripts.h"
#include "string-funcs.h"
#include "debug.h"


int include_port (int, int, int [], int);
int exclude_port (int, int, int [], int);
int exclude_app (char*, char**, int);
int include_app (char*, char**, int);
int filter_ips( char*, char*, char**, int);
int match_ips( char*, char**, int);

#endif
