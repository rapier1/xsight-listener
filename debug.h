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

#ifndef DEBUG_H 
#define DEBUG_H
#include <stdarg.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <syslog.h>

typedef enum LogLevels {
	DEBUG,
	DEBUG2,
	INFO,
	ERROR
} LogLevels;

void log_error(const char* message, ...); 
void log_info(const char* message, ...); 
void log_debug(const char* message, ...);
void log_debug2(const char* message, ...);

#endif
