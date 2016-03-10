/*
 * Copyright (c) 2016 The Board of Trustees of Carnegie Mellon University.
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

#ifndef SAFE_MALLOC_H
#define SAFE_MALLOC_H
#include <stdlib.h>
#include <stdio.h>

void* safe_malloc(size_t, unsigned long);

#define SAFEMALLOC(n) safe_malloc(n, __LINE__)

#endif
	
