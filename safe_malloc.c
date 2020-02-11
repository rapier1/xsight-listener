/*
 * Copyright (c) 2016 The Board of Trustees of Carnegie Mellon University.
 *
 *  Author: Chris Rapier <rapier@psc.edu>
 * actually this was written by Jim Balter (of JBQ Solutions) and 
 * was lifted from a response her wrong on satckoverflow.com 
 * Any copyright claims made by me of Carnegie Mellon do not
 * supercede his claims. 
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

#include "safe_malloc.h"

void* safe_malloc(size_t n, unsigned long line){
	void* p = malloc(n);
	if (!p){
		fprintf(stderr, "[%s:%lu]Out of memory(%lu bytes)\n",
			__FILE__, line, (unsigned long)n);
		exit(EXIT_FAILURE);
	}
	return p;
}
