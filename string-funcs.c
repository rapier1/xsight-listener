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

/* this file provides the methods used to handle strings that are not found in
 * the standard c strings library
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>


/**
 * Delete a character from the specified position (zero offset)
 *
 * The len parameter allows the function to work with non null terminated
 * strings and could also be considered a weak attempt at buffer overflow
 * protection.
 *
 * @note The original string is modified.
 *
 * @param[in] src   Pointer to string from which to remove the character
 * @param[in] pos   Zero-offset position of the character to remove
 * @param[in] len   Max number of characters to process
 */
void
delete_at(char *src, int pos, int len)
{
        char *dst;
        int i;

        if ( pos < 0 )
                return;

        // Small attempt to control a buffer overflow if the
        // the string is not null-terminated and a proper length
        // is not specified.
        if ( len <= 0 )
                len = 1024;

        if ( pos >= len )
                return;

        src += pos;
        dst = src;
        src++;

        for ( i = pos + 1; i < len && *src != 0; i++ )
                *dst++ = *src++;

        // Ensure the string is null-terminated.
        *dst = 0;

        return;
}
// delete_at()

// use this to return the index position of the first appearance of the needle
// -1 means it does not exist
int strpos (char *haystack, char *needle) {
	char *p = strstr(haystack, needle);
	if (p) 
		return p - haystack;
	return -1;
}

// take in incoming string and split by the delimiter and place the 
// results into an array. 
char** str_split( char* str, char delim, int* numSplits )
{
	char** ret;
	int retLen;
	char* c;
	
	if ((str == NULL) || (delim == '\0')) {
		/* Either of those will cause problems */
		ret = NULL;
		retLen = -1;
	} else {
		retLen = 0;
		c = str;
		/* Pre-calculate number of elements */
		while ( *c != '\0' ) {
			if ( *c == delim )
				retLen++;
			c++;
		}
		// malloced but not freed! We need to pass a buffer in 
		// that we can free from the caller. 
		ret = malloc((retLen + 1) * sizeof(*ret));
		ret[retLen] = NULL;
		
		c = str;
		retLen = 1;
		ret[0] = str;
		while (*c != '\0') {
			if (*c == delim) {
				ret[retLen++] = &c[1];
				*c = '\0';
			}
			c++;
		}
	}
	
	if ( numSplits != NULL )
		*numSplits = retLen;
	
	return ret;
}

// strip leading and trailing whitespace
char *strip(char *string) {
	char *start = string;
	while(isblank(*start)) start++;
	int end = strlen(start);
	if(start != string) {
		memmove(string, start, end);
		string[end] = '\0';
	}
	while(isblank(*(string+end-1))) end--;
	string[end] = '\0';
	return string;
}

// strip leading and trailing whitespace                                                                                                                                                                                                                                  

char *noquotes(char *string) {
	char *start = string;
	while(*start == '"') start++;
	int end = strlen(start);
	if(start != string) {
		memmove(string, start, end);
		string[end] = '\0';
	}
	while(*(string+end-1) == '"') end--;
	string[end] = '\0';
	return string;
}

void join_strings(char **buf, char **strings, char *seperator, int count) {
    size_t total_length = 0;      /* Total length of joined strings */
    int i = 0;                    /* Loop counter                   */

    /* Find total length of joined strings */
    for (i = 0; i < count; i++) total_length += strlen(strings[i]);
    total_length++;     /* For joined string terminator */
    total_length += strlen(seperator) * (count - 1); // for seperators

    *buf = malloc((total_length+1) * sizeof(char));  /* Allocate memory for joined strings */
    *buf[0] = '\0';                      /* Empty string we can append to      */

    /* Append all the strings */
    for (i = 0; i < count; i++) {
        strcat(*buf, strings[i]);
        if (i < (count - 1)) strcat(*buf, seperator);
    }

//    return str;
}
