/*
 * Copyright (c) 2013 The Board of Trustees of Carnegie Mellon University.
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

/* this file provides the routines for handling incoming requests
 * from the websocket and turning those request, when necessary, into 
 * structures needed to filter the tcpdata
 */
#define _GNU_SOURCE 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "scripts.h"
#include "string-funcs.h"
#include "parse.h"
#include "debug.h"

extern int debugflag;
// if the dest port or source port exists in the array of ports
// then return a 0. This sets the flag to zero and ensures that the
// tcpdata is not skipped
int include_port (int sport, int dport, int ports[], int index) {
	int i;
	for (i = 0; i < index; i++) {
		if (sport == ports[i] || dport == ports[i]) 
			return 0;
	}
	return 1;
}

// Same as above but if the tuples port is in the list then skip it. 
int exclude_port (int sport, int dport, int ports[], int index) {
	int i;
	for (i = 0; i < index; i++) {
		if (sport == ports[i] || dport == ports[i])
			return 1;
	}
	return 0;
}

// Take the incoming ints and or them. Then and them against a 
// mask we create based on the number of bits in the mask. This was taken from 
// addr4_ match in the linux kernel (include/net/xfrm.h)
bool cidr_match(int addr, int net, uint8_t bits) {
	// if bits is 0 then it will always match
	if (bits == 0) {
		return true;
	}
	return !((addr ^ net) & htonl(0xFFFFFFFFu << (32 - bits)));
}

/* only report on the ipaddresses that are passed to the client
 * Originally this was a simple string compare but that has serious issues
 * so we use getaddrinfo to get the information about each of the addresses
 * we are testing (local, remote, and the user defined ips). We use the ai_family
 * data to determine if it is ipv4 or ipv6. We then cast the getaddrinfo
 * address to the appropriate sockaddr_in struct. For ipv4 we can directly compare
 * the ints found in sin_addr.s_addr. If it's ipv6 then we do a memcmp because the
 * struct for sin6_addr.s6_addr is a char[16]. If they match we return 0 (which 
 * doesn't set the skip flag) if they don't we return a 1. 
 * New: we can now use CIDR masks for IPV4. I haven't gone to ip6 yet as that's
 * a pain on the UI side. 
 */
/* worth mentioning. This returns 0 if the ip address in the cid matches our filter.
 * why? Because the flag the result is returned to squelches any CID that has a 1.
 * so some filters return 1 and some return 0 depending on what we want to squelch
 */
int filter_ips( char* local, char* remote, char** ips, int index) {
	int i, ret = 0;
	int result = 1;
	struct addrinfo hint;
	struct addrinfo *locres = 0;
	struct addrinfo *remres = 0; 
	struct addrinfo *testres = 0;
	struct sockaddr_in *locaddr = NULL;
	struct sockaddr_in *remaddr = NULL;
	struct sockaddr_in *testaddr = NULL;
	struct sockaddr_in6 *locaddr6 = NULL;
	struct sockaddr_in6 *remaddr6 = NULL;
	struct sockaddr_in6 *testaddr6 = NULL;
	char *ip;
	char *mask;
	char *tmpip;
	int bits = 32; // the default mask if they don't include a mask

	memset(&hint, '\0', sizeof hint);
	
	hint.ai_family = AF_UNSPEC;

	/* get the info for the remote ip address.*/
	ret = getaddrinfo(remote, NULL, &hint, &remres);
	if (ret != 0){
		// we shouldn't see a bad address here but we should check anyway
		fprintf(stderr, "getaddrinfo: %s (likely an invalid remote ip address)\n", 
			gai_strerror(ret));
		free(remres);
		return 1;
	}

	// cast the address information to the appropriate struct
	if (remres->ai_family == AF_INET)  
		remaddr = (struct sockaddr_in*)remres->ai_addr;
	else 
		remaddr6 = (struct sockaddr_in6*)remres->ai_addr;

	// same as above but for the local ip address
	ret = getaddrinfo(local, NULL, &hint, &locres);
	if (ret != 0) {
		fprintf(stderr, "getaddrinfo: %s (likely an invalid local ip address)\n", 
			gai_strerror(ret));
		freeaddrinfo(remres);
		freeaddrinfo(locres);
		return 1;
	}

	if (locres->ai_family == AF_INET)  
		locaddr = (struct sockaddr_in*)locres->ai_addr;
	else 
		locaddr6 = (struct sockaddr_in6*)locres->ai_addr;

	for (i = 0; i < index; i++) {

		/* use strndupa because strdup and free was causing odd errors in valgrind
		 * i think this is because of what was happening with the strtok
		 */
		tmpip = strndupa(ips[i], strlen(ips[i]));

		// we need to examine the incoming address to see if it has a slash
		// indicating that it is being masked. 
		ip = strtok(tmpip, "/");
		mask = strtok(NULL, "\0");

		// convert whatever we have into an int
		// this is *only* for ipv4.
		if (mask != NULL) {
			bits = atoi(mask);
		}
		
		// if the int is outside of the range then set it to the narrowest possible
		// as you can see we aren't supporting a /0 mask. TODO: fix it so we can. 
		if (bits == 0 || bits > 32) {
			bits = 32;
		}

		// go through the above for each ip address we are testing against
		ret = getaddrinfo(ip, NULL, &hint, &testres);
		if (ret != 0) {
			fprintf(stderr, "getaddrinfo: %s (likely an invalid user defined ip address)\n", 
				gai_strerror(ret));
			continue;
		}

		if (testres->ai_family == AF_INET)  
			testaddr = (struct sockaddr_in*)testres->ai_addr;
		else 
			testaddr6 = (struct sockaddr_in6*)testres->ai_addr;

		
		// do the families match? If not just skip it
		if (locres->ai_family == testres->ai_family) {
			// compare on either ipv4 (AF_INET) or ipv6
			if (locres->ai_family == AF_INET) {
				// match using the bits and the ints for the addresses
				if (cidr_match(locaddr->sin_addr.s_addr, testaddr->sin_addr.s_addr, bits)) {
					result = 0;
					freeaddrinfo(testres);
					goto Cleanup;
				}
			} else {
				if (memcmp(locaddr6->sin6_addr.s6_addr, testaddr6->sin6_addr.s6_addr, 
					   sizeof(testaddr6->sin6_addr.s6_addr)) == 0) {
					result = 0;
					freeaddrinfo(testres);
					goto Cleanup;
				}

			}
		}

		if (remres->ai_family == testres->ai_family) {
			if (remres->ai_family == AF_INET) {
				if (cidr_match(remaddr->sin_addr.s_addr, testaddr->sin_addr.s_addr, bits)) {
					result = 0;
					freeaddrinfo(testres);
					goto Cleanup;
				}
			} else {
				if (memcmp(remaddr6->sin6_addr.s6_addr, testaddr6->sin6_addr.s6_addr, 
					   sizeof(testaddr6->sin6_addr.s6_addr)) == 0) {
					result = 0;
					freeaddrinfo(testres);
					goto Cleanup;
				}
			}
		}
		freeaddrinfo(testres);
	}
Cleanup:
	freeaddrinfo(remres);
	freeaddrinfo(locres);
	return result;
}

// if the application name is found in the list of excluded apps
// then return 1 indicating that we should not report this app
int exclude_app (char* appname, char** apps, int index) {
	int i;
	for (i = 0; i < index; i++) {
		if (strcmp(appname, apps[i]) == 0)
			return 1;
	}
	return 0;
}

// if the application name is found in the list of included apps
// then return 0 indicating that we should report on this app
int include_app (char* appname, char** apps, int index) {
	int i;
	for (i = 0; i < index; i++) {
		if (strcmp(appname, apps[i]) == 0)
			return 0;
	}
	return 1;
}
