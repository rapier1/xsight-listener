/*
 * Copyright (c) 2015 The Board of Trustees of the University of Illinois,
 *                    Carnegie Mellon University.
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

#include "hash.h"
#include "libinflux.h"

extern struct ConnectionHash *activeflows;
extern struct NetworksHash *networks;

void add_network(struct NetworksHash *n, int network_id) {
	n->network_id = network_id; /* pointless assignment to supress unused variable warning - remove ths later */
	HASH_ADD_INT(networks, network_id, n);
}

int  hash_get_curl_handles () {
	struct NetworksHash *current, *temp;
	char *influx_service_url;
	int length;
	CURL *mycurl = NULL;
	HASH_ITER(hh, networks, current, temp) {
		/* generate the service url from the options */
		length = snprintf (NULL, 0, "write?db=%s&u=%s&p=%s", 
				   current->influx_database, current->influx_user, current->influx_password);
		length++;
		influx_service_url = malloc(length * sizeof(char));
		snprintf(influx_service_url, length, "write?db=%s&u=%s&p=%s", 
			 current->influx_database, current->influx_user, current->influx_password);
		log_debug ("Service URL: %s", influx_service_url);
		
		/* initiate the rest connection*/
		rest_init((char *)current->influx_host_url, influx_service_url);
		if (mycurl == NULL) {
			log_error("Could not initiate the curl connection to %s%s", 
				  current->influx_host_url, influx_service_url);
			return -1;
		}
		current->curl = mycurl;
		/* we don't need this anymore*/
		free(influx_service_url);
	}
	return 1;
}

/* find a specific connection ID in the hash */
struct ConnectionHash *find_cid(int cid) {
        struct ConnectionHash *s;
	HASH_FIND_INT(activeflows, &cid, s );  
	return s;
};

/* add the new connection to the hash */
struct ConnectionHash *add_connection (struct estats_connection_info *conn) {
	struct ConnectionHash *flow = NULL;
	flow = (ConnectionHash*)malloc(sizeof(ConnectionHash));
	flow->cid = conn->cid;
	flow->seen = 1;
	flow->lastpoll = time(NULL);
	HASH_ADD_INT(activeflows, cid, flow);
	log_debug("Added hash: %d", flow->cid);
	return flow;
}

int delete_flow (int cid) {
	struct ConnectionHash *current;
	HASH_FIND_INT(activeflows, &cid, current);
	if (current != NULL) {
		log_debug("Deleting flow: %d", current->cid);
		HASH_DEL(activeflows, current);
		free(current);
		return 1;
	}
	return 0;
}

void clear_hash () {
	struct ConnectionHash *current, *temp;
	HASH_ITER(hh, activeflows, current, temp) {
		HASH_DEL(activeflows, current);
		free(current);
	}
}

/* used for debugging purposes mostly but may be useful in the future*/
int count_hash () {
	int i;
	i = 0;
	struct ConnectionHash *current, *temp;
	HASH_ITER(hh, activeflows, current, temp) {
		i++;
	}
	return i;
}
