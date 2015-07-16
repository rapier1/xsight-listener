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


extern struct ConnectionHash *activeflows;
extern struct NetworksHash *networks;

int _by_precedence(NetworksHash *, NetworksHash *); /*forward declaration*/

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


/* we need to determine which sets of tags to use */
/* this is based on the network stanzas in the config file */
/* iterate theough the networks hash. get the net_addrs field (an arry */
/* Step through that array and see if the */
/* incoming ip address (remote) matches (we can use filter_ips for this */
/* if true then create the tags based on the rest of the information in the */
/* networkshash struct */

int hash_get_tags(struct estats_connection_tuple_ascii *asc, struct ConnectionHash *flow) {
	struct NetworksHash *current, *temp;
	HASH_ITER (hh, networks, current, temp) {
		/* if the count is - then the networks config option is
		 * empty and this means that *everything* should match that
		 * network */
		printf ("%s count %d\n", current->group, current->net_addrs_count);
		if ((current->net_addrs_count == 0) || (match_ips(asc->rem_addr, 
								  current->net_addrs, 
								  current->net_addrs_count))) {

			flow->group = strdup(current->group);
			flow->domain_name = strdup(current->domain_name);
			return 1;
		}
	}
	/* if there is no match to any known network what should we do? */
	/* right now, nothing */
	return 0;
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

void hash_sort_by_precedence () {
	HASH_SORT(networks, _by_precedence);
}

int _by_precedence (NetworksHash *a, NetworksHash *b) {
	return (a->precedence - b->precedence);
};

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
