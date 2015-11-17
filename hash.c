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

void hash_add_network(struct NetworksHash *n, int network_id) {
	n->network_id = network_id; /* pointless assignment to supress unused variable warning */
	HASH_ADD_INT(networks, network_id, n);
}

/* find the curl handle associated with the netname 
 * return a pointer to the influxConn struct. 
 * I should have been able to do with with hash_find_str but
 * it failed to match any of the strings. 
 * This works and is likley no more expensive
 */
influxConn *hash_find_curl_handle(const char *netname) {
	struct NetworksHash *current, *temp;
	if (!netname || netname == NULL) 
		return NULL;
	HASH_ITER(hh, networks, current, temp) {
		if (strcmp(current->netname, netname) == 0) {
		        break;
		}
	}
	return current->conn;
}

void hash_close_curl_handles() {
	struct NetworksHash *current, *temp;
	HASH_ITER(hh, networks, current, temp) {
		free((void *)current->conn->host_url);
		free((void *)current->conn->db);
		free((void *)current->conn->user);
		free((void *)current->conn->pass);
		rest_cleanup(current->conn);
		free(current->conn);
	}
}


/* create influxConn curl handles based on the information in the config
 * file network stanzas. This handle is stored in the NetworkHash struct.
 */
int hash_get_curl_handles () {
	struct NetworksHash *current, *temp;
	influxConn *mycurl = NULL;
	
	HASH_ITER(hh, networks, current, temp) {
		/* create the connection */

		mycurl = create_conn ((char *)current->influx_host_url,  
		 		      (char *)current->influx_database,  
		 		      (char *)current->influx_user,  
		 		      (char *)current->influx_password, 
		 		      current->verify_ssl); 
		log_debug ("Created connection for %s to %s: %p", current->netname, current->influx_host_url, mycurl);

		current->conn = mycurl; /*current->conn needs *some* value before leaving this function*/
		if (mycurl == NULL) {
                        log_error("Could not initiate the curl connection to %s", 
                                  current->influx_host_url);
			return -1;
		}
	}
	return 1;
}

/* find a specific connection ID in the hash */
struct ConnectionHash *hash_find_cid(int cid) {
        struct ConnectionHash *temphash;
	HASH_FIND_INT(activeflows, &cid, temphash );  
	return temphash;
};

/* add the new connection to the hash */
struct ConnectionHash *hash_add_connection (struct estats_connection_info *conn) {
	struct ConnectionHash *flow = NULL;
	flow = (ConnectionHash*)malloc(sizeof(ConnectionHash));
	flow->cid = conn->cid;
	flow->seen = true;
	flow->lastpoll = time(NULL);
	HASH_ADD_INT(activeflows, cid, flow);
	log_debug("Added hash: %d", flow->cid, conn->cmdline);
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
		/* if the count is 0 then the networks config option is
		 * empty and this means that *everything* should match that
		 * network */
		if ((current->net_addrs_count == 0) || (match_ips(asc->rem_addr, 
								  current->net_addrs, 
								  current->net_addrs_count))) {

			flow->netname = strndup(current->netname, strlen(current->netname));
			flow->domain_name = strndup(current->domain_name, strlen(current->domain_name));
			return 1;
		}
	}
	/* if there is no match to any known network what should we do? */
	/* right now, nothing */
	return 0;
}

int hash_delete_flow (int cid) {
	struct ConnectionHash *current;
	HASH_FIND_INT(activeflows, &cid, current);
	if (current != NULL) {
		log_debug("Deleting flow: %d", current->cid);
		HASH_DEL(activeflows, current);
		/* we may delete a flow before these are added to the struct */
		if (current->added) {
			free((void *)current->netname);
			free((void *)current->domain_name);
			free((void *)current->flowid_char);
			free(current);
		}
		return 1;
	}
	return 0;
}

void hash_clear_hash () {
	struct ConnectionHash *curconn, *tempconn;
	struct NetworksHash *curnet, *tempnet;
	int i;
	HASH_ITER(hh, activeflows, curconn, tempconn) {
		HASH_DEL(activeflows, curconn);
		free((void *)curconn->netname);
		free((void *)curconn->domain_name);
		free((void *)curconn->flowid_char);
		free(curconn);
	}
	HASH_ITER(hh, networks, curnet, tempnet) {
		HASH_DEL(networks, curnet);
		free((void *)curnet->netname);
		free((void *)curnet->domain_name);
		free((void *)curnet->influx_host_url);
		free((void *)curnet->influx_database);
		free((void *)curnet->influx_password);
		free((void *)curnet->influx_user);
		for (i = 0; i< curnet->net_addrs_count; i++) {
			free((void *)curnet->net_addrs[i]);
		}
		if (curnet->net_addrs_count)
			free(curnet->net_addrs);
		free(curnet);
	}
}

void hash_sort_by_precedence () {
	HASH_SORT(networks, _by_precedence);
}

int _by_precedence (NetworksHash *a, NetworksHash *b) {
	return (a->precedence - b->precedence);
};

/* used for debugging purposes mostly but may be useful in the future*/
int hash_count_hash () {
	return HASH_COUNT(activeflows);
}
