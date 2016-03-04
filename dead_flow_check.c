/* in these functions we check for dead flows that may have happened
 * when the listener restarts. If a dead flow is found then the most recent
 * data collection timestamp is used. This may significnatly impact some 
 * calculations but there isn't much we can do about that right now. 
 * An alternative method would be to have the listener write the most recent time
 * to a file every second. We could then use this as it may be somewhat
 * more accurate (depends on how long it takes the listenr restart and the
 * metric polling period). 
 * 
 * Basically here is the process
 * 1) On program start get a list of all flows matching our DTN 
 *    that have an EndTime of 0 and caculate flowids for each of them.
 * 2) Get a list of currently open connections and caculate flow IDs for them
 * 3) Any that match are discarded. All others taken from the DB
 *    need to have their end time set.
 */

#include "dead_flow_check.h"

extern struct NetworksHash *networks;
extern struct Options options;
struct DeadFlowHash *dfhash;

/* This global is set so we can tag each item in the orphan flow hash
 * with the associated network connection. 
 * i do not like using this as a global but there is no threading 
 * so it should be alright. I should rethink how values are being 
 * passed through the functions here
 */
NetworksHash *global_current_network;


/* primary function to find and resolve orphan flows
 * step through each network connection and get all flows
 * that have an EndTime of 0. Pass that jsonObject to the parser
 * and build a hash of them
 */
void get_end_time () {
	struct NetworksHash *current, *temp;
	CURLcode curl_res;
	influxConn *mycurl = NULL;
	json_object *json_in = NULL;
	char *query;
	int length;

	/* iterate over the open curl handles and fetch 
	 * endtime data from each of them as json objects
	 */
	HASH_ITER(hh, networks, current, temp) {
		global_current_network = current; /* we use this later to tage the flow with the associated network */
		/* get curl handle */
		mycurl = current->conn;
		mycurl->response_size = 0;
		
		/* build the query */
		length = strlen(options.dtn_id) + strlen(current->domain_name) +
			strlen(current->netname) + 128;
		query = malloc(length);
		snprintf(query, length,
			 "SELECT flow,value FROM EndTime WHERE dtn='%s' and domain='%s' and netname='%s' and value=0",
			options.dtn_id, current->domain_name, current->netname);

		curl_res = influxQuery(mycurl, query);
		free(query);
		/* if this fails go to the next connection but don't fail. */
		if (curl_res != CURLE_OK) {
			log_error("Curl Failure for %s while checking stale flows",
				  curl_easy_strerror(curl_res));
			continue;
		}

		if (build_json_object(mycurl->response, &json_in) == 0) {
			// failed to form valid json object
			// the called function will throw a warning
			continue;
		}

		/* we are looking for flows so set the flow flag to 1 */
		parse_flows_json(json_in, 1);
		json_object_put(json_in); /* free json object*/
	}
	get_current_flows();
	process_dead_flows();
	/* and we are done */
}

/* take the incoming json string and turn it into an object 
 * char response: incoming json string
 * json_object json_in: pointer to json object that will hold parsed string
 * returns 0 on failre, 1 on success
 */
int build_json_object ( char *response, json_object **json_in) {
        json_tokener *tok = json_tokener_new();
        enum json_tokener_error jerr;
	if (strlen(response) < 1)
		return 0;
	
        // grab the incoming json string
        *json_in = json_tokener_parse_ex(tok, response, strlen(response));
        while ((jerr = json_tokener_get_error(tok)) == json_tokener_continue);
        if (jerr != json_tokener_success)
        {
                // it doesn't seem to be a json object
                fprintf(stderr, "Inbound JSON Error: %s\n", json_tokener_error_desc(jerr));
		json_tokener_free(tok);
                return 0;
        }
	
        if ((int)(tok->char_offset) < (int)(strlen(response))) // shouldn't access internal fields
        {
                // this is when we get characters appended to the end of the json object
		fprintf(stderr, "Poorly formed JSON object. Check for extraneous characters.");
		json_tokener_free(tok);
                return 0;
        }
        json_tokener_free(tok);
	return 1;
}

/* go through the values array for the flow ids and add them to a hash 
 * json_object *jobj: inbound json object (array)
 * int index: position in array for flow id string
 */
void getFlows (json_object *jobj, int index) {
	int i, length;
	json_object *jvalue; 
	json_object *jarray = jobj;
	json_object *values;
	/*turn the key:value pair into an array of arrays*/
      	json_object_object_get_ex(jobj, "values", &jarray); 
        /*Getting the numbers of arrays in the object*/
	length = json_object_array_length(jarray); 
	if (length > 0) {
		for (i = 0; i < length; i++) {
			struct DeadFlowHash *curr = NULL;
			curr = (DeadFlowHash *)malloc(sizeof(DeadFlowHash));
			values = json_object_array_get_idx(jarray, i);
			jvalue = json_object_array_get_idx(values, index);
			/* add to hash*/
			curr->flow = (char *)strdup(json_object_get_string(jvalue));
			/* we do this so we can match the flow to a specific network connection */
			curr->network = global_current_network;
			HASH_ADD_KEYPTR(hh, dfhash, curr->flow, strlen(curr->flow), curr);
		}
	}
}

/* get the time value from a json object
 * json_object jobj: inbound json object
 * int index: position of time value in array
 * returns: timestamp on success, -1 on failure
 */
uint64_t getTime (json_object *jobj, int index) {
	json_object *jvalue; 
	json_object *jarray = jobj;
	json_object *values;
	struct tm tm = {0}; 
	time_t t = 0;
	/* put the values array into a new object */
      	json_object_object_get_ex(jobj, "values", &jarray); 
	/* now get the real array*/
	values = json_object_array_get_idx(jarray, 0);
	/* get the value in the index position (should be the date*/
	jvalue = json_object_array_get_idx(values, index);
	/* we are assuming it's in RFC 3339 format. We don't error check
	 * as we are getting this from influxdb directly. Not the best move
	 * but should be safe */
	strptime(json_object_get_string(jvalue), "%FT%TZ", &tm);
	/* turn the date struct into epoch */
	t = mktime(&tm);
	return t;
}

/* it is possible that the index position of the value we are
 * seeking may change. As such we need to find the index position
 * by iterating through the columns array to find the 'title' for the
 * metric we want
 * json_object jobj: inbound json object
 * int flows: flag to determine if we want flow ids or time values
 * return: int position of index
 */
int getIndex (json_object *jobj, int flows) {
	int i, length;
	int j = -1;
	json_object *jvalue; 
	json_object *jarray = jobj;
	char *needle;
	if (flows)
		needle = "flow";
	else
		needle = "time";
	
	json_object_object_get_ex(jobj, "columns", &jarray); /*Getting the array if it is a key value pair*/
	length = json_object_array_length(jarray); /*Getting the length of the array*/
	for (i = 0; i < length; i++) {
		jvalue = json_object_array_get_idx(jarray, i); /*Getting the array element at position i*/
		if (strpos((char *)json_object_get_string(jvalue), needle) == 0)
			j = i;
	}
	return (j);
}

/* recursively look through json arrays
 * json_object jobj: inbound json object
 * char key: key name of array
 * int flows: flag to determine type fo data being sought (flowid vs time)
 */
void json_parse_array( json_object *jobj, char *key, int flows) {
	enum json_type type;
	int arraylen;
	int i;
	json_object * jvalue;
	json_object *jarray = jobj; /*Simply get the array*/
	
	if(key)
		json_object_object_get_ex(jobj, key, &jarray); /*Getting the array if it is a key value pair*/
	
	arraylen = json_object_array_length(jarray); /*Getting the length of the array*/
	for (i=0; i< arraylen; i++){
		jvalue = json_object_array_get_idx(jarray, i); /*Getting the array element at position i*/
		type = json_object_get_type(jvalue);
		if (type == json_type_array) {
			json_parse_array(jvalue, NULL, flows);
		}
		else if (type != json_type_object) {
		}
		else {
			parse_flows_json(jvalue, flows);
		}
	}
}

/*Parsing the root json object*/
/* TODO: This is a kludge as we are depending on a NULL return at the end for this
 * to actually work and it may not work at different levels of optimization. Figure out the
 * boundary conditions and possible rewrite
 */ 
uint64_t parse_flows_json(json_object * jobj, int flows) {
	int index = 0;
	uint64_t timestamp;
	enum json_type type;
	json_object_object_foreach(jobj, key, val) { /*Passing through every array element*/
		type = json_object_get_type(val);
		switch (type) {
		case json_type_array:
			if (key) {
				if (strpos(key, "columns") == 0) {
					if (flows) 
						index = getIndex(jobj, flows);
					else
						index = getIndex(jobj, flows);
					if (index == -1) {
						fprintf(stderr, "Failed to get index position for orphan flow data\n");
						break;
					}
				}
				if (strpos(key, "values") == 0) {
					if (flows) 
						getFlows(jobj, index);
					else {
						timestamp = getTime(jobj, index);
						return timestamp;
					}
				}
			}
			json_parse_array(jobj, key, flows);
			break;
		case json_type_string:
		case json_type_boolean: 
		case json_type_double: 
		case json_type_int: 
		case json_type_object:
		case json_type_null:
			break;
		}
	}
	return; /*this will throw a warning. It's okay*/
} 

/* go through the open tcp connections and get the 
 * the open connections. Build a sha256 hash based on the
 * tuple and starttime data and compare that to flow ids
 * we received from the database. If any of those match
 * remove it from the orphan flow hash as it means that they are
 * active
 */
void get_current_flows () {
	struct estats_error* err = NULL;
	struct estats_nl_client* cl = { 0 };
	struct estats_connection_list* clist = NULL;
	struct estats_connection_info* ci;
	struct estats_val_data* esdata = NULL;
	struct estats_mask stime_mask;
	struct estats_connection_tuple_ascii asc;
	uint64_t starttime = 0;
	int i;
	
	/* set up estats mask to get the StartTime information */
	/* we need this for the flow id hash */
	stime_mask.masks[0] = 1UL << 12;/*perf*/
        stime_mask.masks[1] = 0;        /*path*/
        stime_mask.masks[2] = 0;        /*stack*/
        stime_mask.masks[3] = 0;        /*app*/ 
        stime_mask.masks[4] = 0;        /*tune*/ 
        stime_mask.masks[5] = 0;        /*extras*/ 

        for (i = 0; i < MAX_TABLE; i++) {
                stime_mask.if_mask[i] = 1;
        }

	/* init the nl client and gather the connection information */
	Chk(estats_nl_client_init(&cl));

	Chk(estats_connection_list_new(&clist));
	Chk(estats_list_conns(clist, cl));
	Chk(estats_connection_list_add_info(clist));
	Chk(estats_val_data_new(&esdata));
	
	/* we need to generate a flowid for each of the active connections
	 * we then compare that to the flow ids in the hash and 
	 * delete anything that exists. Everything left over will 
	 * be closed flows without an end time */
	estats_list_for_each(&clist->connection_info_head, ci, list) {
		char tempstr[128] = "\0"; /*should handle 2 ipv6, ts, and port information*/
		char timechar[19];
		unsigned char hash[SHA256_DIGEST_LENGTH];
		char flowid[SHA256_TEXT+1];
		SHA256_CTX sha256;
		DeadFlowHash *dfresult = NULL;
		
		Chk(estats_nl_client_set_mask(cl, &stime_mask));
		Chk2Ign(estats_read_vars(esdata, ci->cid, cl));
		/* get the StartTime from estats */
		for (i = 0; i < esdata->length; i++) {
			if (esdata->val[i].masked)
				continue;
			starttime = esdata->val[i].uv64 * 1000;
		}
		estats_connection_tuple_as_strings(&asc, &ci->tuple);
		
		/* there is a more compact way of doing this but
		 * using a single snprintf produces a different hash value
		 * so for now we keep it like this */
		snprintf(timechar, 19, "%"PRIu64"", starttime);
		strcat(tempstr, asc.local_addr);
		strcat(tempstr, asc.rem_addr);
		strcat(tempstr, asc.local_port);
		strcat(tempstr, asc.rem_port);
		strcat(tempstr, timechar);
		
		SHA256_Init(&sha256);
		SHA256_Update(&sha256, tempstr, strlen(tempstr));
		SHA256_Final(hash, &sha256);
		for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
			sprintf(flowid + (i * 2), "%02x", hash[i]);
		HASH_FIND_STR(dfhash, flowid, dfresult);
		if (dfresult) {
			/* the flow ids matched so it is active. 
			 * so delete it from our hash
			 */
			HASH_DEL(dfhash, dfresult);
			free (dfresult->flow);
			free (dfresult);
		}
	}
	/* anything left in the hash doesn't have an active flow 
	 * associated with it*/

Continue:
	estats_val_data_free(&esdata);
	estats_connection_list_free(&clist);
	
Cleanup:
	estats_nl_client_destroy(&cl);
	
	if (err != NULL) {
		PRINT_AND_FREE(err);
	}
}

/* iterate over the dead flow hash. Anything left in the hash is
 * an unmatched flow and presumed to be dead. Grab the newest
 * metric associated with that flowid and use that to write the
 * EndTime value. This part is no fun. Basically we need to 
 * query the DB for each flowid, parse out the timestamp, create a 
 * new query, and then remove the item from the hash. At the end the
 * hash shoudl be empty and all of the dead flows should have 
 * somewhat valid EndTimes
 */
void process_dead_flows () {
	DeadFlowHash *currflow, *tempflow;
	NetworksHash *currnet, *tempnet;
	influxConn *readcurl, *writecurl;
	char *query;
	int qlen;
	CURLcode curl_res;
	json_object *json_in = NULL;
	uint64_t endtime;
	
	/* iterate through the networks hash
	 * we do this so that we only query db's where the flow
	 * is a possible member. */
	HASH_ITER(hh, networks, currnet, tempnet) {
		/* we can't use the same curl handle twice in the following loop.
		 * I'm not entirely sure why. However, Influx says "Method Not Allowed"
		 * and that isn't valid json so it just bombs. TODO: Figure out why
		 */
		readcurl = currnet->conn;
		writecurl = create_conn ((char *)currnet->conn->host_url, (char *)currnet->conn->db,
					 (char *)currnet->conn->user, (char *)currnet->conn->pass,
					 currnet->conn->ssl);
		HASH_ITER(hh, dfhash, currflow, tempflow) {
			if (currnet != currflow->network)
				continue;
			qlen = strlen(currflow->flow) +
				strlen("SELECT time, value FROM SegsIn WHERE flow ='' ORDER BY DESC LIMIT 1")
				+ 1;
			query = malloc (qlen);
			snprintf(query, qlen,
				 "SELECT time, value FROM SegsIn WHERE flow ='%s' ORDER BY DESC LIMIT 1",
				 currflow->flow);
			readcurl->response_size = 0;
			curl_res = influxQuery(readcurl, query);
			if (curl_res != CURLE_OK)
				log_error("Curl Failure for %s while finding EndTime for orphan flows",
					  curl_easy_strerror(curl_res));
			if (build_json_object(readcurl->response, &json_in) == 0) {
				/* throw an exception as the json string is invalid and continue */
				continue;
			}
			endtime = parse_flows_json(json_in, 0) * 1000000000;
			if (endtime == 0) {
				fprintf(stderr, "Invalid endtime value. Skipping\n");
				continue;
			}
			json_object_put(json_in); /*free the json object*/
			
			/* qlen should be 158 but in case anything changes in the formats we do this */
			qlen = strlen ("EndTime,type=flowdata,netname=,domain=,dtn=,flow= value=i 0") 
				+ strlen(currnet->netname)
				+ strlen(currnet->domain_name)
				+ strlen(options.dtn_id)
				+ strlen(currflow->flow)
				+ 20;
			query = realloc(query, qlen);
			snprintf (query, qlen, "EndTime,type=flowdata,netname=%s,domain=%s,dtn=%s,flow=%s value=%lui 0",
				  currnet->netname, currnet->domain_name, options.dtn_id, currflow->flow, endtime);
			query[qlen-1] = '\0';
			curl_res = influxWrite(writecurl, query);
			if (curl_res != CURLE_OK)
				log_error("Curl Failure for %s while updating orphan flows",
					  curl_easy_strerror(curl_res));
			free (query);
			HASH_DEL(dfhash, currflow);
			free(currflow->flow);
			free(currflow);
		}
		free_conn(writecurl);
	}
}

