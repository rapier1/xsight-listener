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
#include "safe_malloc.h"

extern struct NetworksHash *networks;
extern struct Options options;
struct DeadFlowHash *dfhash;
struct DeadFlowHash *ethash;
struct DeadFlowHash *sthash;


/* This global is set so we can tag each item in the orphan flow hash
 * with the associated network connection. 
 * i do not like using this as a global but there is no threading 
 * so it should be alright. I should rethink how values are being 
 * passed through the functions here
 */
NetworksHash *global_current_network;


/* NEED TO REDO THIS. We no longer have EndTime=0 to look for. We 
   need to get a list of all flows with a StartTime and all flows with
   and EndTime. Find the flows with a StartTime but no EndTime. Then check 
   those hash values to see if any of them ar still active. Write an
   EndTime for the ones that are not */


/* primary function to find and resolve orphan flows
 * step through each network connection and get all flows
 * that have an EndTime of 0. Pass that jsonObject to the parser
 * and build a hash of them
 * only look at flows in the past day - cjr 6/5/2019
 */
void get_end_time () {
	struct NetworksHash *current, *temp;
	CURLcode curl_res;
	influxConn *mycurl = NULL;
	json_object *json_in = NULL;
	char query[512];

	//printf("In get_end_time\n");
	/* iterate over the open curl handles and fetch 
	 * endtime data from each of them as json objects
	 */
	HASH_ITER(hh, networks, current, temp) {
		global_current_network = current; /* we use this later to tag the flow with the associated network */

		/* get curl handle*/
		mycurl = current->conn[0];
		mycurl->response_size = 0;
		
		/* build the query */
		snprintf(query, 512,
			 "SELECT flow,value FROM EndTime WHERE time > now() - 1d");
		curl_res = influxQuery(mycurl, query);
		/* if this fails go to the next connection but don't fail. */
		if (curl_res != CURLE_OK) {
			log_error("Curl Failure for %s while checking stale flows",
				  curl_easy_strerror(curl_res));
			continue;
		}

		if (build_json_object(mycurl->response, &json_in) == 0) {
			/* failed to form valid json object
			 * the called function will throw a warning */
			continue;
		}

		/* we are looking for endtime flows so set the flow flag to 1 
		 * and the startttime flag to false */
		parse_flows_json(json_in, 1, NULL, NULL);
		json_object_put(json_in); /* free json object*/

		mycurl->response_size = 0;
		
		/* build the query */
		snprintf(query, 512,
			 "SELECT flow,value FROM StartTime WHERE time > now() - 1d");
		curl_res = influxQuery(mycurl, query);
		/* if this fails go to the next connection but don't fail. */
		if (curl_res != CURLE_OK) {
			log_error("Curl Failure for %s while checking stale flows",
				  curl_easy_strerror(curl_res));
			continue;
		}

		if (build_json_object(mycurl->response, &json_in) == 0) {
			/* failed to form valid json object
			 * the called function will throw a warning */
			continue;
		}

		/* we are looking for starttime flows so set the flow flag to 1 
                 * and the starttime flag to true */
		parse_flows_json(json_in, 1, NULL, 1);
		json_object_put(json_in); /* free json object*/		
	}
	find_difference();
	get_current_flows();
	process_dead_flows();
	clean_up(); /* go through all of the hashes and make sure we free everything in them */
	/* and we are done */
}

/* find the difference between the EndTime has and the StartTime hash.
 * Basically, go through the StartTime hash and any flows that don't
 * exist in the EndTime hash are placed in the deadflow hash (dfhash)
 * then use the dfhash in the rest of the code */

void find_difference () {
	DeadFlowHash *currflow, *tempflow, *response;
	
	HASH_ITER(hh, sthash, currflow, tempflow) {
		HASH_FIND_STR(ethash, currflow->flow, response);
		if (response == NULL) {
			/* We may have duplicate StartTimes in the DB (just because, that's why
			 * so make sure we haven't already added this flow to the dfhash */
			HASH_FIND_STR(dfhash, currflow->flow, response);
			if (response == NULL) {
				/* printf ("Could not find a match for %s\n", currflow->flow);*/
				HASH_ADD_KEYPTR(hh, dfhash, currflow->flow, strlen(currflow->flow), currflow);
			}
		}
	}
	log_debug ("Number of dead flows: %d", HASH_COUNT(dfhash)); 
}


/* take the incoming json string and turn it into an object 
 * char response: incoming json string
 * json_object json_in: pointer to json object that will hold parsed string
 * returns 0 on failre, 1 on success
 */
int build_json_object ( char *response, json_object **json_in) {
        json_tokener *tok = json_tokener_new();
        enum json_tokener_error jerr;

	/* printf("In build_json_object\n");*/
	if (strlen(response) < 1)
		return 0;
	
        /* grab the incoming json string */
        *json_in = json_tokener_parse_ex(tok, response, strlen(response));
        while ((jerr = json_tokener_get_error(tok)) == json_tokener_continue);
        if (jerr != json_tokener_success)
        {
                /* it doesn't seem to be a json object */
                fprintf(stderr, "Inbound JSON Error: %s\n", json_tokener_error_desc(jerr));
		json_tokener_free(tok);
                return 0;
        }
	
        if ((int)(tok->char_offset) < (int)(strlen(response))) /* shouldn't access internal fields */
        {
		/* this is when we get characters appended to the end of the json object */
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
void getFlows (json_object *jobj, int index, bool starttime) {
	int i, length;
	json_object *jvalue; 
	json_object *jarray = jobj;
	json_object *values;
	/* printf("In getFlows\n"); */
	/*turn the key:value pair into an array of arrays*/
      	json_object_object_get_ex(jobj, "values", &jarray); 
        /*Getting the numbers of arrays in the object*/
	length = json_object_array_length(jarray); 
	if (length > 0) {
		for (i = 0; i < length; i++) {
			struct DeadFlowHash *curr = NULL;
			curr = (DeadFlowHash *)SAFEMALLOC(sizeof(DeadFlowHash));
			values = json_object_array_get_idx(jarray, i);
			jvalue = json_object_array_get_idx(values, index);
			/* add to hash*/
			curr->flow = (char *)strdup(json_object_get_string(jvalue));
			/* we do this so we can match the flow to a specific network connection */
			curr->network = global_current_network;
			if (starttime)
				HASH_ADD_KEYPTR(hh, sthash, curr->flow, strlen(curr->flow), curr);
			else
				HASH_ADD_KEYPTR(hh, ethash, curr->flow, strlen(curr->flow), curr);
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
	struct tm tm; 
	time_t t = 0;

	/* printf("In getTime\n");*/
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

	/* printf ("In getIndex\n");*/
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
 * uint64_t endtime: pointer to value for endtime used by getTime in process_dead_flows
 */
void json_parse_array( json_object *jobj, char *key, int flows, uint64_t *endtime, bool starttime) {
	enum json_type type;
	int arraylen;
	int i;
	json_object * jvalue;
	json_object *jarray = jobj; /*Simply get the array*/

	/*printf("In json_parse_array\n");*/
	if(key)
		json_object_object_get_ex(jobj, key, &jarray); /*Getting the array if it is a key value pair*/
	
	arraylen = json_object_array_length(jarray); /*Getting the length of the array*/
	for (i=0; i< arraylen; i++){
		jvalue = json_object_array_get_idx(jarray, i); /*Getting the array element at position i*/
		type = json_object_get_type(jvalue);
		if (type == json_type_array) {
			json_parse_array(jvalue, NULL, flows, endtime, starttime);
		}
		else if (type != json_type_object) {
		}
		else {
			parse_flows_json(jvalue, flows, endtime, starttime);
		}
	}
}

/*Parsing the root json object*/
void parse_flows_json(json_object * jobj, int flows, uint64_t *endtime, bool starttime) {
	int index = 0;
	enum json_type type;

	/* printf("In parse_flows_json\n"); */
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
						getFlows(jobj, index, starttime);
					else {
						*endtime = getTime(jobj, index) * 1000000000;
					}
				}
			}
			json_parse_array(jobj, key, flows, endtime, starttime);
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
	
	/* printf ("In get_current_flows\n"); */
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
			log_debug("Matched orphan flow with existing flow: %s", flowid);
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
/* because you screwed this up before. Do *not* delete/free from dfhash. These are
   just key pointers to structures in sthash and ethash. If you free dfhash you end
   up with double frees when you clean up st/ethash. Just ignore what you wrote above */
void process_dead_flows () {
	DeadFlowHash *currflow, *tempflow;
	NetworksHash *currnet, *tempnet;
	influxConn *readcurl, *writecurl;
	char query[512];
	int qlen;
	CURLcode curl_res;
	json_object *json_in = NULL;
	int counter;
	int dfhash_max = HASH_COUNT(dfhash);
	
	/* printf ("In process_dead_flows\n");*/
	/* iterate through the networks hash
	 * we do this so that we only query db's where the flow
	 * is a possible member. */
	HASH_ITER(hh, networks, currnet, tempnet) {
		/* we can't use the same curl handle twice in the following loop.
		 * I'm not entirely sure why. However, Influx says "Method Not Allowed"
		 * and that isn't valid json so it just bombs. TODO: Figure out why
		 */
		readcurl = currnet->conn[0];
		writecurl = currnet->conn[1];
		counter = 0;
		HASH_ITER(hh, dfhash, currflow, tempflow) {
			uint64_t endtime = 0;
			if (currnet != currflow->network)
				continue;

			counter++;
			/* get the time stamp from the last metric and use that as the EndTime*/
			qlen = snprintf(query, 512,
					"SELECT time, value FROM SegsIn WHERE flow ='%s' AND time > now()-24h ORDER BY DESC LIMIT 1",
					currflow->flow);
			query[qlen] = '\0';
			readcurl->response_size = 0;
			curl_res = influxQuery(readcurl, query);
			if (curl_res != CURLE_OK)
				log_error("Curl Failure for %s while finding EndTime for orphan flows",
					  curl_easy_strerror(curl_res));
			if (build_json_object(readcurl->response, &json_in) == 0) {
				/* throw an exception as the json string is invalid and continue */
				continue;
			}
			/* pass the pointer to endtime into the json processor
			 * if it remains 0 then it means we couldn't find a timestamp
			 * value in the metrics to use
			 */
			parse_flows_json(json_in, 0, &endtime, NULL);
			if (endtime == 0) {
				/* TODO: instead of skipping we should just insert the
				 * current time. Not ideal but better than leaving it as 0 */
				fprintf(stderr, "Invalid endtime value. Skipping\n");
				endtime = time(NULL);
				//continue;
			}
			json_object_put(json_in); /*free the json object*/
			
			qlen = snprintf (query, 512,
					 "EndTime,type=flowdata value=%"PRIu64"i,flow=\"%s\"\n",
					 endtime,
					 currflow->flow);
			query[qlen] = '\0';
			curl_res = influxWrite(writecurl, query);
			if (curl_res != CURLE_OK)
				log_error("Curl Failure for %s while updating orphan flows",
					  curl_easy_strerror(curl_res));
			else
				log_debug("Closed orphan flow %s (%d of %d)", currflow->flow, counter, dfhash_max);
		}
	}
}

/* go through each of the hashes created and ensure that they are all 
   removed and done */
void clean_up () {
	log_debug2("In dead flow cleanup\n");
	struct DeadFlowHash *current_ethash, *current_sthash, *tmp;
	int sthash_max = HASH_COUNT(sthash);
	int ethash_max = HASH_COUNT(ethash);	
	int counter = 0;
	/* end time hash */
	HASH_ITER(hh, ethash, current_ethash, tmp) {
		HASH_DEL(ethash,current_ethash);
		free(current_ethash->flow);
		free(current_ethash);
		counter++;
		log_debug2("Cleared ethash item (%d of %d)", counter, ethash_max);
	}
	/* start time hash */
	counter = 0;
	HASH_ITER(hh, sthash, current_sthash, tmp) {
		HASH_DEL(sthash,current_sthash);
		free(current_sthash->flow);
		free(current_sthash);
		counter++;
		log_debug2("Cleared sthash item (%d of %d)", counter, sthash_max);
	}
	/* this should be empty so we just need to clear it */
	//HASH_CLEAR(hh, dfhash);
}
