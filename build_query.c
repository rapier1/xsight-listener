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
#define _GNU_SOURCE 1
#include "build_query.h"

extern struct Options options;
extern struct NetworksHash *networks;

void threaded_path_trace(struct PathBuild *);
void threaded_influx_write (struct ThreadWrite *);

/* this is just used to create the job struct 
 *  and call the threaded function 
 */
void add_path_trace (threadpool curlpool, threadpool tracepool, 
		     ConnectionHash *flow, struct estats_connection_info *conn) {
	struct estats_error* err = NULL;
	struct estats_connection_tuple_ascii asc;
	struct PathBuild *job;
	
	/* get the ascii tuple information for the connection we care about */
	Chk(estats_connection_tuple_as_strings(&asc, &conn->tuple)); 
	
	/* all the data in the flow struct has to be copied over to the 
	 * job struct. The flow might be freed while the path is being traced
	 * which leads to some badness (null pointers etc).
	 */
	job = malloc(sizeof (struct PathBuild));
	job->local_addr = strndup(asc.local_addr, strlen(asc.local_addr));
	job->rem_addr = strndup(asc.rem_addr, strlen(asc.rem_addr));
	job->group = strndup(flow->group, strlen(flow->group)); 
	job->domain_name = strndup(flow->domain_name, strlen(flow->domain_name));
	uuid_copy(job->flowid, flow->flowid);
	job->cid = flow->cid;
	job->influx_conn = flow->conn;
	job->mythread = curlpool;
	
	/* add it to the thread pool */
	thpool_add_work(tracepool, (void*)threaded_path_trace, (void*)job);
	
Cleanup:
	if (err != NULL) {
		char flowid_char[40];
		uuid_unparse(flow->flowid, flowid_char);
		log_error("%s:\t%s\t%s tuple to ascii conversion error in add_flow_influx", 
			  flowid_char, estats_error_get_extra(err), 
			  estats_error_get_message(err));
		estats_error_free(&err);
	}
}

/* All of the real work for the traceroute is done here
 * we need one thread pool (tracepool) for the traceroutes
 * we use other thread pool (curlpool) to write to the curl handles
 * because of limitation on how we implement curl we can only
 * have one thread to handle all of the curl connections to the database
 * however we can have multiple threads calling the traceroute functions
 * so the 4 possible trace threads all funnel into the single curl thread
 */
void threaded_path_trace (struct PathBuild *job) {
	struct addrinfo *local_address = 0;
	struct addrinfo *remote_address = 0;
	struct addrinfo hint;
	struct ThreadWrite *influxjob;
	influxConn *curl_conn;
	int MAX_LINE_SZ_PATH = 16384;
	int ttl = 0;
	int i;
	int ret = -1;
	int size = 0;
	int total_size = 0;
	char results[32][45]; /* hops are limited to 30 but start at 1 */
	char flowid_char[40];
	char *tag_str;
	char *temp_str;
	char influx_data[MAX_LINE_SZ_PATH];

	memset(results, '\0', 32*45); /*initialize the results array to null */

	/* get the curl handle. Do this now so we don't waste time if the handle is null*/
	curl_conn = hash_find_curl_handle(job->group);
	if (curl_conn == NULL) {
		log_error("Can't add flow data. There is no existing curl connection to the data base for group %s\n", 
			  job->group);
		goto Cleanup;
	}

	/* determine if the *source* address is ipv4 or ipv6*/
	memset(&hint, '\0', sizeof (hint)); 
	hint.ai_family = AF_UNSPEC; 

	ret = getaddrinfo(job->local_addr, NULL, &hint, &local_address);
	if (ret < 0 ) {
		freeaddrinfo(local_address);
		log_error("Badly formed local address in path_trace: %s", job->local_addr);
		goto Cleanup;
	}

	ret = getaddrinfo(job->rem_addr, NULL, &hint, &remote_address);
	if (ret < 0 ) {
		freeaddrinfo(remote_address);
		log_error("Badly formed remote address in path_trace: %s", job->local_addr);
		goto Cleanup;
	}

	/* if the families don't match we have a problem. 
	 * at this point we will just exit gracefully and move on
	 * TODO: later we should determine if addrinfo has other elements in the linked
	 * list that we can go thorugh
	 */
	if (local_address->ai_family != remote_address->ai_family) {
        freeaddrinfo(remote_address);
		freeaddrinfo(local_address);
		log_error("path_trace: Local and remote address families do not match");
		goto Cleanup;
	}

	/* fill the results array with the various hops and get the 
	 * ttl. This value corresponds to the size of the array
	 */
	if (local_address->ai_family == AF_INET) {
		ttl = trace4(job->rem_addr, job->local_addr, results);
	} else {
		ttl = trace6(job->rem_addr, job->local_addr, results);
	}
	
	/* this should never happen */
	if (ttl < 1) {
		freeaddrinfo(remote_address);
		freeaddrinfo(local_address);
		goto Cleanup;
	}

	/*create the tag string*/

	/* get the uuid in char format */
	uuid_unparse(job->flowid, flowid_char);

	/* determine the size of the tag string so we can malloc it */
	size = snprintf(NULL, 0, ",type=flowdata,group=%s,domain=%s,dtn=%s,flow=%s",
			  job->group, job->domain_name, options.dtn_id, flowid_char);
	size++;
	tag_str = malloc(size * sizeof(char) + 1);
	snprintf(tag_str, size, ",type=flowdata,group=%s,domain=%s,dtn=%s,flow=%s",
		 job->group, job->domain_name, options.dtn_id, flowid_char);
	tag_str[size-1] = '\0';
	
	/* init the final command string for influx*/
	/* this is freed in the threaded_influx_write function*/
	//influx_data = malloc(4);
	//*influx_data = '\0';

	/* iterate through each entry in the results array and craft an
	 * influx happy string */
	for (i = 1; i <= ttl; i++) {
		//size = strlen ("path,hop= value=\"\"\n") + strlen(tag_str) + strlen(results[i]) + 3;
		//printf ("size1: %d\n", size);
		size = snprintf(NULL, 0, "path%s,hop=%d value=\"%s\"\n", tag_str, i, results[i]) + 1;
		//printf ("size2: %d\n", size);
		total_size += size;
		temp_str = malloc(size);
		snprintf(temp_str, size, "path%s,hop=%d value=\"%s\"\n", tag_str, i, results[i]);
		temp_str[size-1] = '\0';
		//influx_data = realloc(influx_data, total_size);
		if (total_size < MAX_LINE_SZ_PATH) {
			strncat(influx_data, temp_str, size);
			influx_data[total_size-1] = '\0';
		}
		free(temp_str);
	}

	/* create the job struct for the curl write. This is freed in that function*/
	influxjob = malloc(sizeof(struct ThreadWrite));
	snprintf(influxjob->action, 32, "Added Path: %d", job->cid);
	influxjob->conn = job->influx_conn;
	influxjob->data = &influx_data[0];
	printf ("%s\n", influx_data); 
	/* add this to the curl thread pool */
	thpool_add_work(job->mythread, (void*)threaded_influx_write, (void*)influxjob);

	free(tag_str);
	free((void *)(job->local_addr));
	free((void *)(job->rem_addr));
	free((void *)(job->group));
	free((void *)(job->domain_name));
 	free(job); 
	freeaddrinfo(local_address);
	freeaddrinfo(remote_address);
Cleanup: 
	; /*just gets us out of the function */
}

/* get the identifying information and add it to the influx flow namespace*/
/* the unique sequence_number */
void add_flow_influx(threadpool curlpool, ConnectionHash *flow, struct estats_connection_info *conn) {
	struct estats_error* err = NULL;
	struct estats_connection_tuple_ascii asc;
	struct ThreadWrite *job;
	char flowid_char[40];
	char *influx_data;
	char *temp_str;
	char *tag_str;
	int length, size, total_size;
	size = total_size = 0;

	/* convert the tuples to a string */
	Chk(estats_connection_tuple_as_strings(&asc, &conn->tuple));

	/* init the final command string for influx*/
	influx_data = malloc(4);
	*influx_data = '\0';

	/* create the flowid */
	uuid_generate(flow->flowid);
	uuid_unparse(flow->flowid, flowid_char);

	/* match the IP to appropriate network from the config file */
	if (!hash_get_tags(&asc, flow)) {
		log_error ("This flow doesn't match any known monitored networks. Continuing.");
		goto Cleanup;
	}
	
	/* the above should return a pointer if it doesn't them
	 * it means the ip didn't match on anything at all
	 * this is a problem but we're just ignoring it now
	 * TODO: Fix this
	 */

	/* get the curl handle. Do this now so we don't waste time if the handle is null*/
	flow->conn = hash_find_curl_handle(flow->group);
	if (flow->conn == NULL) {
		log_error("Can't add flow data. There is no existing curl connection to the data base for group %s\n", flow->group);
		goto Cleanup;
	}
	
	/*create the tag string*/
	length = snprintf(NULL, 0, ",type=flowdata,group=%s,domain=%s,dtn=%s,flow=%s value=", 
			  flow->group, flow->domain_name, options.dtn_id, flowid_char);
	length++;
	tag_str = malloc(length * sizeof(char) + 1);
	snprintf(tag_str, length, ",type=flowdata,group=%s,domain=%s,dtn=%s,flow=%s value=", 
		 flow->group, flow->domain_name, options.dtn_id, flowid_char);
	tag_str[length-1] = '\0';
	
	/* add the src_ip */
	size = snprintf(NULL, 0, "src_ip%s\"%s\"\n", tag_str, asc.local_addr) + 1;
	total_size += size;
	temp_str = malloc(size);
	snprintf(temp_str, size, "src_ip%s\"%s\"\n", tag_str, asc.local_addr);
	temp_str[size-1] = '\0';
	influx_data = realloc(influx_data, total_size);
	strncat(influx_data, temp_str, size);
	influx_data[total_size-1] = '\0';
	free(temp_str);

	/* add the dest_ip */
	size = snprintf(NULL, 0, "dest_ip%s\"%s\"\n", tag_str, asc.rem_addr) + 1;
	total_size += size;
	temp_str = malloc(size + 1);
	snprintf(temp_str, size, "dest_ip%s\"%s\"\n", tag_str, asc.rem_addr);
	temp_str[size-1] = '\0';
	influx_data = realloc(influx_data, total_size + 1);
	strncat(influx_data, temp_str, size);
	influx_data[total_size-1] = '\0';
	free(temp_str);


	/* add the src_port */
	size = snprintf(NULL, 0, "src_port%s%s\n", tag_str, asc.local_port) + 1;
	total_size += size;
	temp_str = malloc(size + 1);
	snprintf(temp_str, size, "src_port%s%s\n", tag_str, asc.local_port);
	temp_str[size-1] = '\0';
	influx_data = realloc(influx_data, total_size + 1);
	strncat(influx_data, temp_str, size);
	influx_data[total_size-1] = '\0';
	free(temp_str);

	/* add the dest_port */
	size = snprintf(NULL, 0, "dest_port%s%s\n", tag_str, asc.rem_port) + 1;
	total_size += size;
	temp_str = malloc(size + 1);
	snprintf(temp_str, size, "dest_port%s%s\n", tag_str, asc.rem_port);
	temp_str[size-1] = '\0';
	influx_data = realloc(influx_data, total_size + 1);
	strncat(influx_data, temp_str, size);
	influx_data[total_size-1] = '\0';
	free(temp_str);


	/* add the command */
	size = snprintf(NULL, 0, "command%s\"%s\"\n", tag_str, conn->cmdline) + 1;
	total_size += size;
	temp_str = malloc(size + 1);
	temp_str[size-1] = '\0';
	snprintf(temp_str, size, "command%s\"%s\"\n", tag_str, conn->cmdline);
	influx_data = realloc(influx_data, total_size + 1);
	strncat(influx_data, temp_str, size);
	influx_data[total_size-1] = '\0';
	free(temp_str);

	/* note, we'll set the start time when we make the initial instrument read */
        
	/* the flow meta data is in influx_data
	 * now send it to the influxdb using curl
	 */

	job = malloc(sizeof(struct ThreadWrite));
	snprintf(job->action, 32, "Added Flow: %d", conn->cid);
	job->conn = flow->conn;
	job->data = &influx_data[0];
	thpool_add_work(curlpool, (void*)threaded_influx_write, (void*)job);
	/* NB: job and influx data are free'd in threaded_influx_write */
	free(tag_str);
Cleanup:
	if (err != NULL) {
		log_error("%s:\t%s\t%s tuple to ascii conversion error in add_flow_influx", 
			  flowid_char, estats_error_get_extra(err), 
			  estats_error_get_message(err));
		estats_error_free(&err);
	}
}

void add_time(threadpool curlpool, struct ConnectionHash *flow, struct estats_nl_client *cl, int cid, char *time_marker) {

	int MAX_LINE_SZ_TIME = 4096;
	struct ThreadWrite *job;
	uint64_t timestamp = 0;
	char flowid_char[40];
	char influx_data[MAX_LINE_SZ_TIME];
	int length;

	uuid_unparse(flow->flowid, flowid_char);

	/* get the curl handle. Do this now so we don't waste time if the handle is null*/
        //	curl_handle = hash_find_curl_handle(flow->group);
	if (flow->conn == NULL) {
		log_error("Can't add time stamp. There is no existing curl connection to the data base for group %s\n", flow->group);
		goto End;
	}

	/* if cl is null then it's an EndTime so we don't need to do this
	 * if it exists then we need to extract the timestamp from the 
	 * kis for this particular flow
	 */
	if (cl != NULL) {
		int i;
		struct estats_mask time_mask;	
		struct estats_val_data* esdata = NULL;
		struct estats_error * err = NULL;

		time_mask.masks[0] = 1UL << 12;/*perf*/
		time_mask.masks[1] = 0;        /*path*/
		time_mask.masks[2] = 0;        /*stack*/
		time_mask.masks[3] = 0;        /*app*/ 
		time_mask.masks[4] = 0;        /*tune*/ 
		time_mask.masks[5] = 0;        /*extras*/ 
		
		for (i = 0; i < MAX_TABLE; i++) {
			time_mask.if_mask[i] = 1;
		}
		Chk(estats_nl_client_set_mask(cl, &time_mask));
		Chk(estats_val_data_new(&esdata));
		Chk(estats_read_vars(esdata, cid, cl));
		for (i = 0; i < esdata->length; i++) {
			if (esdata->val[i].masked)
				continue;		
			timestamp = esdata->val[i].uv64;
		}
	Cleanup:
		estats_val_data_free(&esdata);
		if (err != NULL) {
			log_error("%s:\t%s\t%s", flowid_char, 
				  estats_error_get_extra(err), 
				  estats_error_get_message(err));
			estats_error_free(&err);
		}		
	} else {
		/* StartTimeStamp is in microseconds since epoch so we have to convert
		 * time() to msecs for the EndTime
		 */
		timestamp = time(NULL) * 1000000;
	}
	
	/*create the tag string*/
	length = strlen(",type=flowdata,group=,domain=,dtn=,flow= value=") 
		+ strlen(time_marker) + strlen(flow->group) + strlen(flow->domain_name)
		+ strlen(options.dtn_id) + strlen(flowid_char) + 18;

//	length = snprintf(NULL, 0, "%s,type=flowdata,group=%s,domain=%s,dtn=%s,flow=%s value=%"PRIu64"\n", 
//			  time_marker, flow->group, flow->domain_name, 
//			  options.dtn_id, flowid_char, timestamp);
	length++;
//	influx_data = malloc(length + 1);
	if (length < MAX_LINE_SZ_TIME) {
		snprintf(influx_data, length, "%s,type=flowdata,group=%s,domain=%s,dtn=%s,flow=%s value=%"PRIu64"\n", 
			 time_marker, flow->group, flow->domain_name, 
			 options.dtn_id, flowid_char, timestamp);
		influx_data[length - 1] = '\0';
		job = malloc(sizeof(struct ThreadWrite));
		snprintf(job->action, 32, "Added Time: %d", flow->cid);
		job->conn = flow->conn;
		job->data = &influx_data[0];
		thpool_add_work(curlpool, (void*)threaded_influx_write, (void*)job);
		/* NB: job and influx data are free'd in threaded_influx_write */
	}
End:; /*this is in case the curl handle doesn't exist*/
}

void read_metrics (threadpool curlpool, struct ConnectionHash *flow, struct estats_nl_client *cl) {
	struct estats_error* err = NULL;
	struct estats_mask full_mask;
	struct estats_val_data* esdata = NULL;
	struct ThreadWrite *job;
	char flowid_char[40];
	char *tag_str;
	char estats_val[128];
	int total_size = 0;
	int i, length;
	uint64_t timestamp = 0;
	int MAX_LINE_SIZE = 24576; /* largest I've seen is < 16k */
	char influx_data[MAX_LINE_SIZE];

	full_mask.masks[0] = DEFAULT_PERF_MASK;
        full_mask.masks[1] = DEFAULT_PATH_MASK;
        full_mask.masks[2] = DEFAULT_STACK_MASK;
        full_mask.masks[3] = DEFAULT_APP_MASK;
        full_mask.masks[4] = DEFAULT_TUNE_MASK;
        full_mask.masks[5] = DEFAULT_EXTRAS_MASK;

	/* we will be swapping masks so if_mask has to be set to 1 */
        for (i = 0; i < MAX_TABLE; i++) {
                full_mask.if_mask[i] = 1;
        }

	/* process the uuid */
	uuid_unparse(flow->flowid, flowid_char);

	/* check the curl handle. Do this now so we don't waste time if the handle is null*/
	if (flow->conn == NULL) {
		log_error("Can't add metrics. There is no existing curl connection to the data base for group %s\n", flow->group);
		goto End;
	}

	/* grab the data using the passed client and cid*/
	Chk(estats_nl_client_set_mask(cl, &full_mask));
	Chk(estats_val_data_new(&esdata));
	Chk(estats_read_vars(esdata, flow->cid, cl));	
	/* between flow and and esdata we have all of the information we need */

	/*create the tag string*/
	length = strlen(",type=metrics,group=,domain=,dtn=,flow=") + strlen(flow->group)
		+ strlen(flow->domain_name) + strlen(options.dtn_id) + strlen(flowid_char);
	length++;
	tag_str = malloc(length * sizeof(char));
	snprintf(tag_str, length, ",type=metrics,group=%s,domain=%s,dtn=%s,flow=%s", 
		 flow->group, flow->domain_name, options.dtn_id, flowid_char);
	tag_str[length - 1] = '\0';

	/* init the final command string for influx*/
	//influx_data = malloc(1);
	//*influx_data = '\0';
	//memset(influx_data, '\0', MAX_LINE_SIZE);

	/* we're using the current polling period. 
	 * This gives us 1 second resolution which isn't awesome but it allows
	 * us to lock all of the metric reads to the same timestamp which helps
	 * when we are retreiving the data
	 */
	
	timestamp = flow->lastpoll * 1000000; /*influx expects the timestamp to be in microseconds*/
	
	for (i = 0; i < esdata->length; i++) {
		char *temp_str;
		int size;
	       	switch(estats_var_array[i].valtype) {
		case ESTATS_UNSIGNED32:
			sprintf(estats_val, " value=%"PRIu32" ", esdata->val[i].uv32);
			break;
		case ESTATS_SIGNED32:
			sprintf(estats_val, " value=%"PRId32" ", esdata->val[i].sv32);
			break;
		case ESTATS_UNSIGNED64:
			sprintf(estats_val, " value=%"PRIu64" ", esdata->val[i].uv64);
			break;
		case ESTATS_UNSIGNED8:
			sprintf(estats_val, " value=%"PRIu8" ", esdata->val[i].uv8);
			break;
		case ESTATS_UNSIGNED16:
			sprintf(estats_val, " value=%"PRIu16" ", esdata->val[i].uv16);
			break;
		default:
			break;
		} //end switch
		
		
		/* get the size of the new line */
		/* 18 is the length of the timestamp +1 for null and +1 for the eol*/
		size = strlen(estats_var_array[i].name) + strlen(tag_str) + strlen(estats_val) + 18; 

		/* keep a running total of the sizes */
		total_size += size;

		/* build a temporary string for the data line */
		temp_str = malloc(size);
		snprintf(temp_str, size, "%s%s%s%"PRIu64"\n", estats_var_array[i].name, tag_str, estats_val, timestamp);
		temp_str[size - 1] = '\0';

		/* add it to what we will be sending influx*/
		if (total_size < MAX_LINE_SIZE) { 
			/* what we are writing fits in the buffer */
			strncat(influx_data, temp_str, size);
			influx_data[total_size - 1] = '\0';
		}
		free(temp_str);
	}

	job = malloc(sizeof(struct ThreadWrite));
	snprintf(job->action, 32, "Added Metrics: %d", flow->cid);
	job->conn = flow->conn;
	job->data = &influx_data[0];
	thpool_add_work(curlpool, (void*)threaded_influx_write, (void*)job);
	/* NB: job is free'd in threaded_influx_write */
	free(tag_str); 
Cleanup:
	estats_val_data_free(&esdata);
	if (err != NULL) {
		log_error("%s:\t%s\t%s", flowid_char, 
			  estats_error_get_extra(err), 
			  estats_error_get_message(err));
		estats_error_free(&err);
	}
End: ; /*in case there is no curl handle*/
}

/* this is the function we use to add jobs to the thread pool */
/* we copy the outbound data locally so we can free it in the */
/* context of the caller */
void threaded_influx_write (struct ThreadWrite *job) {
	CURLcode curl_res;
	if ((curl_res = influxWrite(job->conn, job->data) != CURLE_OK)) {
		log_error("CURL failure: %s for %s", curl_easy_strerror(curl_res), job->action);
	} else {
	 	log_debug("%s", job->action);
	}
	log_debug2("%s", job->data);
	//free(job->data);
	free(job);
}
