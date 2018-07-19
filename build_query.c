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
#include <openssl/sha.h>
#include <pthread.h>
#include "xsight.h"
#include "safe_malloc.h"

extern struct Options options;
extern struct NetworksHash *networks;
extern pthread_mutex_t lock;

void threaded_path_trace(struct PathBuild *);
void threaded_influx_write (struct ThreadWrite *);

/* we need to have a flow identifier that would be unique across
 * all flows from all hosts at all times. By hashing
 * srcip, destip, sport, dport, and the start time of the flow
 * reported as StartTime by web10g, we should be able to create 
 * a unique and replicable hash for these combinations. Why not just
 * use a UUID? If the listener restarts than any flows that continue
 * during the restart process will be given entirely new UUIDs and 
 * look like new flows. This methods avoids that problem. 
 * note: We still need to deal with flows that end *during* the time
 * that the listener is restarting
 */

void generate_flow_id (struct ConnectionHash *flow,
		       struct estats_connection_tuple_ascii asc,
		       char *flowid) {
	struct estats_nl_client* cl = { 0 };
	uint64_t timestamp = 0;
	struct estats_error* err = NULL;
	char tempstr[128] = "\0"; /*should handle 2 ipv6, ts, and port information*/
	char timechar[19];
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	
	/* instantiate a new client. */
	/* may want to change this to use the original client later but 
	 * for now this should work */
	Chk(estats_nl_client_init(&cl));

	timestamp = get_start_time(flow, cl, flow->cid);
	snprintf(timechar, 19, "%"PRIu64"", timestamp);
	
	strcat(tempstr, asc.local_addr);
	strcat(tempstr, asc.rem_addr);
	strcat(tempstr, asc.local_port);
	strcat(tempstr, asc.rem_port);
	strcat(tempstr, timechar);

	SHA256_Init(&sha256);
	SHA256_Update(&sha256, tempstr, strlen(tempstr));
	SHA256_Final(hash, &sha256);
	int i = 0;
	for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
	{
		sprintf(flowid + (i * 2), "%02x", hash[i]);
	}
	strcat(flowid, "\0");
	
Cleanup:
        if (err != NULL) {
                estats_error_free(&err);
        }
	estats_nl_client_destroy(&cl);
}



/* this is just used to create the job struct 
 *  and call the threaded function 
 */
void add_path_trace (threadpool curlpool,
		     threadpool tracepool, 
		     ConnectionHash *flow,
		     struct estats_connection_info *conn) {
	struct estats_error* err = NULL;
	struct estats_connection_tuple_ascii asc;
	struct PathBuild *job;
	
	/* get the ascii tuple information for the connection we care about */
	Chk(estats_connection_tuple_as_strings(&asc, &conn->tuple)); 
	
	/* all the data in the flow struct has to be copied over to the 
	 * job struct. The flow might be freed while the path is being traced
	 * which leads to some badness (null pointers etc).
	 */
	job = SAFEMALLOC(sizeof (struct PathBuild));
	job->local_addr = strndup(asc.local_addr, strlen(asc.local_addr));
	job->rem_addr = strndup(asc.rem_addr, strlen(asc.rem_addr));
	job->netname = strndup(flow->netname, strlen(flow->netname)); 
	job->domain_name = strndup(flow->domain_name, strlen(flow->domain_name));
	job->flowid_char = strndup(flow->flowid_char, SHA256_TEXT);
	job->cid = flow->cid;
	job->influx_conn = flow->conn;
	job->mythread = curlpool;
	
	/* add it to the thread pool */
	thpool_add_work(tracepool, (void*)threaded_path_trace, (void*)job);
	
Cleanup:
	if (err != NULL) {
		log_error("%s:\t%s\t%s tuple to ascii conversion error in add_flow_influx", 
			  flow->flowid_char, estats_error_get_extra(err), 
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
	char results[32][45]; /* hops are limited to 30 but start at 1 */
	char tag_str[512];
	char temp_str[512];
	char *influx_data;
	int MAX_LINE_SZ_PATH = 16384; /*max size of influx_data*/
	int ttl = 0;
	int i;
	int ret = -1;
	int size = 0;
	int total_size = 0;

	memset(results, '\0', 32*45); /*initialize the results array to null */

	/* determine if the *source* address is ipv4 or ipv6*/
	memset(&hint, '\0', sizeof (hint)); 
	hint.ai_family = AF_UNSPEC; 

	ret = getaddrinfo(job->local_addr, NULL, &hint, &local_address);
	if (ret < 0 ) {
		freeaddrinfo(local_address);
		log_error("Badly formed local address in path_trace: %s",
			  job->local_addr);
		goto Cleanup;
	}

	ret = getaddrinfo(job->rem_addr, NULL, &hint, &remote_address);
	if (ret < 0 ) {
		freeaddrinfo(remote_address);
		log_error("Badly formed remote address in path_trace: %s",
			  job->local_addr);
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

	/* init the final command string for influx*/
	/* this is freed in the threaded_influx_write function*/
	influx_data = SAFEMALLOC(MAX_LINE_SZ_PATH);
	*influx_data = '\0';

	/* iterate through each entry in the results array and craft an
	 * influx happy string */
	for (i = 1; i <= ttl; i++) {
		size = snprintf(temp_str, 512,
				"path,type=flowdata hop=%d value=\"%s\",flow=\"%s\"\n",
				i, results[i], job->flowid_char);
		temp_str[size] = '\0';
		total_size += size;

		if (total_size < MAX_LINE_SZ_PATH) {
			strncat(influx_data, temp_str, size);
			influx_data[total_size] = '\0';
		}
	}

	/* create the job struct for the curl write. This is freed in that function*/
	influxjob = SAFEMALLOC(sizeof(struct ThreadWrite));
	influxjob->action = SAFEMALLOC(32);
	snprintf(influxjob->action, 32, "Added Path: %d", job->cid);
	influxjob->network = hash_find_curl_handle(job->netname);
	influxjob->data = &influx_data[0];

	/* add this to the curl thread pool */
	thpool_add_work(job->mythread, (void*)threaded_influx_write, (void*)influxjob);

	//free(tag_str);
	free((void *)job->local_addr);
	free((void *)job->rem_addr);
	free((void *)job->netname);
	free((void *)job->domain_name);
	free((void *)job->flowid_char);
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
	char *influx_data;
	char temp_str[512];
	char tag_str[512];
	int size, total_size;
	int MAX_LINE_SZ_FLOW = 16384;
	size = total_size = 0;

	/* convert the tuples to a string */
	Chk(estats_connection_tuple_as_strings(&asc, &conn->tuple));

	/* init the final command string for influx*/
	influx_data = SAFEMALLOC(MAX_LINE_SZ_FLOW);
	*influx_data = '\0';

	/* create the flowid */
	generate_flow_id(flow, asc, (char *)flow->flowid_char);

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

	/* note, we'll set the start time when we make the initial instrument read */

        size = snprintf(tag_str, 512, ",type=flowdata value=");
        tag_str[size] = '\0';

	/* add the src_ip */
	size = snprintf(temp_str, 512, "src_ip%s\"%s\",flow=\"%s\"\n", tag_str,
			asc.local_addr, flow->flowid_char);
	temp_str[size] = '\0';
	total_size += size;
	if (total_size < MAX_LINE_SZ_FLOW)
		strncat(influx_data, temp_str, size);

	/* add the dest_ip */
	size = snprintf(temp_str, 512, "dest_ip%s\"%s\",flow=\"%s\"\n", tag_str,
			asc.rem_addr, flow->flowid_char);
	temp_str[size] = '\0';
	total_size += size;
	if (total_size < MAX_LINE_SZ_FLOW)
			strncat(influx_data, temp_str, size);

	/* add the src_port */
	size = snprintf(temp_str, 512, "src_port%s%si,flow=\"%s\"\n", tag_str,
			asc.local_port, flow->flowid_char);
	temp_str[size] = '\0';
	total_size += size;
	if (total_size < MAX_LINE_SZ_FLOW)
		strncat(influx_data, temp_str, size);

	/* add the dest_port */
	size = snprintf(temp_str, 512, "dest_port%s%si,flow=\"%s\"\n", tag_str,
			asc.rem_port, flow->flowid_char);
	temp_str[size] = '\0';
	total_size += size;
	if (total_size < MAX_LINE_SZ_FLOW)
		strncat(influx_data, temp_str, size);

	/* add the command */
	size = snprintf(temp_str, 512, "command%s\"%s\",flow=\"%s\"\n", tag_str,
			conn->cmdline, flow->flowid_char);
	temp_str[size] = '\0';
	total_size += size;
	if (total_size < MAX_LINE_SZ_FLOW)
		strncat(influx_data, temp_str, size);

	/* add the analyzed sereis */
	size = snprintf(temp_str, 512, "analyzed%s0i,flow=\"%s\"\n", tag_str,
		flow->flowid_char);
	temp_str[size] = '\0';
	total_size += size;
	if (total_size < MAX_LINE_SZ_FLOW)
		strncat(influx_data, temp_str, size);

	influx_data[total_size] = '\0';
        
	/* the flow meta data is in influx_data
	 * now send it to the influxdb using curl
	 */
	
	job = SAFEMALLOC(sizeof(struct ThreadWrite));
	job->action = SAFEMALLOC(32);
	snprintf(job->action, 32, "Added Flow: %d", conn->cid);
	job->network = hash_find_curl_handle(flow->netname);
	job->data = &influx_data[0];
	thpool_add_work(curlpool, (void*)threaded_influx_write, (void*)job);
	/* NB: job and influx data are free'd in threaded_influx_write */
Cleanup:
	if (err != NULL) {
		log_error("%s:\t%s\t%s tuple to ascii conversion error in add_flow_influx", 
			  flow->flowid_char, estats_error_get_extra(err), 
			  estats_error_get_message(err));
		estats_error_free(&err);
	}
}


/* this used to be embedded in add_start_time but we need it in multiple places now
 * we set the mask so that we only get the flow start time and return that. The 
 * the connection hash is passed only in case of an error for logging purposes
 * NB: All timestamsp in the DB are in ns 
 */
uint64_t get_start_time (struct ConnectionHash *flow, struct estats_nl_client *cl, int cid) {
	uint64_t timestamp = 0;
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
		timestamp = esdata->val[i].uv64 * 1000; /*convert to ns*/
	}
Cleanup:
	estats_val_data_free(&esdata);
	if (err != NULL) {
		log_error("%s:\t%s\t%s", flow->flowid_char, 
			  estats_error_get_extra(err), 
			  estats_error_get_message(err));
		estats_error_free(&err);
	}		
	return timestamp;
}

/* I know this looks like a kludge. And it is. However, it seems to be faster than 
 * other methods (strstr on the time_marker etc). 
 */

/* Add the start and end times of the flows to the database.
 * StartTime is taken direct from the web10g data and is accurate to the ms
 * EndTime is only accurate to the second as we only determine if a flow
 * has ended when we see that it has been closed. We coudl get increased
 * accuracy by reducing the sleep in the main loop (xsight.c) but I don't know
 * if that is necessary. Best option would be to extend web10g to capture that data
 */
void add_time(threadpool curlpool, struct ConnectionHash *flow, struct estats_nl_client *cl, int cid, char *time_marker) {
	struct ThreadWrite *job;
	uint64_t timestamp = 0;
	char *influx_data;
	int length;
	char suffix[512];

	/* for end time we need to override the influx timestamp. we use this variable
	 *  and we set everything to null so we don't get weird values. 
	 */
	char influxts[2];
	influxts[0] = '\0';
	influxts[1] = '\0';
	
	/* if cl is null then it's an EndTime so we don't need to do this
	 * if it exists then we need to extract the timestamp from the 
	 * kis for this particular flow
	 */
	if (cl != NULL) {
		timestamp = get_start_time(flow, cl, cid);
		/* we need to create an EndTime entry when the flow is created so we can search
		 * on it if necessary. We have to give it a 0 influx timestamp so it cvan be updated
		 * when the flow ends */
		length = snprintf (suffix, 512,
				   "EndTime,type=flowdata value=0i,flow=\"%s\" 0\n",
				   flow->flowid_char);
	} else {
		/* StartTimeStamp is in nanoseconds since epoch so we have to convert
		 * time() to nsecs for the EndTime
		 */
		timestamp = time(NULL) * 1000000000;
		/* in this case we are only writing the EndTime so the suffix is null but the 
		 * influx timestamp is 0 */
		influxts[0] = '0';
		suffix[0] = '\0';
	}
	
	/*create the time string*/
	length = strlen (",type=flowdata value=i,flow=\"\" \n") 
		+ strlen(time_marker)
		+ SHA256_TEXT
		+ strlen(suffix) + 22; 
	influx_data = SAFEMALLOC(length);
	snprintf(influx_data, length,
		 "%s,type=flowdata value=%"PRIu64"i,flow=\"%s\" %s\n%s", 
		 time_marker,
		 timestamp,
		 flow->flowid_char,
		 influxts,
		 suffix);
	influx_data[length - 1] = '\0';
	
	/* create the job struct and send it over to the thread pool*/
	job = SAFEMALLOC(sizeof(struct ThreadWrite));
	job->action = SAFEMALLOC(32);
	snprintf(job->action, 32, "Added %s: %d", time_marker, flow->cid);
	job->network = hash_find_curl_handle(flow->netname);
	job->data = &influx_data[0];
	thpool_add_work(curlpool, (void*)threaded_influx_write, (void*)job);
	/* NB: job and influx data are free'd in threaded_influx_write */
}

void read_metrics (threadpool curlpool,
		   struct ConnectionHash *flow,
		   struct estats_nl_client *cl) {
	struct estats_error* err = NULL;
	struct estats_mask full_mask;
	struct estats_val_data* esdata = NULL;
	struct ThreadWrite *job;
	char *influx_data;
	char tag_str[512];
	char update_str[512];
	char estats_val[128];
	int total_size = 0;
	int i, size;
	uint64_t timestamp = 0;
	/* maximum observed size has been under 16k but lets be extra safe */
	int MAX_LINE_SZ_METRIC = 24576;

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

	/* grab the data using the passed client and cid*/
	Chk(estats_nl_client_set_mask(cl, &full_mask));
	Chk(estats_val_data_new(&esdata));
	Chk(estats_read_vars(esdata, flow->cid, cl));	
	/* between flow and and esdata we have all of the information we need */

	/*create the tag string*/
	size = snprintf(tag_str, 512, ",type=metrics "); 
	tag_str[size] = '\0';
	
	/* init the final command string for influx*/
	influx_data = SAFEMALLOC(MAX_LINE_SZ_METRIC);
	*influx_data = '\0';

	/* we're using the current polling period. 
	 * This gives us 1 second resolution which isn't awesome but it allows
	 * us to lock all of the metric reads to the same timestamp which helps
	 * when we are retreiving the data
	 */
	
	timestamp = flow->lastpoll * 1000000000; /*influx expects the timestamp to be in nanoseconds*/
	
	for (i = 0; i < esdata->length; i++) {
		char temp_str[512];
	       	switch(estats_var_array[i].valtype) {
		case ESTATS_UNSIGNED32:
			sprintf(estats_val, " value=%"PRIu32"i", esdata->val[i].uv32);
			break;
		case ESTATS_SIGNED32:
			sprintf(estats_val, " value=%"PRId32"i", esdata->val[i].sv32);
			break;
		case ESTATS_UNSIGNED64:
			sprintf(estats_val, " value=%"PRIu64"i", esdata->val[i].uv64);
			break;
		case ESTATS_UNSIGNED8:
			sprintf(estats_val, " value=%"PRIu8"i", esdata->val[i].uv8);
			break;
		case ESTATS_UNSIGNED16:
			sprintf(estats_val, " value=%"PRIu16"i", esdata->val[i].uv16);
			break;
		default:
			break;
		} /*end switch*/
		
		size = snprintf(temp_str, 512, "%s%s%s,flow=\"%s\" %"PRIu64"\n",
				estats_var_array[i].name,
				tag_str,
				estats_val,
				flow->flowid_char,
				timestamp);
		temp_str[size] = '\0';

		total_size += size;
		
		/* add it to what we will be sending influx*/
		if (total_size < MAX_LINE_SZ_METRIC)
			strncat(influx_data, temp_str, size);

		influx_data[total_size] = '\0';
	}


	/* Add a line for the update field in the flowdata 
	 * influx doesn't have a method to update an existing datapoint 
	 * except for overwriting it. To do this you need the timestamp. 
	 * however, we don't make any reads against the database so we set the timestamp
	 * for every datapoint in the update series to the same value of 0
	 */

	size = snprintf(update_str, 512,
			"updated,type=flowdata value=%"PRIu64"i,flow=\"%s\" 0", 
			timestamp,
			flow->flowid_char);
	update_str[size] = '\0';
	total_size += size;
	
	if (total_size < MAX_LINE_SZ_METRIC)
		strncat(influx_data, update_str, size);

	influx_data[total_size] = '\0';

	job = SAFEMALLOC(sizeof(struct ThreadWrite));
	job->action = SAFEMALLOC(32);
	snprintf(job->action, 32, "Added Metrics: %d", flow->cid);
	job->network = hash_find_curl_handle(flow->netname);
	job->data = &influx_data[0];
	thpool_add_work(curlpool, (void*)threaded_influx_write, (void*)job);
	/* NB: job is free'd in threaded_influx_write */

Cleanup:
	estats_val_data_free(&esdata);
	if (err != NULL) {
		log_error("%s:\t%s\t%s", flow->flowid_char, 
			  estats_error_get_extra(err), 
			  estats_error_get_message(err));
		estats_error_free(&err);
	}
}

/* this is the function we use to add jobs to the thread pool */
/* we copy the outbound data locally so we can free it in the */
/* context of the caller */
void threaded_influx_write (struct ThreadWrite *job) {
	CURLcode curl_res;
	influxConn *mycurl = NULL;
	int i;
	
       /* lock this thread while we are looking for a handle from the pool */
       pthread_mutex_lock(&lock);
       for (i = 0; i < NUM_THREADS; i++) {
               if (job->network->conn[i]->status == 1) {
                       log_debug("Using curl handle %d from %s", i, job->network->netname);
                       mycurl = job->network->conn[i];
                       mycurl->status = 0;
                       break;
               }
       }
       pthread_mutex_unlock(&lock);
       
       if (mycurl == NULL) {
               log_error("Could not get valid curl handle for database write in threaded_influx_write");
               goto Error;
       }

	
	if ((curl_res = influxWrite(mycurl, job->data) != CURLE_OK)) {
		log_error("CURL failure: %s for %s",
			  curl_easy_strerror(curl_res),
			  job->action);
		/* there are times when the curl pool just fails
		 * so we take the hit and create a unique curl connection
		 * and try to resend the data. This should happen rarely.
		 */
		influxConn *failcurl = NULL;
		failcurl = create_conn ((char *)job->network->influx_host_url,  
					(char *)job->network->influx_database,
					(char *)job->network->influx_user,  
					(char *)job->network->influx_password, 
					job->network->verify_ssl); 
		if ((curl_res = influxWrite(failcurl, job->data) != CURLE_OK)) {
			log_error("CURL failure recovery failed: %s for %s",
				  curl_easy_strerror(curl_res),
				  job->action);
			free_conn(failcurl);
			goto Error;
		} else {
			log_debug("CURL failure recovery successful: %s\n", job->action);
			free_conn(failcurl);
		}
	} else {
	 	log_debug("%s", job->action);
	}
	
	/* we shouldn't need to lock the thread here */
	mycurl->status = 1;
        log_debug2("%s", job->data);
	
Error:
	free(job->action);
	free(job->data);
	free(job);
}
