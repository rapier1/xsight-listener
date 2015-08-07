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
#include <stdlib.h>
#include <string.h>
#include "build_query.h"
#include "thpool.h"

extern struct Options options;
extern struct NetworksHash *networks;

void threaded_path_trace(struct PathBuild *);

void add_path_trace (threadpool tracepool, ConnectionHash *flow, struct estats_connection_info *conn) {
	struct PathBuild *job;

	job = malloc(sizeof (struct PathBuild));
	job->conn = conn;
	job->flow = flow;

	thpool_add_work(tracepool, (void*)threaded_path_trace, (void*)job);

}

void threaded_path_trace (struct PathBuild *job) {
	struct addrinfo *address = 0;
	struct addrinfo hint;
	struct estats_error* err = NULL;
	struct estats_connection_tuple_ascii asc;
	struct ThreadWrite *influxjob;
	influxConn *curl_conn;
	influxConn *myconn;
	CURLcode curl_res;
	char results[30][45];
	char flowid_char[40];
	char *tag_str;
	char *temp_str;
	char *influx_data;
	int ttl = 0;
	int i;
	int ret = -1;
	int size;
	int total_size;

	/* get the curl handle. Do this now so we don't waste time if the handle is null*/
	curl_conn = hash_find_curl_handle(job->flow->group);
	if (curl_conn == NULL) {
		log_error("Can't add flow data. There is no existing curl connection to the data base for group %s\n", 
			  job->flow->group);
		goto Cleanup;
	}


	Chk(estats_connection_tuple_as_strings(&asc, &(job->conn)->tuple));

	memset(&hint, '\0', sizeof (hint)); 
	hint.ai_family = AF_UNSPEC; 

	ret = getaddrinfo(asc.local_addr, NULL, &hint, &address);
	if (ret < 0 ) {
		perror ("getaddrinfo");
		goto Cleanup;
	}

	if (address->ai_family == AF_INET) {
		ttl = trace4(asc.rem_addr, asc.local_addr, results);
	} else {
		ttl = trace6(asc.rem_addr, asc.local_addr, results);
	}
	
	if (ttl < 1)
		goto Cleanup;

	/*create the tag string*/

	uuid_unparse(job->flow->flowid, flowid_char);

	size = snprintf(NULL, 0, ",type=flowdata,group=%s,domain=%s,dtn=%s,flow=%s", 
			  job->flow->group, job->flow->domain_name, options.dtn_id, flowid_char);
	size++;
	tag_str = malloc(size * sizeof(char) + 1);
	snprintf(tag_str, size, ",type=flowdata,group=%s,domain=%s,dtn=%s,flow=%s value=", 
		 job->flow->group, job->flow->domain_name, options.dtn_id, flowid_char);	

	/* init the final command string for influx*/
	influx_data = malloc(4);
	*influx_data = '\0';

	for (i = 1; i <= ttl; i++) {
		/* add the src_ip */
		size = snprintf(NULL, 0, "path%s,hop=%d value=\"%s\"\n", tag_str, i, results[i]) + 1;
		total_size += size;
		temp_str = malloc(size);
		snprintf(temp_str, size, "path%s,hop=%d value=\"%s\"\n", tag_str, i, results[i]);
		influx_data = realloc(influx_data, total_size);
		strncat(influx_data, temp_str, size);
		free(temp_str);
	}
	
	printf("%s", influx_data);

	influxjob = malloc(sizeof(struct ThreadWrite));
	snprintf(influxjob->action, 32, "Added Path: %d", job->flow->cid);
	influxjob->conn = job->flow->conn;
	influxjob->data = &influx_data[0];
	threaded_influx_write(influxjob);

/* //	myconn = create_conn (curl_conn->host_url, curl_conn->db, curl_conn->user, curl_conn->pass); */

/* 	if ((curl_res = influxWrite(myconn, influx_data) != CURLE_OK)) { */
/* 		log_error("CURL failure: %s", curl_easy_strerror(curl_res)); */
/* 	} else { */
/* 		printf ("ADDED!\n"); */
/* 	} */
/* 	log_debug2("%s", influx_data); */
/* //	curl_easy_reset(myconn);  */

	freeaddrinfo(address);
	free(tag_str);
 	free(job); 
 	free(influx_data); 
Cleanup: ;
	
}

/* get the identifying information and add it to the influx flow namespace*/
/* the unique sequence_number */
void add_flow_influx(threadpool thpool, ConnectionHash *flow, struct estats_connection_info *conn) {
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
	if (!hash_get_tags(&asc, flow))
		goto Cleanup;
	
	/* the above should return a pointer if it doesn't the
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

	
	/* add the src_ip */
	size = snprintf(NULL, 0, "src_ip%s\"%s\"\n", tag_str, asc.local_addr) + 1;
	total_size += size;
	temp_str = malloc(size);
	snprintf(temp_str, size, "src_ip%s\"%s\"\n", tag_str, asc.local_addr);
	influx_data = realloc(influx_data, total_size);
	strncat(influx_data, temp_str, size);
	free(temp_str);

	/* add the dest_ip */
	size = snprintf(NULL, 0, "dest_ip%s\"%s\"\n", tag_str, asc.rem_addr) + 1;
	total_size += size;
	temp_str = malloc(size + 1);
	snprintf(temp_str, size, "dest_ip%s\"%s\"\n", tag_str, asc.rem_addr);
	influx_data = realloc(influx_data, total_size + 1);
	strncat(influx_data, temp_str, size);
	free(temp_str);


	/* add the src_port */
	size = snprintf(NULL, 0, "src_port%s%s\n", tag_str, asc.local_port) + 1;
	total_size += size;
	temp_str = malloc(size + 1);
	snprintf(temp_str, size, "src_port%s%s\n", tag_str, asc.local_port);
	influx_data = realloc(influx_data, total_size + 1);
	strncat(influx_data, temp_str, size);
	free(temp_str);

	/* add the dest_port */
	size = snprintf(NULL, 0, "dest_port%s%s\n", tag_str, asc.rem_port) + 1;
	total_size += size;
	temp_str = malloc(size + 1);
	snprintf(temp_str, size, "dest_port%s%s\n", tag_str, asc.rem_port);
	influx_data = realloc(influx_data, total_size + 1);
	strncat(influx_data, temp_str, size);
	free(temp_str);


	/* add the command */
	size = snprintf(NULL, 0, "command%s\"%s\"\n", tag_str, conn->cmdline) + 1;
	total_size += size;
	temp_str = malloc(size + 1);
	snprintf(temp_str, size, "command%s\"%s\"\n", tag_str, conn->cmdline);
	influx_data = realloc(influx_data, total_size + 1);
	strncat(influx_data, temp_str, size);
	free(temp_str);

	/* note, we'll set the start time when we make the initial instrument read */
        
	/* the flow meta data is in influx_data
	 * now send it to the influxdb using curl
	 */

	job = malloc(sizeof(struct ThreadWrite));
	snprintf(job->action, 32, "Added Flow: %d", conn->cid);
	job->conn = flow->conn;
	job->data = &influx_data[0];
	thpool_add_work(thpool, (void*)threaded_influx_write, (void*)job);
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

void add_time(threadpool thpool, struct ConnectionHash *flow, struct estats_nl_client *cl, int cid, char *time_marker) {

	struct ThreadWrite *job;
	uint64_t timestamp = 0;
	char flowid_char[40];
	char *influx_data;
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
	length = snprintf(NULL, 0, "%s,type=flowdata,group=%s,domain=%s,dtn=%s,flow=%s value=%"PRIu64"\n", 
			  time_marker, flow->group, flow->domain_name, 
			  options.dtn_id, flowid_char, timestamp);
	length++;
	influx_data = malloc(length + 1);
	snprintf(influx_data, length, "%s,type=flowdata,group=%s,domain=%s,dtn=%s,flow=%s value=%"PRIu64"\n", 
			  time_marker, flow->group, flow->domain_name, 
			  options.dtn_id, flowid_char, timestamp);
	
	job = malloc(sizeof(struct ThreadWrite));
	snprintf(job->action, 32, "Added Time: %d", flow->cid);
	job->conn = flow->conn;
	job->data = &influx_data[0];
	thpool_add_work(thpool, (void*)threaded_influx_write, (void*)job);
	/* NB: job and influx data are free'd in threaded_influx_write */
End:; /*this is in case the curl handle doesn't exist*/
}

void read_metrics (threadpool thpool, struct ConnectionHash *flow, struct estats_nl_client *cl) {
	struct estats_error* err = NULL;
	struct estats_mask full_mask;
	struct estats_val_data* esdata = NULL;
	struct ThreadWrite *job;
	char flowid_char[40];
	char *tag_str;
	char *influx_data;
	char estats_val[128];
	int total_size = 0;
	int i, length;
	uint64_t timestamp = 0;

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
	/* between flow and and esdata we have all of the infomration we need */

	/*create the tag string*/
	length = snprintf(NULL, 0, ",type=metrics,group=%s,domain=%s,dtn=%s,flow=%s", 
			  flow->group, flow->domain_name, options.dtn_id, flowid_char);
	length++;
	tag_str = malloc(length * sizeof(char));
	snprintf(tag_str, length, ",type=metrics,group=%s,domain=%s,dtn=%s,flow=%s", 
		 flow->group, flow->domain_name, options.dtn_id, flowid_char);

	/* init the final command string for influx*/
	influx_data = malloc(1);
	*influx_data = '\0';

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
		
		
		/* we're using the current polling period. 
		 * This gives us 1 second resolution which isn't awesome but it allows
		 * us to lock all of the metric reads to the same timestamp which helps
		 * when we are retreiving the data
		 */

		timestamp = flow->lastpoll * 1000000; /*influx expects the timestamp to be in microseconds*/
		/* get the size of the new line */
		size = snprintf(NULL, 0, "%s%s%s%"PRIu64"\n", estats_var_array[i].name, tag_str, estats_val, timestamp) + 1;

		/* keep a running total of the sizes */
		total_size += size;

		/* build a temporary string for the data line */
		temp_str = malloc(size);
		snprintf(temp_str, size, "%s%s%s%"PRIu64"\n", estats_var_array[i].name, tag_str, estats_val, timestamp);

		/* add it to what we will be sending influx*/
		influx_data = realloc(influx_data, total_size);
		strcat(influx_data, temp_str);
		free(temp_str);
	}

	job = malloc(sizeof(struct ThreadWrite));
	snprintf(job->action, 32, "Added Metrics: %d", flow->cid);
	job->conn = flow->conn;
	job->data = &influx_data[0];
	thpool_add_work(thpool, (void*)threaded_influx_write, (void*)job);
	/* NB: job and influx data are free'd in threaded_influx_write */
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
		log_error("CURL failure: %s", curl_easy_strerror(curl_res));
	} else {
	 	log_debug("%s", job->action);
	}
	log_debug2("%s", job->data);
	curl_easy_reset(job->conn->curl);
	free(job->data);
	free(job);
}
