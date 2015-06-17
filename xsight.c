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
#include "xsight.h"
#include "time.h"
#include "libinflux.h"

#define INTERVAL 500

int debugflag = 0;
int printjson = 0;

struct Options options;

struct ConnectionHash *activeflows = NULL;

struct ConnectionHash *find_cid(int cid) {
        struct ConnectionHash *s;
	HASH_FIND_INT( activeflows, &cid, s );  
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
	return flow;
}

/* 
 * we need a function to replace a placeholder points array
 * with real values. After the real values are in place convert the 
 * object to a string and concatonate to the end of the influxdb string
 */
void replace_array_in_json_object (json_object *my_object, char *keyname, 
				     char *value, char *flowid, char **influx_cmd) {
	char *json_str;
	int size;

	/* step through the object and looks for the array labled points*/
        json_object_object_foreach(my_object, key, val) {
		if (strcmp(key, "points") == 0) {
			/* we found it so build a replacement object for it */
			json_object *points_array = json_object_new_array();
			json_object *new_array = json_object_new_array();
			json_object *new_key = json_object_new_string(keyname);
			json_object *new_value = json_object_new_string(value);
			json_object *new_flowid = json_object_new_string(flowid);
			json_object_array_add(new_array, new_key);
			json_object_array_add(new_array, new_value);
			json_object_array_add(new_array, new_flowid);
			json_object_array_add(points_array, new_array);
			json_object_object_add(my_object, key, points_array);
		}
		
        }
	json_str = strdup((char *)json_object_to_json_string_ext(my_object, JSON_C_TO_STRING_PLAIN));

	size = strlen(*influx_cmd) + strlen(json_str); 
	/* resize the command line to take the new json string*/
	*influx_cmd = realloc(*influx_cmd,  sizeof(char *) * (size + 2));
	strncat(*influx_cmd, json_str, strlen(json_str));
	free(json_str);
}

/* get the identifying information and add it to the influx flow namespace*/
/* the unique sequence_number */
void add_flow_influx(uuid_t flowid, struct estats_connection_info *conn) {
	struct estats_error* err = NULL;
	struct estats_connection_tuple_ascii asc;
	char flowid_char[40];
	char *influx_data;
	CURLcode curl_res;

	/* init the final command string for influx*/
	influx_data = malloc(2 * sizeof(char));
	*influx_data = '\0';
	/* influx expect everything to be an array so we need enclosing brackets */
	strncat(influx_data, "[", 1);

	/* create the flowid */
	uuid_generate(flowid);
	uuid_unparse(flowid, flowid_char);

	/* main constructs for object */
	json_object *jsonout = json_object_new_object();
        json_object *points = json_object_new_array();
        json_object *columns = json_object_new_array();

        /* add name */
        json_object *jo_name = json_object_new_string("FlowTable");
        json_object_object_add(jsonout, "name", jo_name);

        /* build columns array */
        json_object *clm_key = json_object_new_string("key");
        json_object *clm_value = json_object_new_string("value");
        json_object *clm_flowid = json_object_new_string("flowid");
        
        json_object_array_add(columns, clm_key);
        json_object_array_add(columns, clm_value);
        json_object_array_add(columns, clm_flowid);

        /* add columns array */
        json_object_object_add(jsonout, "columns", columns);

	/* add points array */
	/* this is justa place holder */
        json_object_object_add(jsonout, "points", points);
	 
	/* convert the tuples to a string */
	Chk(estats_connection_tuple_as_strings(&asc, &conn->tuple));

	/* now we replace the empty points array with real values 
	 * this keeps us from having to rebuild the whole of the json object each time
	 */
	
	replace_array_in_json_object(jsonout, "src_ip", asc.local_addr, flowid_char, &influx_data);
	strncat(influx_data, ",", 1); /* add commas to separate the json objects*/

	replace_array_in_json_object(jsonout, "dst_ip", asc.rem_addr, flowid_char, &influx_data);
	strncat(influx_data, ",", 1);

	replace_array_in_json_object(jsonout, "src_port", asc.local_port, flowid_char, &influx_data);
	strncat(influx_data, ",", 1);

	replace_array_in_json_object(jsonout, "dest_port", asc.rem_port, flowid_char, &influx_data);
	strncat(influx_data, ",", 1);

	replace_array_in_json_object(jsonout, "command", conn->cmdline, flowid_char, &influx_data);
	strncat(influx_data, "]", 1); /*close the bracket*/

	/*free the json object*/
	json_object_put(jsonout);

	/* note, we'll set the start time when we make the initial instrument read */
        
	/* the flow meta data is in json_out
	 * now send it to the influxdb using curl
	 */

	log_debug("%s\n", influx_data);
	if ((curl_res = influxWrite(influx_data) != CURLE_OK)) {
		log_error("CURL failure: %s\n", curl_easy_strerror(curl_res));
	} else {
		log_debug("Success flow add\n");
	}
	free(influx_data);
Cleanup:
	if (err != NULL) {
		log_debug("%s:\t%s\t%s tuple to ascii conversion error in add_flow_influx\n", 
			  flowid_char, estats_error_get_extra(err), 
			  estats_error_get_message(err));
		estats_error_free(&err);
	}

}

/* currently we are just going to use the system time 
 * as the StartTime instrument isn't currently implemented. 
 * NB: Fix this once it is done!
 */
void add_time(uuid_t uuid, char *time_marker) {

	int localtime = time(NULL);
	size_t size;
	char systime[12];
	char flowid_char[40];
	char *influx_data;
	char *json_str;
	CURLcode curl_res;

	/* init the final command string for influx*/
	influx_data = malloc(sizeof(char) * 4);
	*influx_data='\0';
	strncat(influx_data, "[", 1);

	snprintf(systime, 12, "%d", localtime);
	
	uuid_unparse(uuid, flowid_char);

	/* main constructs for object */
	json_object *jsonout = json_object_new_object();
        json_object *points = json_object_new_array();
        json_object *columns = json_object_new_array();

        /* add name */
        json_object *jo_name = json_object_new_string("FlowTable");
        json_object_object_add(jsonout, "name", jo_name);

        /* build columns array */
        json_object *clm_key = json_object_new_string("key");
        json_object *clm_value = json_object_new_string("value");
        json_object *clm_flowid = json_object_new_string("flowid");
        
        json_object_array_add(columns, clm_key);
        json_object_array_add(columns, clm_value);
        json_object_array_add(columns, clm_flowid);

        /* add columns array */
        json_object_object_add(jsonout, "columns", columns);

        /* build points array */
        json_object *pnt_key = json_object_new_string(time_marker);
        json_object *pnt_value = json_object_new_string(systime);
        json_object *pnt_flowid = json_object_new_string(flowid_char);
	json_object *new_array = json_object_new_array();

	/* influx expects an array of arrays for the points*/
	json_object_array_add(new_array, pnt_key);
	json_object_array_add(new_array, pnt_value);
	json_object_array_add(new_array, pnt_flowid);
        json_object_array_add(points, new_array);

	/* add points array */
        json_object_object_add(jsonout, "points", points);	

	json_str = strdup((char *)json_object_to_json_string_ext(jsonout, JSON_C_TO_STRING_PLAIN));
	json_object_put(jsonout); /* free the json object */

	/* get the size of the resulting string so I can reallocate influx_data */
	size = strlen(influx_data) + strlen(json_str); 
	influx_data = realloc(influx_data, size + 3);

	/* copy the json string into the influx data string*/
	strncat(influx_data, json_str,strlen(json_str));

	/* close the bracket */
	strncat(influx_data, "]", 1);
	
	log_debug("%s\n", influx_data);
	if ((curl_res = influxWrite(influx_data) != CURLE_OK)) {
		log_error("CURL failure: %s\n", curl_easy_strerror(curl_res));
	} else {
		log_debug("Success time add\n");
	}
	free(json_str);
	free(influx_data);
}

int delete_flow (int cid) {
	struct ConnectionHash *current;
	HASH_FIND_INT(activeflows, &cid, current);
	if (current != NULL) {
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

void count_hash () {
	int i;
	i = 0;
	struct ConnectionHash *current, *temp;
	HASH_ITER(hh, activeflows, current, temp) {
		i++;
	}
	printf("Hash count: %d\n", i);
}

void read_metrics (struct ConnectionHash *flow, struct estats_nl_client *cl) {
	struct estats_error* err = NULL;
	struct estats_mask full_mask;
	struct estats_val_data* esdata = NULL;
	char flowid_char[40];
	char *json_str;
	char *name_str;
	char *influx_data;
	json_object *estats_val = NULL;
	json_object *estats_name = NULL;
	CURLcode curl_res;

	int i, length;

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

	/* grab the data using the passed client and cid*/
	Chk(estats_nl_client_set_mask(cl, &full_mask));
	Chk(estats_val_data_new(&esdata));
	Chk(estats_read_vars(esdata, flow->cid, cl));	
	/* between flow and and esdata we have all of the infomration we need */

	/*create the series name string*/
	length = snprintf(NULL, 0, "group_%s_dtn_%s_flow_%s", options.domain_name, options.dtn_id, flowid_char);
	length++;
	name_str = malloc(length * sizeof(char));
	snprintf(name_str, length, "group_%s_dtn_%s_flow_%s", options.domain_name, options.dtn_id, flowid_char);

	/* init the final command string for influx*/
	influx_data = malloc(4 * sizeof(char));
	*influx_data = '\0';
	/* influx expect everything to be an array so we need enclosing brackets */
	strncat(influx_data, "[", 1);

	/* NB: Originally I constructed a 'header' that corresponded to the
	 * name string and columns as they don't change. However, a deep copy of the
	 * structure seemed more work than necessary. Revisit this if necessary.
	 * Saving the header json_object as a string and then
	 * reparsing it into a new object wasn't saving any cycles.
	 */ 
	for (i = 0; i < esdata->length; i++) {
		json_object * columns = json_object_new_array(); 
		json_object * points = json_object_new_array();
		json_object * new_array = json_object_new_array();
		json_object * jsonout = json_object_new_object();
		int size;


		/* apply the name string to the json object*/
		estats_val = json_object_new_string(name_str);
		json_object_object_add(jsonout, "name", estats_val);

		/* create the columns portion */
		estats_name = json_object_new_string ("polltime");
		json_object_array_add(columns, estats_name);
		estats_name = json_object_new_string ("metric");
		json_object_array_add(columns, estats_name);
		estats_name = json_object_new_string ("value");
		json_object_array_add(columns, estats_name);
		json_object_object_add(jsonout, "columns", columns);
		
		/* create the timestamp for points*/
		estats_val = json_object_new_int64(flow->lastpoll);
		json_object_array_add(new_array, estats_val);

		switch(estats_var_array[i].valtype) {
		case ESTATS_UNSIGNED32:
			estats_val = json_object_new_int64(esdata->val[i].uv32);
			break;
		case ESTATS_SIGNED32:
			estats_val = json_object_new_int64(esdata->val[i].sv32);
			break;
		case ESTATS_UNSIGNED64:
			estats_val = json_object_new_int64(esdata->val[i].uv64);
			break;
		case ESTATS_UNSIGNED8:
			estats_val = json_object_new_int64(esdata->val[i].uv8);
			break;
		case ESTATS_UNSIGNED16:
			estats_val = json_object_new_int64(esdata->val[i].uv16);
			break;
		default:
			break;
		} //end switch
		estats_name = json_object_new_string(estats_var_array[i].name);
		json_object_array_add(new_array, estats_val);
		json_object_array_add(new_array, estats_name);
		json_object_array_add(points, new_array);
		json_object_object_add(jsonout, "points", points);
		json_str = strdup((char *)json_object_to_json_string_ext(jsonout, JSON_C_TO_STRING_PLAIN));

		/* get the size of the resulting string so I can reallocate influx_data */
		size = strlen(influx_data) + strlen(json_str); 
		influx_data = realloc(influx_data, sizeof(char *) * (size + 2));

		/* copy the json string into the influx data string*/
		strncat(influx_data, json_str,strlen(json_str));
		/* this add commas between the individual commands except for the last one */
		if (i < esdata->length-1) 
			strncat(influx_data, ",", 1);
		free(json_str);
		json_object_put(jsonout);
	}
	strncat(influx_data, "]", 1); /*close the bracket*/
	if ((curl_res = influxWrite(influx_data) != CURLE_OK)) {
		log_error("CURL failure: %s\n", curl_easy_strerror(curl_res));
	} else {
		log_debug("Success metric add\n");
	}
	log_debug("%s\n", influx_data);
	free(name_str);
	free(influx_data);
Cleanup:
	estats_val_data_free(&esdata);
	if (err != NULL) {
		log_debug("%s:\t%s\t%s\n", flowid_char, 
			  estats_error_get_extra(err), estats_error_get_message(err));
		estats_error_free(&err);
	}
}

/* read the configuration file */
int get_config(char *path) {
	int value, count, i;
	const char *string;
	const config_setting_t *array;
	config_t cfg;
	

	if (strlen(path) <= 1) {
		/*no path to config file! error out*/
		log_error("Config file not provided! Exiting.\n");
		return -1;
	}

	config_init(&cfg);
	
	/*read config file*/
	if (!config_read_file(&cfg, path)) {
		log_error("\n%s:%d - %s", config_error_file(&cfg), config_error_line(&cfg), config_error_text(&cfg));
		return -1;
	}

	/* set some basics for the option struct*/
	options.in_apps_count = 0;
	options.ex_apps_count = 0;
	options.in_ips_count = 0;
	options.ex_ips_count = 0;

	/* start goin through the cfg file */
	if (config_lookup_int(&cfg, "debug", &value)) {
		log_debug("Debug flag: %d\n", options.debugflag);
		debugflag = options.debugflag;
	}

	if (config_lookup_int(&cfg, "printjson", &value)) {
		log_debug("printjson: %d\n", options.printjson);
		printjson = options.printjson;
	}

	if (!config_lookup_string(&cfg, "domain", &string)) {
		log_error("Domain not specified in config file! Exiting.\n");
		return -1;
	}
	options.domain_name = strdup(string);
	log_debug("Domain: %s\n", options.domain_name);

	if (!config_lookup_string(&cfg, "dtn_id", &string)) {
		log_error("DTN ID not specified in config file! Exiting.\n");
		return -1;
	}
	options.dtn_id = strdup(string);
	log_debug("DTN: %s\n", options.dtn_id);

	if (!config_lookup_string(&cfg, "database", &string)) {
		log_error("Influx database not specified in config file! Exiting.\n");
		return -1;
	}
	options.influx_database = strdup(string);
	log_debug("Influx Database: %s\n", options.influx_database);

	if (!config_lookup_string(&cfg, "password", &string)) {
		log_error("Influx database password not specified in config file! Exiting.\n");
		return -1;
	}
	options.influx_password = strdup(string);
	log_debug("Influx Password: %s\n", options.influx_password);

	if (!config_lookup_string(&cfg, "host_url", &string)) {
		log_error("Influx host URL not specified in config file! Exiting.\n");
		return -1;
	}
	options.influx_host_url = strdup(string);
	log_debug("Influx Host URL: %s\n", options.influx_host_url);

	if (!config_lookup_int(&cfg, "conn_poll_interval", &value)) {
		log_error("Connection polling interval not specified in config file! Exiting.\n");
		return -1;
	}
	options.conn_interval = value;
	log_debug("Connection Poll Interval : %d(s)\n", options.conn_interval);

	if (!config_lookup_int(&cfg, "metric_poll_interval", &value)) {
		log_error("Metric polling interval not specified in config file! Exiting.\n");
		return -1;
	}
	options.metric_interval = value;
	log_debug("Metric Poll Interval : %d(s)\n", options.metric_interval);

	/* get any excluded ip addresses */
	array = config_lookup(&cfg, "exclude_ips");
	count = config_setting_length(array);
	if (count) {
		options.exclude_ips = malloc(sizeof(options.exclude_ips) * count);
		options.ex_ips_count = count;
	}
	for (i = 0; i < count; i++) {
		string = config_setting_get_string_elem(array, i);
		options.exclude_ips[i] = strdup(string);
		printf("ex ip is %s\n", options.exclude_ips[i]);
	}

	/* get any included ip addresses */
	array = config_lookup(&cfg, "include_ips");
	count = config_setting_length(array);
	if (count) {
		options.include_ips = malloc(sizeof(options.include_ips) * count);
		options.in_ips_count = count;
	}
	for (i = 0; i < count; i++) {
		string = config_setting_get_string_elem(array, i);
		options.include_ips[i] = strdup(string);
		printf("in ip is %s\n", options.include_ips[i]);
	}

	/* get any excluded apps */
	array = config_lookup(&cfg, "exclude_apps");
	count = config_setting_length(array);
	if (count) {
		options.exclude_apps = malloc(sizeof(options.exclude_apps) * count);
		options.ex_apps_count = count;
	}
	for (i = 0; i < count; i++) {
		string = config_setting_get_string_elem(array, i);
		options.exclude_apps[i] = strdup(string);
		printf("ex app is %s\n", options.exclude_apps[i]);
	}

	/* get any included apps */
	array = config_lookup(&cfg, "include_apps");
	count = config_setting_length(array);
	if (count) {
		options.include_apps = malloc(sizeof(options.include_apps) * count);
		options.in_apps_count = count;
	}
	for (i = 0; i < count; i++) {
		string = config_setting_get_string_elem(array, i);
		options.include_apps[i] = strdup(string);
		printf("in app is %s\n", options.include_apps[i]);
	}

	config_destroy(&cfg);
	return 1;
}

int filter_connection (struct estats_connection_info *conn) {
	struct estats_error *err = NULL;
	struct estats_connection_tuple_ascii asc;
	int exip, inip, exap, inap;

	exip = inip = exap = inap = 0;

	Chk(estats_connection_tuple_as_strings(&asc, &conn->tuple));	

	/* if we have ips to exclude check them */
	if (options.ex_ips_count != 0) {
		/* if we get a match it returns 0 so skip it */
		if (filter_ips(asc.local_addr, asc.rem_addr, 
			       options.exclude_ips, options.ex_ips_count) == 0)
			exip = 1;
	}

	/* if we have ips to include check them */
	if (options.in_ips_count != 0) {
		/* if we don't get a match it returns 1 so skip it */
		if (filter_ips(asc.local_addr, asc.rem_addr, 
			       options.include_ips, options.in_ips_count) == 0)
			inip = 1;
	}

	/* do we want to exclude this app?*/
	if (options.ex_apps_count != 0) {
		if (exclude_app(conn->cmdline, options.exclude_apps, 
				options.ex_apps_count) == 1)
			exap = 1;
	}

	/* do we want to include this app*/
	if (options.in_apps_count != 0) {
		if (include_app(conn->cmdline, options.include_apps, 
				options.in_apps_count) == 0)
			inap = 1;
	}
	
Cleanup:
	if (err != NULL) {
		PRINT_AND_FREE(err);
	}

	/* we haven't set anything so we care about all connections */
	if (!inip && !exip && !inap && !exap)
		return 0;

      	/* its in a network we don't care about nuke it */
	if (exip)
		return 1;

	/* its an application we don't care about nuke it */
	if (exap)
		return 1;

	/* its in a network we care about but we may not care about the application */
	if (inip && options.ex_apps_count) {
		if (exap)
			return 1; /* don't care */
		else
			return 0; /*do care */
	}

	/* it's in a nework we care about and we may care about the application */
	if (inip && options.in_apps_count) {
		if (inap)
			return 0; /* we do care */
		else
			return 1; /*we don't care */
	}

	/* its in a network we care about and we care about all applications */
	if (inip)
		return 0; /* we do care */

	/* its an application we care about across all networks*/
	if (inap)
		return 0;

	/* we should nver get here */
	/* but if we do then assume 
	 * the connection is odd enough to include
	 */
	return 1;
}


int main(int argc, char **argv)
{

	struct estats_error* err = NULL;
	struct estats_nl_client* cl = { 0 };
	struct estats_connection_list* clist = NULL;
	struct estats_connection_info* ci;
	struct estats_val_data* esdata = NULL;
	struct estats_mask state_mask;
	struct ConnectionHash* temphash = NULL;
	char *influx_service_url = NULL;
	char *config_filepath = "xsight.cfg";
	int length, i, j;

	if (get_config(config_filepath) == -1) {
		return -1;
	}

	/* generate the service url from the options */
	length = snprintf (NULL, 0, "db/%s/series?u=client&p=%s", options.influx_database, options.influx_password);
	length++;
	influx_service_url = malloc(length * sizeof(char));
	snprintf(influx_service_url, length, "db/%s/series?u=client&p=%s", options.influx_database, options.influx_password);
	log_debug ("Service URL: %s\n", influx_service_url);
	printf("Service URL: %s\n", influx_service_url);
	
	/* initiate the rest connection*/
	rest_init((char *)options.influx_host_url, influx_service_url);

	free(influx_service_url);


	/* random seed init for uuid */
	srand(time(NULL));

	/* set up estats mask to get state information */
	state_mask.masks[0] = 0;        /*perf*/
        state_mask.masks[1] = 0;        /*path*/
        state_mask.masks[2] = 1UL << 9; /*stack*/
        state_mask.masks[3] = 0;        /*app*/ 
        state_mask.masks[4] = 0;        /*tune*/ 
        state_mask.masks[5] = 0;        /*extras*/ 

        for (i = 0; i < MAX_TABLE; i++) {
                state_mask.if_mask[i] = 1;
        }

	/* init the nl client and gather the connection information */
	Chk(estats_nl_client_init(&cl));

	j = 0;
	while (1) {
		printf("pass: %d\n", j);
		j++;

		Chk(estats_connection_list_new(&clist));
		Chk(estats_list_conns(clist, cl));
		Chk(estats_connection_list_add_info(clist));
		Chk(estats_val_data_new(&esdata));
		
		/* set the seen flag in the hash to zero */
		for (temphash = activeflows; temphash != NULL; temphash=temphash->hh.next) {
			temphash->seen = 0;
		}
		estats_list_for_each(&clist->connection_info_head, ci, list) {
			/* check to see if the CID is already in our hash of active connections*/
			temphash = NULL;
			temphash = find_cid(ci->cid);
			if (temphash != NULL) {
				/* if it is then set the seen flag to 1 */
				temphash->seen = 1;
			} else {
				/* filter incoming connections based on option rule sets */
				if (filter_connection(ci) == 1) {
					continue;
				}
				/* if it is not then add the connection to our hash */
				temphash = add_connection(ci);
				add_flow_influx(temphash->flowid, ci);
				printf("Added flow: %d\n", temphash->cid);
				read_metrics(temphash, cl);
				add_time(temphash->flowid, "StartTime");
			}		
		}
		/* iterate over the hash. If the seen flag is 0 then the connection closed so we should remove it */
		/* note to self we are collecting the state information so we should use the change from 1 to 0 to indicate
		 * when we need to pull the last set of metrics. We could use the state information to determine when to eliminate
		 * the connection from the list but I'm afraid that we'll miss that at some point. 
		 */
		for (temphash = activeflows; temphash !=NULL; temphash=temphash->hh.next) {
			if (temphash->seen == 0) {
				if (delete_flow(temphash->cid) != 1) {
					printf ("Error deleting flow from table.");
				}
			}
			/* the flow has not expired so get the state information */
			Chk(estats_nl_client_set_mask(cl, &state_mask));
			Chk2Ign(estats_read_vars(esdata, temphash->cid, cl));
			/*commented out until the state action is working*/
			/* everything is masked except for state */
			for (i = 0; i < esdata->length; i++) {
				if (esdata->val[i].masked)
					continue;
				if (esdata->val[i].sv32 == 1) {
					/*connection has closed (state:1 means closed) - get final stats and delete*/
					read_metrics(temphash, cl);
					add_time(temphash->flowid, "EndTime");
					delete_flow(temphash->cid);
					printf("Deleted flow %d\n", temphash->cid);
				}
			}
			/* the connection has not closed so check to see if the timer expired */
			if (time(NULL) - temphash->lastpoll >= options.metric_interval) {
				// get data
				printf("Update metrics for cid %d\n", temphash->cid);
				read_metrics(temphash, cl);
				temphash->lastpoll = time(NULL);
			}
		}
	Continue: ;
		estats_val_data_free(&esdata);
		estats_connection_list_free(&clist);
//		count_hash();
		sleep(1);
	}
	
 Cleanup:
	estats_nl_client_destroy(&cl);

	/* close the rest connection*/
	rest_cleanup();

	/* free the hash */
	clear_hash();

	if (err != NULL) {
		PRINT_AND_FREE(err);
		return EXIT_FAILURE;
	}
	
	return EXIT_SUCCESS;
}
