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

#include "json_influx.h"
extern struct Options options;

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
	json_str = strdup((char *)json_object_to_json_string_ext(my_object, 
								 JSON_C_TO_STRING_PLAIN));

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

	/* convert the tuples to a string */
	Chk(estats_connection_tuple_as_strings(&asc, &conn->tuple));

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
	/* this is just a place holder that we use later*/
        json_object_object_add(jsonout, "points", points);
	 
	/* now we replace the empty points array with real values 
	 * this keeps us from having to rebuild the whole of the json object each time
	 */
	
	replace_array_in_json_object(jsonout, "src_ip", 
				     asc.local_addr, flowid_char, &influx_data);
	strncat(influx_data, ",", 1); /* add commas to separate the json objects*/

	replace_array_in_json_object(jsonout, "dst_ip", 
				     asc.rem_addr, flowid_char, &influx_data);
	strncat(influx_data, ",", 1);

	replace_array_in_json_object(jsonout, "src_port", 
				     asc.local_port, flowid_char, &influx_data);
	strncat(influx_data, ",", 1);

	replace_array_in_json_object(jsonout, "dest_port", 
				     asc.rem_port, flowid_char, &influx_data);
	strncat(influx_data, ",", 1);

	replace_array_in_json_object(jsonout, "command", 
				     conn->cmdline, flowid_char, &influx_data);
	strncat(influx_data, "]", 1); /*close the bracket*/

	/*free the json object*/
	json_object_put(jsonout);

	/* note, we'll set the start time when we make the initial instrument read */
        
	/* the flow meta data is in influx_data
	 * now send it to the influxdb using curl
	 */

	log_debug2("%s", influx_data);
	if ((curl_res = influxWrite(influx_data) != CURLE_OK)) {
		log_error("CURL failure: %s", curl_easy_strerror(curl_res));
	} else {
		log_debug("Flow added: %d", conn->cid);
	}
Cleanup:
	if (err != NULL) {
		log_error("%s:\t%s\t%s tuple to ascii conversion error in add_flow_influx", 
			  flowid_char, estats_error_get_extra(err), 
			  estats_error_get_message(err));
		estats_error_free(&err);
	}
	free(influx_data);
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

	json_str = strdup((char *)json_object_to_json_string_ext(jsonout, 
								 JSON_C_TO_STRING_PLAIN));
	json_object_put(jsonout); /* free the json object */

	/* get the size of the resulting string so I can reallocate influx_data */
	size = strlen(influx_data) + strlen(json_str); 
	influx_data = realloc(influx_data, size + 3);

	/* copy the json string into the influx data string*/
	strncat(influx_data, json_str,strlen(json_str));

	/* close the bracket */
	strncat(influx_data, "]", 1);
	
	log_debug2("%s", influx_data);
	if ((curl_res = influxWrite(influx_data) != CURLE_OK)) {
		log_error("CURL failure: %s", curl_easy_strerror(curl_res));
	} else {
		log_debug("Timestamp added");
	}
	free(json_str);
	free(influx_data);
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
	length = snprintf(NULL, 0, "group_%s_dtn_%s_flow_%s", 
			  options.domain_name, options.dtn_id, flowid_char);
	length++;
	name_str = malloc(length * sizeof(char));
	snprintf(name_str, length, "group_%s_dtn_%s_flow_%s", 
		 options.domain_name, options.dtn_id, flowid_char);

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
		json_str = strdup((char *)json_object_to_json_string_ext(jsonout, 
									 JSON_C_TO_STRING_PLAIN));

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
		log_error("CURL failure: %s", curl_easy_strerror(curl_res));
	} else {
		log_debug("Updated metrics: %d", flow->cid);
	}
	log_debug2("%s", influx_data);
	free(name_str);
	free(influx_data);
Cleanup:
	estats_val_data_free(&esdata);
	if (err != NULL) {
		log_error("%s:\t%s\t%s", flowid_char, 
			  estats_error_get_extra(err), 
			  estats_error_get_message(err));
		estats_error_free(&err);
	}
}
