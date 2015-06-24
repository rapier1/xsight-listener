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

#include "options.h"

extern struct Options options;

/* read the configuration file */
int get_config(char *path, int tmp_debug) {
	int value, count, i;
	const char *string;
	const config_setting_t *array;
	config_t cfg;
	
	config_init(&cfg);
	
	/*read config file*/
	if (!config_read_file(&cfg, path)) {
		log_error("%s:%d - %s (bad path to config file?)", 
			  config_error_file(&cfg), config_error_line(&cfg), 
			  config_error_text(&cfg));
		return -1;
	}

	/* set some basics for the option struct*/
	options.in_apps_count = 0;
	options.ex_apps_count = 0;
	options.in_ips_count = 0;
	options.ex_ips_count = 0;

	/* start going through the cfg file */
	if (config_lookup_int(&cfg, "debug", &value)) {
		debugflag = options.debugflag = value;
		/* lets the user override the debig level from the command line */
		if (tmp_debug != -1)
			debugflag = tmp_debug;
		log_debug("Debug flag: %d", debugflag);
	}

	if (config_lookup_int(&cfg, "printjson", &value)) {
		printjson = options.printjson = value;
		log_debug("Print JSON flag: %d", printjson);
	}

	if (!config_lookup_string(&cfg, "domain", &string)) {
		log_error("Domain not specified in config file! Exiting.");
		return -1;
	}
	options.domain_name = strdup(string);
	log_debug("Domain: %s", options.domain_name);

	if (!config_lookup_string(&cfg, "dtn_id", &string)) {
		log_error("DTN ID not specified in config file! Exiting.");
		return -1;
	}
	options.dtn_id = strdup(string);
	log_debug("DTN: %s", options.dtn_id);

	if (!config_lookup_string(&cfg, "database", &string)) {
		log_error("Influx database not specified in config file! Exiting.");
		return -1;
	}
	options.influx_database = strdup(string);
	log_debug("Influx Database: %s", options.influx_database);

	if (!config_lookup_string(&cfg, "password", &string)) {
		log_error("Influx database password not specified in config file! Exiting.");
		return -1;
	}
	options.influx_password = strdup(string);
	log_debug("Influx Password: %s", options.influx_password);

	if (!config_lookup_string(&cfg, "host_url", &string)) {
		log_error("Influx host URL not specified in config file! Exiting.");
		return -1;
	}
	options.influx_host_url = strdup(string);
	log_debug("Influx Host URL: %s", options.influx_host_url);

	if (!config_lookup_int(&cfg, "conn_poll_interval", &value)) {
		log_error("Connection polling interval not specified in config file! Exiting.");
		return -1;
	}
	options.conn_interval = value;
	log_debug("Connection Poll Interval : %d(s)", options.conn_interval);

	if (!config_lookup_int(&cfg, "metric_poll_interval", &value)) {
		log_error("Metric polling interval not specified in config file! Exiting.");
		return -1;
	}
	options.metric_interval = value;
	log_debug("Metric Poll Interval : %d(s)", options.metric_interval);

	/* get any excluded ip addresses */
	array = config_lookup(&cfg, "exclude_ips");
	count = config_setting_length(array);
	if (count) {
		options.exclude_ips = malloc(sizeof(*options.exclude_ips) * count);
		options.ex_ips_count = count;
	}
	for (i = 0; i < count; i++) {
		string = config_setting_get_string_elem(array, i);
		options.exclude_ips[i] = strdup(string);
		log_debug("Excluded IP: %s", options.exclude_ips[i]);
	}

	/* get any included ip addresses */
	array = config_lookup(&cfg, "include_ips");
	count = config_setting_length(array);
	if (count) {
		options.include_ips = malloc(sizeof(*options.include_ips) * count);
		options.in_ips_count = count;
	}
	for (i = 0; i < count; i++) {
		string = config_setting_get_string_elem(array, i);
		options.include_ips[i] = strdup(string);
		log_debug("Included IP: %s", options.include_ips[i]);
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
		log_debug("Excluded application: %s", options.exclude_apps[i]);
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
		log_debug("Included application: %s", options.include_apps[i]);
	}

	config_destroy(&cfg);
	return 1;
}

void freeoptions () {
	int i;
	free((void *)options.domain_name);
	free((void *)options.dtn_id);
	free((void *)options.influx_host_url);
	free((void *)options.influx_database);
	free((void *)options.influx_password);
	if (options.in_ips_count) {
		for (i = 0; i < options.in_ips_count; i++) {
			free(options.include_ips[i]);
		}
		free(options.include_ips);
	}
	if (options.ex_ips_count) {
		for (i = 0; i < options.ex_ips_count; i++) {
			free(options.exclude_ips[i]);
		}
		free(options.exclude_ips);
	}
	if (options.in_apps_count) {
		for (i = 0; i < options.in_apps_count; i++) {
			free(options.include_apps[i]);
		}
		free(options.include_apps);
	}
	if (options.ex_apps_count) {
		for (i = 0; i < options.ex_apps_count; i++) {
			free(options.exclude_apps[i]);
		}
		free(options.exclude_apps);
	}
}
