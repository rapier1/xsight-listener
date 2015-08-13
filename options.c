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
extern struct Networks *networks;

/* read the configuration file */
int options_get_config(char *path, int tmp_debug) {
	char search_str[64];
	int value, count, i, order;
	const char *string;
	const char *network_name;
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
		debugflag = value;
		/* lets the user override the debig level from the command line */
		if (tmp_debug != -1)
			debugflag = tmp_debug;
		log_debug("Debug flag: %d", debugflag);
	}

	if (!config_lookup_string(&cfg, "dtn_id", &string)) {
		log_error("DTN ID not specified in config file! Exiting.");
		return -1;
	}
	options.dtn_id = strdup(string);
	log_debug("DTN: %s", options.dtn_id);

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

	array = config_lookup(&cfg, "network_names");
	count = config_setting_length(array);
	if (count < 1) {
		log_error("No monitored networks defined. Exiting!");
		return -1;
	}
	options.network_count = count;
	log_debug("Monitored networks in 'networks' stanza: %d\n", count);
	/* add the information to the hash */
	for (i = 0; i < count; i++) {
		int j = 0;
		int mycount = 0;
		config_setting_t *root;
		config_setting_t *net_child;
		config_setting_t *net_stanza;
		config_setting_t *net_array;

		struct NetworksHash *network = NULL;
		network = (NetworksHash*)malloc(sizeof(NetworksHash));

		network_name = config_setting_get_string_elem(array, i); /* string now holds the network name */

		root = config_root_setting(&cfg);
		net_stanza = config_setting_get_member(root, "networks");
		net_child = config_setting_get_member(net_stanza, network_name); 

		sprintf (search_str, "networks.%s.group", network_name);

		if (!config_setting_lookup_string(net_child, "group", &string)) { 
			log_error("Monitored network %s's group name not specified in config file! Exiting.", network_name);
			return -1;
		}
		log_debug("Network: %s, group: %s", network_name, string);
		network->group = strdup(string);

		if (!config_setting_lookup_string(net_child, "domain", &string)) {
			log_error("Monitored network %s's domain not specified in config file! Exiting.", network_name);
			return -1;
		}
		log_debug("Network: %s, domain_name: %s", network_name, string);
		network->domain_name = strdup(string);

		if (!config_setting_lookup_string(net_child, "host_url", &string)) {
			log_error("Monitored network %s's hosturl not specified in config file! Exiting.", network_name);
			return -1;
		}
		log_debug("Network: %s, host_url: %s", network_name, string);
		network->influx_host_url = strdup(string);

		if (!config_setting_lookup_string(net_child, "database", &string)) {
			log_error("Monitored network %s's database not specified in config file! Exiting.", network_name);
			return -1;
		}
		log_debug("Network: %s, database: %s", network_name, string);
		network->influx_database = strdup(string);

		if (!config_setting_lookup_string(net_child, "db_user", &string)) {
			log_error("Monitored network %s's database user not specified in config file! Exiting.", network_name);
			return -1;
		}
		log_debug("Network: %s, db_user: %s", network_name, string);
		network->influx_user = strdup(string);

		if (!config_setting_lookup_string(net_child, "password", &string)) {
			log_error("Monitored network %s's database password not specified in config file! Exiting.", network_name);
			return -1;
		}
		log_debug("Network: %s, password: %s", network_name, string);
		network->influx_password = strdup(string);

		if (!config_setting_lookup_int(net_child, "order", &order)) {
			network->precedence = i;
		}

		log_debug("Network: %s, precedence: %d", network_name, order);
		network->precedence = order;

		net_array = config_setting_get_member(net_child, "networks");
		mycount = config_setting_length(net_array);
		network->net_addrs_count = 0;
		if (mycount) {
			network->net_addrs = malloc(sizeof(network->net_addrs) * mycount);
		        network->net_addrs_count = mycount;
		}
		for (j = 0; j < mycount; j++) {
			string = config_setting_get_string_elem(net_array, j);
			network->net_addrs[j] = strdup(string);
			log_debug("%s: Added network : %s", network_name, network->net_addrs[j]);
		}
		hash_add_network(network, i);
	}
	/* we need to sort the network hash in precedence order */
	hash_sort_by_precedence();
	config_destroy(&cfg);
	return 1;
}



void options_freeoptions () {
	int i;
	free((void *)options.domain_name);
	free((void *)options.dtn_id);
	free((void *)options.influx_host_url);
	free((void *)options.influx_database);
	free((void *)options.influx_password);
	free((void *)options.influx_user);
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
