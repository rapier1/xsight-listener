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
#include <pthread.h>

int debugflag = 0;
int daemonize = 0;
int exitnow = 0;
pthread_mutex_t lock;

/* global options struct*/
struct Options options;

/* global struct for network information */
struct NetworksHash *networks = NULL;

/* global struct for active connections/flows */
struct ConnectionHash *activeflows = NULL;

/* initially I was calling this function for every single connection
 * we saw every time we cycled through things. Turns out this is
 * pretty expensive. Durr. So we will only call this when a flow 
 * lives long enough to be of interest to us. Additionally, we
 * will only call this once per flow. You mean I was calling it multiple 
 * times per flow? Yes. Because Durr. 
 */
int filter_connection (struct estats_connection_info *conn) {
	struct estats_error *err = NULL;
	struct estats_connection_tuple_ascii asc;
	int exip, inip, exap, inap;

	exip = inip = exap = inap = 0;

	Chk(estats_connection_tuple_as_strings(&asc, &conn->tuple));	

	/* if we have ips to exclude check them */
	if (options.ex_ips_count != 0) {
		/* if we get a match it returns 0 so skip it */
		if ((match_ips(asc.local_addr, options.exclude_ips, 
			      options.ex_ips_count) == 1) || 
			(match_ips(asc.local_addr, options.exclude_ips, 
				   options.ex_ips_count) == 1))
			exip = 1;
	}

	/* if we have ips to include check them */
	if (options.in_ips_count != 0) {
		/* if we don't get a match it returns 1 so skip it */
		if ((match_ips(asc.local_addr, options.include_ips, 
			      options.in_ips_count) == 1) || 
			(match_ips(asc.local_addr, options.include_ips, 
				   options.in_ips_count) == 1))
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

	/* we should never get here */
	/* but if we do then assume 
	 * the connection is odd enough to include
	 */
	return 1;
}


void sighandler(int signo) {
	if (signo == SIGINT) {
		log_error("\nClosing xsight due to ctrl-c interrupt\n");
		exitnow = 1;
	}
}

int main(int argc, char *argv[]) {

	struct estats_error* err = NULL;
	struct estats_nl_client* cl = { 0 };
	struct estats_connection_list* clist = NULL;
	struct estats_connection_info* ci;
	struct estats_val_data* esdata = NULL;
	struct estats_mask state_mask;
	struct ConnectionHash* temphash = NULL;
	struct ConnectionHash* vtemphash = NULL;
	threadpool curlpool = NULL;
	threadpool tracepool = NULL;
	char *config_filepath;
	int i, opt, tmp_debug, stats_count, restart_curl_count;
	pid_t pid, sid;
	uint32_t j, trace_count, metric_count;
	
	config_filepath = "/usr/local/etc/xsight.cfg";

	tmp_debug = -1;
	j = 0;
	daemonize = 0;
	trace_count = 0;
	metric_count = 0;
	stats_count = 0;
	restart_curl_count = 0;
	
	if (signal(SIGINT, sighandler) == SIG_ERR) {
		log_error ("SIGINT handler not functional");
	}

	while ((opt = getopt(argc, argv, "d:f:hDv")) != -1) {
		switch (opt) {
		case 'h':
			printf("xsight -f[config filepath] -d[debug level [0|1|2]] -D(daemonize)\n\n");
			return 1;
		case 'f':
			config_filepath = optarg;
			break;
		case 'd':
			tmp_debug = atoi(optarg);
			break;
		case 'D':
			daemonize = 1;
			break;
		case 'v':
			printf("XSight Listener version %.2f\n", XSIGHT_VERSION);
			return 1;
		default:
			break;
		}
	}

	if (daemonize == 1) {
		pid = fork();
		if (pid < 0) {
			log_error("Could not daemonize xsight process! Exiting.\n");
			exit(EXIT_FAILURE);
		} 
		if (pid > 0)
			exit(EXIT_SUCCESS);
		
		umask(0);
		
		sid = setsid();
		if (sid < 0) {
			log_error("Could not create new SID for child process.");
			exit(EXIT_FAILURE);
		}
		/* Change the current working directory */
		if ((chdir("/")) < 0) {
			log_error ("Could not chidir to /.");
			exit(EXIT_FAILURE);
		}
		
		/* Close out the standard file descriptors */
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);		
		openlog(NULL, LOG_PID, LOG_USER);
		syslog(LOG_INFO, "Starting xsight listener in daemon mode");
	}	

	
	if (options_get_config(config_filepath, tmp_debug) == -1) {
		log_error("Could not find or process configuration file. Exiting."); 
		exit(EXIT_FAILURE);
	}

	log_debug("XSight Listener version %.2f", XSIGHT_VERSION);
		
	libinflux_init();

	/* iterate over the various networks and generate a curl handle for each of them */
	/* store a pointer to the curl handle in the entry in the hash */
	/* when a new connection is matched to a specific monitored network */
	/* store the curl handle in the active flow struct */
	/* then, when connecting use that curl handle */
	if (hash_get_curl_handles() == -1) {
		log_error("Unable to open all curl handles. Exiting");
		goto Cleanup;
	}

	/* enable the threadpool we use for curl requests */
	curlpool = thpool_init(NUM_THREADS);

	/* enable the threadpool for the traceroute requests */
	tracepool = thpool_init(NUM_THREADS);

	if (pthread_mutex_init(&lock, NULL) != 0){
		log_error("Could not initialize mutex. Exiting\n");
		exit(1);
	}
	log_debug ("Mutex initialized");
	
	/* find the orphan flows*/
	get_end_time();

	/* random seed */
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

	while (1) {
		j++;
		stats_count++;
		log_debug("Connection scan: %d", j);

		Chk(estats_connection_list_new(&clist));
		Chk(estats_list_conns(clist, cl));
		Chk(estats_connection_list_add_info(clist));
		Chk(estats_val_data_new(&esdata));
		
		/* set the seen flag in the hash to zero */
		HASH_ITER(hh, activeflows, temphash, vtemphash) {
			temphash->seen = false;
		}
		estats_list_for_each(&clist->connection_info_head, ci, list) {
			temphash = NULL;
			/* check to see if the CID is already in our hash of active connections*/
			/* TODO: the following line might taking up too much time. What could be faster?*/
			temphash = hash_find_cid(ci->cid);

			/* if the cmdline is empty then the connection is dead so skip it */
                        /* technically the cmd line would be empty because the cid can't find
                         * a corresponding entry in the pid table. This may fail in some 
                         * cirucmstances so a better way to handle this might be useful
                         */
                        if (strlen(ci->cmdline) == 0) {
				/* however, we need to see if the flow is in our hash 
				 * already and if it is then set the seen flag true. 
				 * if we don't then the flow is marked as stale and
				 * removed before the state information can be collected 
				 * and EndTime set */
				if (temphash != NULL) {
					temphash->seen = true;
				}
                                continue;
                        }

			if (temphash != NULL) {
				/* if it is then set the seen flag to 1 */
				temphash->seen = true;
				/* since we are putting everything in the hash we need to make sure
				 *  that we set continuing flows to true *even if* we are excluding them
				 *  otherwise they'll be deleted and readded unnessarily
				 */
				if (temphash->exclude == true)
					continue;
				temphash->age++; /* age of flow */
				/*only add to db if old enough and not already added */
				if (temphash->age >= options.conn_interval && 
				    temphash->added == false) {
					add_flow_influx(curlpool, temphash, ci);
					read_metrics(curlpool, temphash, cl);
					metric_count++;
					add_time(curlpool, temphash, cl, ci->cid, "StartTime");
					add_path_trace(curlpool, tracepool, temphash, ci);
					trace_count++;
					temphash->added = true;
				}
			} else {
				/* if it is not then add the connection to our hash */
				temphash = hash_add_connection(ci);
				hash_init_flow(temphash);
				if (filter_connection(ci) == 1)
					temphash->exclude = true;
				else
					temphash->exclude = false;
			}		
		}
		/* iterate over all of the flows we've collected*/
		HASH_ITER(hh, activeflows, temphash, vtemphash) {
			/* delete stale flows from the hash */
			if (temphash->seen == false || temphash->closed == true) {
				if (hash_delete_flow(temphash->cid) != 1) {
					log_error("Error deleting flow %d from table.", temphash->cid);
				}
				continue;
			}

			/* we only care about flows that live longer than our mininmum */
			/* as a note: we neverincrement the age of exluded flows so this check
			 * will also skip excluded flows as well as young flows */
			if (temphash->age <= options.conn_interval) 
				continue;
			
			/* the flow has not expired so get the state information */
			Chk(estats_nl_client_set_mask(cl, &state_mask));
			Chk2Ign(estats_read_vars(esdata, temphash->cid, cl));

			/* the connection has not closed (other wise it would have been deleted) 
			 * so check to see if the timer expired */
			if ((time(NULL) - temphash->lastpoll >= options.metric_interval)) {
				// get data
				temphash->lastpoll = time(NULL);
				read_metrics(curlpool, temphash, cl);
				metric_count++;
			}

			/* everything is masked except for state */
			for (i = 0; i < esdata->length; i++) {
				if (esdata->val[i].masked)
					continue;
				if (esdata->val[i].sv32 == 1) {
					/*connection has closed (state:1 means closed) - 
					 * get final stats*/
					/* don't delete the hash here. 
					 * it will still show up in the connection scan and
					 * be readded to the hash
					 * so just wait for it to expire
					 */
					read_metrics(curlpool, temphash, cl);
					metric_count++;
					add_time(curlpool, temphash, NULL, 0, "EndTime");
					temphash->closed = true;
				}
			}
		}
	Continue:
		estats_val_data_free(&esdata);
		estats_connection_list_free(&clist);
		if (stats_count == 60) {
			restart_curl_count++;
			stats_count = 0;
			log_info ("Scan #: %d; Current hash count: %d; Total Traceroutes: %d; Total Metrics: %d; Flow Hash Overhead: %ld",
				  j, hash_count_hash(), trace_count,
				  metric_count, HASH_OVERHEAD(hh, activeflows));
			log_info ("Curl job queue: %d; Traceroute job queue: %d",
				  thpool_jobqueue_length(curlpool),
				  thpool_jobqueue_length(tracepool));
			
		}
		/* once an hour kill the curl handles and restart them. Maybe this will help with memory issues */
		/* that didn't help with the memory issues so we are going to comment this 
		 * out. We aren't deleting it as I may want to revisit this at some
		 * point - CJR 2/20/2020
		 */
		/* if (restart_curl_count == -1) { */
		/* 	log_info ("Restarting curl handles"); */
		/* 	restart_curl_count = 0; */
		/* 	log_info ("Waiting on curlpool"); */
		/* 	thpool_wait(curlpool); /\* drain the curlpool *\/ */
		/* 	log_info ("Waiting on tracepool"); */
		/* 	thpool_wait(tracepool); */
		/* 	hash_close_curl_handles(); /\* close all of the curl handles *\/ */
		/* 	log_info("detsroying pools"); */
		/* 	thpool_destroy(curlpool); */
		/* 	thpool_destroy(tracepool); */
		/* 	log_info ("initializing pools"); */
		/* 	curlpool = thpool_init(NUM_THREADS); */
		/* 	tracepool = thpool_init(NUM_THREADS); */
		/* 	hash_get_curl_handles(); /\* get new curl handles *\/ */
		/* 	log_info ("Curl handles restarted");			 */
		/* } */

		if (exitnow)
			goto Cleanup;
		/* sleep(options.conn_interval); */
		sleep (1);
	}
	
 Cleanup:
	estats_nl_client_destroy(&cl);

	/* destroy the threadpools */
	/* have to do this before we close the curl handles */
	log_info("Closing down.");
	log_info ("Waiting for curl threadpool queue to drain.");
	thpool_wait(curlpool);
	log_info ("Waiting for traceroute threadpool queue to drain.");
	thpool_wait(tracepool);
	log_info ("Detsroying threadpools.");
	thpool_destroy(curlpool);
	thpool_destroy(tracepool);
	
	/* close the rest connection*/
	hash_close_curl_handles();
	libinflux_cleanup();

	/* free the hash */
	hash_clear_hash();

	/* free the option struct*/
	options_freeoptions();
	
	if (err != NULL) {
		PRINT_AND_FREE(err);
		return EXIT_FAILURE;
	}

	if (daemonize)
		closelog();
	exit(EXIT_SUCCESS);
	return EXIT_SUCCESS;
}
