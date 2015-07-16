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

int debugflag = 0;
int daemonize = 0;

/* global options struct*/
struct Options options;

/* global struct for network information */
struct NetworksHash *networks = NULL;

/* global struct for active connections/flows */
struct ConnectionHash *activeflows = NULL;

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

int main(int argc, char *argv[])
{

	struct estats_error* err = NULL;
	struct estats_nl_client* cl = { 0 };
	struct estats_connection_list* clist = NULL;
	struct estats_connection_info* ci;
	struct estats_val_data* esdata = NULL;
	struct estats_mask state_mask;
	struct ConnectionHash* temphash = NULL;
	struct ConnectionHash* vtemphash = NULL;
	char *config_filepath;
	int i, j, opt, tmp_debug;
	pid_t pid, sid;

	config_filepath = "/home/rapier/xsight/newcode/xsight.cfg";

	tmp_debug = -1;
	daemonize = 0;

	while ((opt = getopt(argc, argv, "d:f:hD")) != -1) {
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
		default:
			break;
		}
	}

	if (daemonize == 1) {
		pid = fork();
		if (pid < 0) {
			fprintf(stderr, "Could not daemonize xsight process! Exiting.\n");
			exit(EXIT_FAILURE);
		} 
		if (pid > 0)
			exit(EXIT_SUCCESS);
		
		umask(0);
		
		sid = setsid();
		if (sid < 0) {
			fprintf(stderr, "Could not create new SID for child process! Exiting.\n");
			log_error("Could not create new SID for child process.");
			exit(EXIT_FAILURE);
		}
		/* Change the current working directory */
		if ((chdir("/")) < 0) {
			fprintf (stderr, "Could not chdir to /. Exiting.\n"); 
			log_error ("Could not chidir to /.");
			exit(EXIT_FAILURE);
		}
		
		/* Close out the standard file descriptors */
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);		
	}	


	if (get_config(config_filepath, tmp_debug) == -1) {
		return -1;
	}

	/* iterate over the various networks and generate a curl handle for each of them */
	/* store a pointer to the curl handle in the entry in the hash */
	/* when a new connection is matched to a specific monitored network */
	/* store the curl handle in the active flow struct */
	/* then, when connecting use that curl handle */

	if (hash_get_curl_handles() == -1) {
		log_error("Unable to open all curl handles. Exiting");
		//goto Cleanup;
	}

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
		log_debug("Connection scan: %d", j);
		j++;

		Chk(estats_connection_list_new(&clist));
		Chk(estats_list_conns(clist, cl));
		Chk(estats_connection_list_add_info(clist));
		Chk(estats_val_data_new(&esdata));
		
		/* set the seen flag in the hash to zero */
		HASH_ITER(hh, activeflows, temphash, vtemphash) {
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
				temphash->closed = 0;
				add_flow_influx(temphash, ci);
				read_metrics(temphash, cl);
				add_time(temphash, cl, ci->cid, "StartTime");
			}		
		}
		/* iterate over all of the flows we've collected*/
		HASH_ITER(hh, activeflows, temphash, vtemphash) {
			/* delete stale flows from the hash */
			if (temphash->seen == 0) {
				log_debug("Deleting flow: %d", temphash->cid);
				if (delete_flow(temphash->cid) != 1) {
					log_error("Error deleting flow %d from table.", temphash->cid);
				}
				continue;
			}

			/* the flow has not expired so get the state information */
			Chk(estats_nl_client_set_mask(cl, &state_mask));
			Chk2Ign(estats_read_vars(esdata, temphash->cid, cl));

			/* the connection has not closed so check to see if the timer expired */
			/* but only if the flow is not closed (as per the state) */
			if ((time(NULL) - temphash->lastpoll >= options.metric_interval) 
			    && (temphash->closed != 1)) {
				// get data
				temphash->lastpoll = time(NULL);
				read_metrics(temphash, cl);
			}

			/* everything is masked except for state */
			for (i = 0; i < esdata->length; i++) {
				if (esdata->val[i].masked)
					continue;
				if ((esdata->val[i].sv32 == 1) && (temphash->closed != 1)) {
					/*connection has closed (state:1 means closed) - 
					 * get final stats*/
					/* don't delete the hash here. 
					 * it will still show up in the connection scan and
					 * be readded to the hash
					 * so just wait for it to expire
					 */
					read_metrics(temphash, cl);
					add_time(temphash, NULL, 0, "EndTime");
					temphash->closed = 1;
				}
			}
		}
	Continue:
		estats_val_data_free(&esdata);
		estats_connection_list_free(&clist);
		log_debug("Hash count: %d", count_hash());
		sleep(options.conn_interval);
	}
	
 Cleanup:
	estats_nl_client_destroy(&cl);

	/* close the rest connection*/
	rest_cleanup();

	/* free the hash */
	clear_hash();

	/* free the option struct*/
	freeoptions();

	if (err != NULL) {
		PRINT_AND_FREE(err);
		return EXIT_FAILURE;
	}

	if (daemonize)
		closelog();

	return EXIT_SUCCESS;
}
