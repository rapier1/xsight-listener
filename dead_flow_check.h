#define _XOPEN_SOURCE 700
#include "hash.h"
#include "libinflux.h"
#include <uthash.h>
#include "options.h"
#include <json-c/json.h>
#include "string-funcs.h"
#include "debug.h"
#include <time.h>


void get_end_time();
int get_flow_ids(char *);
void json_parse_array( json_object *, char *, int, uint64_t *, bool);
void parse_flows_json(json_object *, int, uint64_t *, bool);
int parse_tuples_json(json_object *);
int build_json_object ( char *, json_object **);
void get_current_flows();
void process_dead_flows();
uint64_t get_last_metric_ts(json_object *);
uint64_t getTime(json_object *, int);
int getIndex(json_object *, int);
void getFlows(json_object *, int, bool);
void find_difference();
void clean_up();
