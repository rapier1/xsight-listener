/* Copyright © 2015, Pittsburgh Supercomputing Center.  All Rights Reserved. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include "libinflux.h"

bool influx_debug = 0;


/* Set-up and tear-down functions */


/* Prepares libinflux & cURL - call before any other libinflux functions */
void libinflux_init()
{
	curl_global_init(CURL_GLOBAL_SSL);
}

/* Cleans up memory used by libinflux & cURL */
void libinflux_cleanup()
{
	curl_global_cleanup();
}


/* Creates and initilizes a new influxConn structure. A pointer to the new
 * struct is returned. User should free the returned struct with free_conn().
 */
influxConn* create_conn(char *host, char *database, char *user, char *pass, int ssl_verify)
{
	/* create new influxConn structure */
	influxConn *newConn = malloc(sizeof(influxConn));
	
	/* initilize members */
	newConn->curl = curl_easy_init();
	newConn->on_data_ready = NULL;
	newConn->host_url = strndup(host, strlen(host));
	newConn->db = strndup(database, strlen(database));
	newConn->user = strndup(user, strlen(user));
	newConn->pass = strndup(pass, strlen(pass));
	newConn->response = malloc(1); /* not always used but always free'd so need to have something here */
	newConn->ssl = ssl_verify;
	
	/* check for https protocol */
	if(strstr(newConn->host_url, "https://")){
		/* enable SSL */
		curl_easy_setopt(newConn->curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
		/* set ssl peer verification on/off */
		curl_easy_setopt(newConn->curl, CURLOPT_SSL_VERIFYPEER, newConn->ssl);
	}else{
		/* disable ssl */
		newConn->ssl = -1;
	}
	
	return newConn;
}

/* Frees the influxConn structure that is passed in.
 * The library does not keep track of created connections
 * so it is the user's job free all created connections.
 */
void free_conn(influxConn *conn)
{
	curl_easy_cleanup(conn->curl);
	free(conn->host_url);
	free(conn->db);
	free(conn->user);
	free(conn->pass);
	free(conn->response);
	free(conn);
}

/* Allows the user to pass in a function to handle server response when it is
 * ready. The user-defined function must accept a char pointer as a parameter.
 * The function must return an int: 0 one success, non-zero on failure.
 */
void set_callback(influxConn *conn, int (*callback)(char*))
{
	conn->on_data_ready = callback;
}

/* Internal utility functions  */


/* Updates the curl handle contained in the influxConn struct
 * based on the the ssl member.
 */
void update_ssl_opts(influxConn *conn)
{
	if(conn->ssl == 0 || conn->ssl == 1){ /* if ssl is enabled */
		/* enable SSL */
		curl_easy_setopt(conn->curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
		/* set ssl peer verification on/off */
		//curl_easy_setopt(conn->curl, CURLOPT_SSL_VERIFYPEER, conn->ssl);
	}
}

char* build_write_url(influxConn *conn)
{
	char endpoint[] = "write?";
	
	/* allocate space for parameterized url */
	size_t size = sizeof(char *) * ( (int)strlen(conn->host_url)
					 + (int)strlen(endpoint) 
					 + (int)strlen(conn->db)+3 
					 + (int)strlen(conn->user)+3 
					 + (int)strlen(conn->pass)+3 + 1);
	char *url = malloc(size);
	
	/* concatenate endpoint and parameters to host_url */
	if(url){
		snprintf(url, size, "%s%sdb=%s&u=%s&p=%s", conn->host_url, endpoint, 
			 conn->db, conn->user, conn->pass);
	}
	
	return url;
}

char* build_query_url(influxConn *conn)
{
	char endpoint[] = "query?";
	
	/*allocate space for parameterized url*/
	size_t size = sizeof(char *) * ( (int)strlen(conn->host_url)
					 + (int)strlen(endpoint)             /* warning - magic numbers */
					 + (int)strlen(conn->db)+3           /* 'db=' */
					 + (int)strlen(conn->user)+3         /* '&u=' */
					 + (int)strlen(conn->pass)+3 +3 + 1);/* '&p=', '&q=' */
	char *url = malloc(size);
	
	/*concatenate endpoint and parameters to host_url*/
	if(url){
		snprintf(url, size, "%s%sdb=%s&u=%s&p=%s&q=", conn->host_url, endpoint, 
			 conn->db, conn->user, conn->pass);
	}
	
	return url;
}

/* setter functions for influxConn struct */
void set_host_url(influxConn *conn, char *url){
	conn->host_url = strdup(url);
}
void set_database(influxConn *conn, char *database){
	conn->db = strdup(database);
}
void set_user(influxConn *conn, char *pass){
	conn->user = strdup(pass);
}
void set_pass(influxConn *conn, char *pass){
	conn->pass = strdup(pass);
}
void set_debug(bool debug){
	influx_debug = debug;
}

/* Function that handles cURL's write callback. It allocates a new string 
 * containing the server response. The response string is passed to the
 * user-defined callback, influxConn->on_data_ready, if it is defined.
 * Otherwise, it sends the response string to stdout.
 */
size_t writeCallback(char *contents, size_t size, size_t nmemb, influxConn *conn){
	influxConn *inbound = conn;
	size_t realsize = size * nmemb;
	
	/*allocate memory for new data */
	inbound->response = realloc(inbound->response, inbound->response_size + realsize + 1);
	if (inbound->response == NULL) {
		fprintf(stderr, "realloc returned NULL");
		return 0;
	}
	
	/*copy data from contents to the response pointer */
	memcpy(&(inbound->response[inbound->response_size]), contents, realsize);
	inbound->response_size += realsize; /* increment size of string */
	inbound->response[inbound->response_size] = '\0'; /* null terminate string */
	
	/*if user defined a callback */
	if(conn->on_data_ready){
		/*pass response to callback */
		if(conn->on_data_ready(inbound->response) != 0){
			fprintf(stderr, "user callback returned non-zero result");
		}
	}else{
		if(influx_debug){printf("User data callback not defined.\n");}
	}
	
	return realsize;
}


/* InfluxDB functions */


/* Sends the query string, *query, to the database represented by *service_url.
 * *query must be a properly formatted InfluxDB query.
 * Returns a CURLcode that is globally stored in influxConn->result_code 
 */
CURLcode influxQuery(influxConn *conn, char *query){
	char *url = build_query_url(conn); /* freed in sendGet() */
	
	if(influx_debug){printf("[q: %s]\n", url);}
	
	update_ssl_opts(conn);
	conn->result_code = sendGet(conn, url, query);
	return conn->result_code;
}

/* Writes the JSON object, *data, to the database represented by *service_url.
 * *data must be a properly formatted InfluxDB JSON object.
 * Returns a CURLcode that is stored in influxConn->result_code
 */
CURLcode influxWrite(influxConn *conn, char *data){
	char *url = build_write_url(conn); /* freed in sendPost() */
	
	if(influx_debug){printf("[w: %s]\n", url);}
	
	update_ssl_opts(conn);
	conn->result_code = sendPost(conn, url, data);
	return conn->result_code; 
}

/* Tests an influxDB connection with a GET request.
 * 
 */
bool influxCheck(influxConn *conn)
{
	update_ssl_opts(conn);
	conn->result_code = sendGet(conn, conn->host_url, NULL);
	return conn->result_code;
}


/* Basic CURL functions */


/* Send a POST request to write *data to *url 
 * Sends request to influx host defined in conn. Returns resulting CURLcode.
 */
CURLcode sendPost(influxConn *conn, char *url, char *data){
    CURL *curl = conn->curl;
    CURLcode resultCode = {0};
    if(influx_debug){printf("[post]\n");}
    if(curl){
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(data));
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, conn);
        resultCode = curl_easy_perform(curl);
    }
    free(url);
    if(influx_debug){
        if(resultCode != CURLE_OK)
            printf("[post] CURL ERROR\n");
        else
            printf("[post] CURL OK\n");
    }
    return resultCode;
}

/* Send a GET request to write *data (after url encoding) to *url 
 * Sends request to influx host defined in conn. Returns resulting CURLcode.
 */
CURLcode sendGet(influxConn *conn, char *url, char *data){
    CURL *curl = conn->curl;
    CURLcode resultCode = {0};
    if(curl){
	    if(data){ /* urlencode data */
		    char *encoded_data = curl_easy_escape(curl, data, strlen(data));
		    url = realloc(url, sizeof(char *) * ((int) strlen(url) + strlen(encoded_data) + 1) );
		    if(url){
			    strncat(url, encoded_data, strlen(encoded_data));
			    curl_free(encoded_data);
		    }
	    }
	    
	    if(influx_debug){printf("[q: %s]\n", url);}
	    
	    curl_easy_setopt(curl, CURLOPT_URL, url);
	    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
	    curl_easy_setopt(curl, CURLOPT_WRITEDATA, conn);
	    resultCode = curl_easy_perform(curl);
    }
    free(url);
    return resultCode;
}
