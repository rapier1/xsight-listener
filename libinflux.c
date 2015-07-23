/* Copyright © 2015, Pittsburgh Supercomputing Center.  All Rights Reserved. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include "libinflux.h"

int debug = 0;

/* Set-up and tear-down functions */

//Prepares libinflux & cURL - call before any other libinflux functions
void rest_init()
{
    curl_global_init(CURL_GLOBAL_ALL);
}

/* Creates and initilizes a new influxConn structure. A pointer to the new
 * struct is returned. User should free the returned pointer before exiting.
 */
influxConn* create_conn(char *host, char *database, char *user, char *pass)
{
    //create new influxConn structure
    influxConn *newConn = malloc(sizeof(influxConn));

    //initilize members
    newConn->curl = curl_easy_init();
    newConn->host_url = strdup(host);
    newConn->db = strdup(database);
    newConn->user = strdup(user);
    newConn->pass = strdup(pass);

    return newConn;
}

char* build_write_url(influxConn *conn)
{
    char endpoint[] = "write?";

    //allocate space for parameterized url
    size_t size = sizeof(char *) * ( (int)strlen(conn->host_url)
                + (int)strlen(endpoint) 
                + (int)strlen(conn->db)+3 
                + (int)strlen(conn->user)+3 
                + (int)strlen(conn->pass)+3 + 1);
    char *url = malloc(size);

    //concatenate endpoint and parameters to host_url
    if(url){
        snprintf(url, size, "%s%sdb=%s&u=%s&p=%s&precision=u", conn->host_url, endpoint, 
            conn->db, conn->user, conn->pass);
    }

    return url;
}

char* build_query_url(influxConn *conn)
{
    char endpoint[] = "query?";

    //allocate space for parameterized url
    size_t size = sizeof(char *) * ( (int)strlen(conn->host_url)
                + (int)strlen(endpoint) 
                + (int)strlen(conn->db)+3 
                + (int)strlen(conn->user)+3 
                + (int)strlen(conn->pass)+3 +3 + 1);
    char *url = malloc(size);

    //concatenate endpoint and parameters to host_url
    if(url){
        snprintf(url, size, "%s%sdb=%s&u=%s&p=%s&q=", conn->host_url, endpoint, 
            conn->db, conn->user, conn->pass);
    }

    return url;
}

//Cleans up memory used by the library
void rest_cleanup(influxConn *conn)
{
    curl_easy_cleanup(conn->curl);
}

//setter functions for influxConn struct
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

/* InfluxDB functions - Query & Write */

/* Sends the query string, *query, to the database represented by *service_url.
 * *query must be a properly formatted InfluxDB query.
 * Returns a CURLcode that is globally stored as res (until the next call)
 */
CURLcode influxQuery(influxConn *conn, char *query){
    char *url = build_query_url(conn); //freed in sendGet()
   
    if(debug){printf("[q: %s]\n", url);}
    
    sendGet(conn, url, query);
    return conn->resCode;
}

/* Writes the JSON object, *data, to the database represented by *service_url.
 * *data must be a properly formatted InfluxDB JSON object.
 * Returns a CURLcode that is globally stored as res (until the next call)
 */
CURLcode influxWrite(influxConn *conn, char *data){
    char *url = build_write_url(conn); //freed in sendPost()

    if(debug){printf("[w: %s]\n", url);}

    sendPost(conn, url, data);
    return conn->resCode; 
}

/* Basic CURL functions - GET & POST */

/* Send a POST request to write *data to *url 
 * Sends request to influx host defined in conn. Returns resulting CURLcode.
 */
CURLcode sendPost(influxConn *conn, char *url, char *data){
    if(conn->curl){
        curl_easy_setopt(conn->curl, CURLOPT_URL, url);
        curl_easy_setopt(conn->curl, CURLOPT_POSTFIELDSIZE, (long)strlen(data));
        curl_easy_setopt(conn->curl, CURLOPT_POSTFIELDS, data);
	curl_easy_setopt(conn->curl, CURLOPT_TCP_KEEPALIVE, 1L);
	curl_easy_setopt(conn->curl, CURLOPT_TCP_KEEPIDLE, 30L);
	curl_easy_setopt(conn->curl, CURLOPT_TCP_KEEPINTVL, 10L);
        conn->resCode = curl_easy_perform(conn->curl);
    }
    free(url);
    return conn->resCode;
}

/* Send a GET request to write *data (after url encoding) to *url 
 * Sends request to influx host defined in conn. Returns resulting CURLcode.
 */
CURLcode sendGet(influxConn *conn, char *url, char *data){
    if(conn->curl){
        if(data){ //urlencode data
            char *encoded_data = curl_easy_escape(conn->curl, data, strlen(data));
            url = realloc(url, sizeof(char *) * ((int)strlen(encoded_data)+1) );
            if(url){
                strncat(url, encoded_data, strlen(encoded_data));
                curl_free(encoded_data);
            }
        }
        curl_easy_setopt(conn->curl, CURLOPT_URL, url);
        conn->resCode = curl_easy_perform(conn->curl);
    }
    free(url);
    return conn->resCode;
}

