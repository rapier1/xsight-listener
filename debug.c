/*
 * Copyright (c) 2015 The Board of Trustees of Carnegie Mellon University.
 *
 *  Author: Chris Rapier <rapier@psc.edu>
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


#include "debug.h"

extern int debugflag;
extern int daemonize;
 
void log_format(const char* tag, const char* message, LogLevels level, va_list args) {   
	if (daemonize) {
		switch (level) {
		case DEBUG:
		case DEBUG2:
			vsyslog(LOG_DEBUG, message, args);
			break;
		case ERROR:
			vsyslog(LOG_ERR, message, args);
			break;
		case INFO:
			vsyslog(LOG_INFO, message, args);
			break;
		default:
			break;
		}
	} else {
		time_t now;     
		time(&now);     
		char * date =ctime(&now);   
		date[strlen(date) - 1] = '\0';  
		printf("%s [%s] ", date, tag);  
		vprintf(message, args);     
		printf("\n"); 
	}
}

void log_error(const char* message, ...) {  
	va_list args;   
	LogLevels level;
	level = ERROR;

	va_start(args, message);    
	log_format("error", message, level, args);     
	va_end(args); 
}

void log_info(const char* message, ...) {   
	va_list args;   
	LogLevels level;
	level = INFO;

	va_start(args, message);    
	log_format("info", message, level, args);  
	va_end(args); 
}

void log_debug(const char* message, ...) {  
	if (debugflag < 1)
		return;
	va_list args;   
	LogLevels level;
	level = DEBUG;
	
	va_start(args, message);    
	log_format("debug", message, level, args);     
	va_end(args); 
}

void log_debug2(const char* message, ...) {  
	if (debugflag < 2)
		return;
	va_list args;   
	LogLevels level;
	level = DEBUG2;
	
	va_start(args, message);    
	log_format("debug2", message, level, args);     
	va_end(args); 
}
