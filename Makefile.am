AM_CFLAGS= -O2 -g -Wall -Wextra -std=gnu99 -fgnu89-inline -fno-omit-frame-pointer -DXOPEN_SOURCE
AM_LDFLAGS= -lestats -lcurl -lconfig -lpthread -lcrypto -ljson-c
bin_PROGRAMS = xsight
xsight_SOURCES= xsight.c hash.c build_query.c options.c libinflux.c \
		debug.c parse.c thpool.c tracer.c dead_flow_check.c \
		string-funcs.c safe_malloc.c
