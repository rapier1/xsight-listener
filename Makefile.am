if LINK_LIBJSONC
USE_LIBJSON=-ljson-c
else
USE_LIBJSON=-ljson
endif

if DEBUG
AM_CFLAGS =-g3 -O0 
AM_CXXFLAGS =-g3 -O0
else
AM_CFLAGS =-O3
AM_CXXFLAGS =-O3
endif

AM_CFLAGS += -Wall -Wextra -std=gnu11 -fgnu89-inline -DXOPEN_SOURCE -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc -fno-builtin-free
AM_LDFLAGS= -lestats -lcurl -lconfig -lpthread -lcrypto $(USE_LIBJSON)  -ljemalloc
bin_PROGRAMS = xsight
xsight_SOURCES= xsight.c hash.c build_query.c options.c libinflux.c \
		debug.c parse.c thpool.c tracer.c dead_flow_check.c \
		string-funcs.c safe_malloc.c
