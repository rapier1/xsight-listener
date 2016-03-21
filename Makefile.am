if LINK_LIBJSON
  USE_LIBJSON=-ljson
endif
if LINK_LIBJSONC
  USE_LIBJSON=-ljson-c
endif
AM_CFLAGS= -O3 -g -Wall -Wextra -std=gnu99 -fgnu89-inline -DXOPEN_SOURCE
AM_LDFLAGS= -lestats -lcurl -lconfig -lpthread -lcrypto $(USE_LIBJSON)
bin_PROGRAMS = xsight
xsight_SOURCES= xsight.c hash.c build_query.c options.c libinflux.c \
		debug.c parse.c thpool.c tracer.c dead_flow_check.c \
		string-funcs.c safe_malloc.c
