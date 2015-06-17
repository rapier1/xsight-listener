if LINK_LIBJSON
  USE_LIBJSON=-ljson
endif
if LINK_LIBJSONC
  USE_LIBJSON=-ljson-c
endif
AM_CFLAGS= -g -O3 -Wall -std=gnu99 -fgnu89-inline
AM_LDFLAGS= -lestats  -lcurl -luuid -lconfig $(USE_LIBJSON)
bin_PROGRAMS = xsight
xsight_SOURCES= xsight.c libinflux.c string-funcs.c debug.c parse.c \
                 scripts.h xisght.h string-funcs.h \
		 debug.h uthash.h version.h
