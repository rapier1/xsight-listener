#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT(insight, 0.1, rapier@psc.edu)
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([./])
AC_CONFIG_HEADERS([config.h])

LDFLAGS="$LDFLAGS"

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_SEARCH_LIBS([estats_read_vars], [estats], [], [
	echo "libestats (from Web10g) is missing."
        exit -1])
AC_SEARCH_LIBS([curl_easy_init], [curl], [], [
	echo "libcurl is missing."
        exit -1])
AC_SEARCH_LIBS([config_init], [config], [], [
	echo "libconfig is missing."
        exit -1])
AC_SEARCH_LIBS([uuid_generate], [uuid], [], [
	echo "libuuid is missing."
        exit -1])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h inttypes.h netinet/in.h stddef.h stdint.h stdlib.h string.h sys/param.h sys/socket.h unistd.h])
AC_CHECK_HEADERS([uuid/uuid.h estats/estats.h curl/curl.h libconfig.h netdb.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_UID_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T
AC_CHECK_TYPES([ptrdiff_t])

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memmove memset strchr strdup strstr])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
