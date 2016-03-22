#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT(xsight, 0.9, rapier@psc.edu)
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([./])
AC_CONFIG_HEADERS([config.h])

AC_ARG_ENABLE([clang],
	[AS_HELP_STRING([--enable-clang],[use clang instead of gcc as C compiler.])])

#Use C99 compilation mode
if test "x$enable_clang" = "xyes"; then
    	# clang uses c99 mode by default, so we just set CC to clang and we are done
    	CC="clang";
fi


AC_ARG_ENABLE(debug,
AS_HELP_STRING([--enable-debug],
               [enable debugging, default: no]),
[case "${enableval}" in
             yes) debug=true ;;
             no)  debug=false ;;
             *)   AC_MSG_ERROR([bad value ${enableval} for --enable-debug]) ;;
esac],
[debug=false])

AM_CONDITIONAL(DEBUG, test x"$debug" = x"true")

LDFLAGS="$LDFLAGS"
CFLAGS="$CFLAGS"

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_SEARCH_LIBS([pthread_create], [pthread], [], [
	echo "libpthreads is missing."
	exit -1])
AC_SEARCH_LIBS([estats_read_vars], [estats], [], [
	echo "libestats (from Web10g) is missing."
        exit -1])
AC_SEARCH_LIBS([curl_easy_init], [curl], [], [
	echo "libcurl is missing."
        exit -1])
AC_SEARCH_LIBS([config_init], [config], [], [
	echo "libconfig is missing."
        exit -1])
AC_SEARCH_LIBS([SHA256_Init], [crypto], [], [
	echo "SHA256 functions not found. Install libssl or make sure SHA256 functions are compiled into library."
        exit -1])
AC_SEARCH_LIBS([json_tokener_parse_ex], [json-c json], [], [
        echo "JSON-C (fedoa) and/or LibJson (debian) library ) is missing."
        exit -1])
AC_CHECK_LIB([json-c], [json_tokener_parse_ex], [LIBJSONC=true], [], [])
AM_CONDITIONAL([LINK_LIBJSONC], [test x$LIBJSONC = xtrue])
AC_CHECK_LIB([json], [json_tokener_parse_ex], [LIBJSON=true], [], [])
AM_CONDITIONAL([LINK_LIBJSON], [test x$LIBJSON = xtrue])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h inttypes.h netinet/in.h stddef.h stdint.h stdlib.h string.h sys/param.h sys/socket.h unistd.h])
AC_CHECK_HEADERS([libssl/sha.h estats/estats.h curl/curl.h libconfig.h netdb.h pthreads.h])

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
