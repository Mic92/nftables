#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)

AC_COPYRIGHT([Copyright (c) 2008 Patrick McHardy <kaber@trash.net>])
AC_INIT([nftables], [0.100], [netfilter-devel@vger.kernel.org])
AC_DEFINE([RELEASE_NAME], ["keith-alexander-filter"], [Release name])

AC_CONFIG_SRCDIR([src/rule.c])
AC_CONFIG_HEADER([config.h])

AC_DEFINE([_GNU_SOURCE], [], [Enable various GNU extensions])
AC_DEFINE([_STDC_FORMAT_MACROS], [], [printf-style format macros])

AC_ARG_ENABLE([debug],
	      AS_HELP_STRING([--enable-debug], [Enable debugging]),
	      [CONFIG_DEBUG="$(echo $enableval | cut -b1)"],
	      [CONFIG_DEBUG="y"])
AC_SUBST([CONFIG_DEBUG])

# Checks for programs.
AC_PROG_CC
AC_PROG_MKDIR_P
AC_PROG_INSTALL
AC_PROG_SED

AC_CHECK_PROG(CONFIG_MAN, docbook2x-man, y, n)
if test "$CONFIG_MAN" != "y"
then
	AC_MSG_WARN([docbookx2-man not found, no manpages will be built])
fi

AC_CHECK_PROG(CONFIG_PDF, db2pdf, y, n)
if test "$CONFIG_PDF" != "y"
then
	AC_MSG_WARN([db2pdf not found, no PDF manpages will be built])
fi

AC_PATH_PROG(LEX, [flex])
if test -z "$LEX"
then
	AC_MSG_ERROR([No suitable version of flex found])
fi

AC_PATH_PROG(YACC, [bison])
if test -z "$YACC"
then
	AC_MSG_ERROR([No suitable version of bison found])
fi

# Checks for libraries.
AC_CHECK_LIB([mnl], [mnl_socket_open], ,
	     AC_MSG_ERROR([No suitable version of libmnl found]))

AC_CHECK_LIB([nftnl], [nft_rule_alloc], ,
	     AC_MSG_ERROR([No suitable version of libnftnl found]))

AC_CHECK_LIB([gmp], [__gmpz_init], ,
	     AC_MSG_ERROR([No suitable version of libgmp found]))

AC_CHECK_LIB([readline], [readline], ,
	     AC_MSG_ERROR([No suitable version of libreadline found]))

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_ASSERT
AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h libintl.h limits.h malloc.h \
		  netdb.h netinet/in.h netinet/ip.h netinet/ip6.h \
		  netinet/tcp.h netinet/udp.h netinet/ip_icmp.h \
		  stddef.h stdint.h stdlib.h string.h unistd.h], ,
		 AC_MSG_ERROR([Header file not found]))

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_CONST
AC_C_INLINE
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_TYPE_UID_T
AC_TYPE_INT8_T
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([memmove memset strchr strdup strerror strtoull])

AC_CONFIG_FILES([Makefile Makefile.defs Makefile.rules])
AC_CONFIG_FILES([src/Makefile doc/Makefile files/Makefile])
AC_OUTPUT
