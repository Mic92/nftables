#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)

AC_COPYRIGHT([Copyright (c) 2008 Patrick McHardy <kaber@trash.net>])
AC_INIT([nftables], [0.4], [netfilter-devel@vger.kernel.org])
AC_DEFINE([RELEASE_NAME], ["Support Edward Snowden"], [Release name])

AC_CONFIG_AUX_DIR([build-aux])
AC_CANONICAL_HOST
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([-Wall foreign subdir-objects
        tar-pax no-dist-gzip dist-bzip2 1.6])

dnl kernel style compile messages
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_CONFIG_SRCDIR([src/rule.c])
AC_CONFIG_HEADER([config.h])

AC_DEFINE([_GNU_SOURCE], [], [Enable various GNU extensions])
AC_DEFINE([_STDC_FORMAT_MACROS], [], [printf-style format macros])

AC_ARG_ENABLE([debug],
	      AS_HELP_STRING([--enable-debug], [Enable debugging]),
	      [with_debug=no],
	      [with_debug=yes])
AC_SUBST(with_debug)
AM_CONDITIONAL([BUILD_DEBUG], [test "x$with_debug" != xno])

# Checks for programs.
AC_PROG_CC
AC_PROG_MKDIR_P
AC_PROG_INSTALL
AC_PROG_SED
AM_PROG_LEX
AC_PROG_YACC

if test -z "$ac_cv_prog_YACC"
then
        echo "*** Error: No suitable bison/yacc found. ***"
        echo "    Please install the 'bison' package."
        exit 1
fi
if test -z "$ac_cv_prog_LEX"
then
        echo "*** Error: No suitable flex/lex found. ***"
        echo "    Please install the 'flex' package."
        exit 1
fi

AC_CHECK_PROG(DOCBOOK2X_MAN, [docbook2x-man], [docbook2x-man], [no])
AC_CHECK_PROG(DOCBOOK2MAN, [docbook2man], [docbook2man], [no])
AC_CHECK_PROG(DB2X_DOCBOOK2MAN, [db2x_docbook2man], [db2x_docbook2man], [no])
AS_IF([test "$DOCBOOK2X_MAN" != "no"], [DB2MAN="$DOCBOOK2X_MAN"],
	[AS_IF([test "$DOCBOOK2MAN" != "no"], [DB2MAN="$DOCBOOK2MAN"],
		[AS_IF([test "$DB2X_DOCBOOK2MAN" != "no"], [DB2MAN="$DB2X_DOCBOOK2MAN"],
			[AC_MSG_WARN([docbookx2-man/db2x_docbook2man not found, no manpages will be built])]
		)]
	)]
)
AC_SUBST(DB2MAN)
AM_CONDITIONAL([BUILD_MAN], [test -n "$DB2MAN"])

AC_CHECK_PROG(DBLATEX, [dblatex], [found], [no])
AS_IF([test "$DBLATEX" == "no"],
	[AC_MSG_WARN([dblatex not found, no PDF manpages will be built])]
)
AM_CONDITIONAL([BUILD_PDF], [test "$DBLATEX" == "found"])

# Checks for libraries.
PKG_CHECK_MODULES([LIBMNL], [libmnl >= 1.0.3])
PKG_CHECK_MODULES([LIBNFTNL], [libnftnl >= 1.0.2])

AC_ARG_WITH([mini-gmp], [AS_HELP_STRING([--with-mini-gmp],
            [Use builtin mini-gmp (for embedded builds)])], [],
            [with_mini_gmp=no])
AS_IF([test "x$with_mini_gmp" != xyes], [
AC_CHECK_LIB([gmp],[__gmpz_init], , AC_MSG_ERROR([No suitable version of libgmp found]))
])
AM_CONDITIONAL([BUILD_MINIGMP], [test "x$with_mini_gmp" == xyes])

AC_ARG_WITH([cli], [AS_HELP_STRING([--without-cli],
            [disable interactive CLI (libreadline support)])],
            [], [with_cli=yes])
AS_IF([test "x$with_cli" != xno], [
AC_CHECK_LIB([readline], [readline], ,
	     AC_MSG_ERROR([No suitable version of libreadline found]))
AC_DEFINE([HAVE_LIBREADLINE], [1], [])
])
AC_SUBST(with_cli)
AM_CONDITIONAL([BUILD_CLI], [test "x$with_cli" != xno])

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_ASSERT
AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h limits.h malloc.h \
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
AC_CHECK_FUNCS([memmove memset strchr strdup strerror strtoull])

AC_CONFIG_FILES([					\
		Makefile				\
		src/Makefile				\
		include/Makefile			\
		include/linux/Makefile			\
		include/linux/netfilter/Makefile	\
		doc/Makefile				\
		files/Makefile				\
		files/nftables/Makefile			\
		])
AC_OUTPUT

echo "
nft configuration:
  cli support:			${with_cli}
  enable debugging:		${with_debug}
  use mini-gmp:			${with_mini_gmp}"
