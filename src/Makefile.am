sbin_PROGRAMS = nft

CLEANFILES = scanner.c parser_bison.c

AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CPPFLAGS += -DDEFAULT_INCLUDE_PATH="\"${sysconfdir}\"" -DDEBUG \
		${LIBMNL_CFLAGS} ${LIBNFTNL_CFLAGS}

AM_CFLAGS = -Wall								\
	    -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations	\
	    -Wdeclaration-after-statement -Wsign-compare -Winit-self		\
	    -Wformat-nonliteral -Wformat-security -Wmissing-format-attribute	\
	    -Wcast-align -Wundef -Wbad-function-cast
	    -Waggregate-return -Wunused -Wwrite-strings


AM_YFLAGS = -d

# yacc and lex generate dirty code
parser_bison.o scanner.o: AM_CFLAGS += -Wno-missing-prototypes -Wno-missing-declarations -Wno-implicit-function-declaration -Wno-nested-externs -Wno-undef -Wno-redundant-decls

BUILT_SOURCES = parser_bison.h

nft_SOURCES =	main.c				\
		rule.c				\
		statement.c			\
		datatype.c			\
		expression.c			\
		evaluate.c			\
		proto.c				\
		payload.c			\
		exthdr.c			\
		meta.c				\
		ct.c				\
		netlink.c			\
		netlink_linearize.c		\
		netlink_delinearize.c		\
		segtree.c			\
		rbtree.c			\
		gmputil.c			\
		utils.c				\
		erec.c				\
		mnl.c				\
		scanner.l			\
		parser_bison.y

if BUILD_CLI
nft_SOURCES +=	cli.c
endif

nft_LDADD	= ${LIBMNL_LIBS} ${LIBNFTNL_LIBS}
