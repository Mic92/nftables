/*
 * Copyright (c) 2008 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Development of this code funded by Astaro AG (http://www.astaro.com/)
 */

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <ctype.h> /* isdigit */
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <linux/netfilter.h>

#include <nftables.h>
#include <datatype.h>
#include <expression.h>
#include <gmputil.h>
#include <erec.h>

static const struct datatype *datatypes[TYPE_MAX + 1] = {
	[TYPE_INVALID]		= &invalid_type,
	[TYPE_VERDICT]		= &verdict_type,
	[TYPE_BITMASK]		= &bitmask_type,
	[TYPE_INTEGER]		= &integer_type,
	[TYPE_STRING]		= &string_type,
	[TYPE_LLADDR]		= &lladdr_type,
	[TYPE_IPADDR]		= &ipaddr_type,
	[TYPE_IP6ADDR]		= &ip6addr_type,
	[TYPE_ETHERADDR]	= &etheraddr_type,
	[TYPE_ETHERTYPE]	= &ethertype_type,
	[TYPE_INET_PROTOCOL]	= &inet_protocol_type,
	[TYPE_INET_SERVICE]	= &inet_service_type,
	[TYPE_TIME]		= &time_type,
	[TYPE_MARK]		= &mark_type,
	[TYPE_ARPHRD]		= &arphrd_type,
};

void datatype_register(const struct datatype *dtype)
{
	datatypes[dtype->type] = dtype;
}

const struct datatype *datatype_lookup(enum datatypes type)
{
	if (type > TYPE_MAX)
		return NULL;
	return datatypes[type];
}

const struct datatype *datatype_lookup_byname(const char *name)
{
	const struct datatype *dtype;
	enum datatypes type;

	for (type = TYPE_INVALID; type <= TYPE_MAX; type++) {
		dtype = datatypes[type];
		if (dtype == NULL)
			continue;
		if (!strcmp(dtype->name, name))
			return dtype;
	}
	return NULL;
}

void datatype_print(const struct expr *expr)
{
	const struct datatype *dtype = expr->dtype;

	do {
		if (dtype->print != NULL)
			return dtype->print(expr);
		if (dtype->sym_tbl != NULL)
			return symbolic_constant_print(dtype->sym_tbl, expr);
	} while ((dtype = dtype->basetype));

	BUG("datatype has no print method or symbol table\n");
}

struct error_record *symbol_parse(const struct expr *sym,
				  struct expr **res)
{
	const struct datatype *dtype = sym->dtype;

	assert(sym->ops->type == EXPR_SYMBOL);

	if (dtype == NULL)
		return error(&sym->location, "No symbol type information");
	do {
		if (dtype->parse != NULL)
			return dtype->parse(sym, res);
		if (dtype->sym_tbl != NULL)
			return symbolic_constant_parse(sym, dtype->sym_tbl,
						       res);
	} while ((dtype = dtype->basetype));

	return error(&sym->location,
		     "Can't parse symbolic %s expressions",
		     sym->dtype->desc);
}

struct error_record *symbolic_constant_parse(const struct expr *sym,
					     const struct symbol_table *tbl,
					     struct expr **res)
{
	const struct symbolic_constant *s;
	const struct datatype *dtype;

	for (s = tbl->symbols; s->identifier != NULL; s++) {
		if (!strcmp(sym->identifier, s->identifier))
			break;
	}

	dtype = sym->dtype;
	if (s->identifier == NULL)
		return error(&sym->location, "Could not parse %s", dtype->desc);

	*res = constant_expr_alloc(&sym->location, dtype,
				   dtype->byteorder, dtype->size,
				   &s->value);
	return NULL;
}

void symbolic_constant_print(const struct symbol_table *tbl,
			     const struct expr *expr)
{
	const struct symbolic_constant *s;

	for (s = tbl->symbols; s->identifier != NULL; s++) {
		if (!mpz_cmp_ui(expr->value, s->value))
			break;
	}

	if (s->identifier == NULL)
		return expr_basetype(expr)->print(expr);

	printf("%s", s->identifier);
}

void symbol_table_print(const struct symbol_table *tbl,
			const struct datatype *dtype)
{
	const struct symbolic_constant *s;
	unsigned int size = 2 * dtype->size / BITS_PER_BYTE;

	for (s = tbl->symbols; s->identifier != NULL; s++)
		printf("\t%-30s\t0x%.*" PRIx64 "\n",
		       s->identifier, size, s->value);
}

static void invalid_type_print(const struct expr *expr)
{
	gmp_printf("0x%Zx [invalid type]", expr->value);
}

const struct datatype invalid_type = {
	.type		= TYPE_INVALID,
	.name		= "invalid",
	.desc		= "invalid",
	.print		= invalid_type_print,
};

static void verdict_type_print(const struct expr *expr)
{
	switch (expr->verdict) {
	case NF_ACCEPT:
		printf("accept");
		break;
	case NF_DROP:
		printf("drop");
		break;
	case NF_QUEUE:
		printf("queue");
		break;
	case NFT_CONTINUE:
		printf("continue");
		break;
	case NFT_BREAK:
		printf("break");
		break;
	case NFT_JUMP:
		printf("jump %s", expr->chain);
		break;
	case NFT_GOTO:
		printf("goto %s", expr->chain);
		break;
	case NFT_RETURN:
		printf("return");
		break;
	default:
		BUG("invalid verdict value %u\n", expr->verdict);
	}
}

const struct datatype verdict_type = {
	.type		= TYPE_VERDICT,
	.name		= "verdict",
	.desc		= "netfilter verdict",
	.print		= verdict_type_print,
};

const struct datatype bitmask_type = {
	.type		= TYPE_BITMASK,
	.name		= "bitmask",
	.desc		= "bitmask",
	.basetype	= &integer_type,
};

static void integer_type_print(const struct expr *expr)
{
	const char *fmt = "%Zu";

	if (expr->dtype->basefmt != NULL)
		fmt = expr->dtype->basefmt;
	gmp_printf(fmt, expr->value);
}

static struct error_record *integer_type_parse(const struct expr *sym,
					       struct expr **res)
{
	mpz_t v;
	int len;

	mpz_init(v);
	if (gmp_sscanf(sym->identifier, "%Zu%n", v, &len) != 1 ||
	    (int)strlen(sym->identifier) != len) {
		mpz_clear(v);
		if (sym->dtype != &integer_type)
			return NULL;
		return error(&sym->location, "Could not parse %s",
			     sym->dtype->desc);
	}

	*res = constant_expr_alloc(&sym->location, sym->dtype,
				   BYTEORDER_HOST_ENDIAN, 1, NULL);
	mpz_set((*res)->value, v);
	mpz_clear(v);
	return NULL;
}

const struct datatype integer_type = {
	.type		= TYPE_INTEGER,
	.name		= "integer",
	.desc		= "integer",
	.print		= integer_type_print,
	.parse		= integer_type_parse,
};

static void string_type_print(const struct expr *expr)
{
	unsigned int len = div_round_up(expr->len, BITS_PER_BYTE);
	char data[len+1];

	mpz_export_data(data, expr->value, BYTEORDER_HOST_ENDIAN, len);
	data[len] = '\0';
	printf("\"%s\"", data);
}

static struct error_record *string_type_parse(const struct expr *sym,
	      				      struct expr **res)
{
	*res = constant_expr_alloc(&sym->location, &string_type,
				   BYTEORDER_HOST_ENDIAN,
				   (strlen(sym->identifier) + 1) * BITS_PER_BYTE,
				   sym->identifier);
	return NULL;
}

const struct datatype string_type = {
	.type		= TYPE_STRING,
	.name		= "string",
	.desc		= "string",
	.print		= string_type_print,
	.parse		= string_type_parse,
};

static void lladdr_type_print(const struct expr *expr)
{
	unsigned int len = div_round_up(expr->len, BITS_PER_BYTE);
	const char *delim = "";
	uint8_t data[len];
	unsigned int i;

	mpz_export_data(data, expr->value, BYTEORDER_HOST_ENDIAN, len);
	for (i = 0; i < len; i++) {
		printf("%s%.2x", delim, data[i]);
		delim = ":";
	}
}

static struct error_record *lladdr_type_parse(const struct expr *sym,
					      struct expr **res)
{
	char buf[strlen(sym->identifier) + 1], *p;
	const char *s = sym->identifier;
	unsigned int len, n;

	for (len = 0;;) {
		n = strtoul(s, &p, 16);
		if (s == p || n > 0xff)
			return erec_create(EREC_ERROR, &sym->location,
					   "Invalid LL address");
		buf[len++] = n;
		if (*p == '\0')
			break;
		s = ++p;
	}

	*res = constant_expr_alloc(&sym->location, sym->dtype,
				   BYTEORDER_HOST_ENDIAN, len * BITS_PER_BYTE,
				   buf);
	return NULL;
}

const struct datatype lladdr_type = {
	.type		= TYPE_LLADDR,
	.name		= "lladdr",
	.desc		= "link layer address",
	.byteorder	= BYTEORDER_HOST_ENDIAN,
	.basetype	= &integer_type,
	.print		= lladdr_type_print,
	.parse		= lladdr_type_parse,
};

static void ipaddr_type_print(const struct expr *expr)
{
	struct sockaddr_in sin = { .sin_family = AF_INET, };
	char buf[NI_MAXHOST];
	int err;

	sin.sin_addr.s_addr = mpz_get_be32(expr->value);
	err = getnameinfo((struct sockaddr *)&sin, sizeof(sin), buf,
			  sizeof(buf), NULL, 0,
			  numeric_output ? NI_NUMERICHOST : 0);
	if (err != 0) {
		getnameinfo((struct sockaddr *)&sin, sizeof(sin), buf,
			    sizeof(buf), NULL, 0, NI_NUMERICHOST);
	}
	printf("%s", buf);
}

static struct error_record *ipaddr_type_parse(const struct expr *sym,
					      struct expr **res)
{
	struct addrinfo *ai, hints = { .ai_family = AF_INET,
				       .ai_socktype = SOCK_DGRAM};
	struct in_addr *addr;
	int err;

	err = getaddrinfo(sym->identifier, NULL, &hints, &ai);
	if (err != 0)
		return error(&sym->location, "Could not resolve hostname: %s",
			     gai_strerror(err));

	if (ai->ai_next != NULL) {
		freeaddrinfo(ai);
		return error(&sym->location,
			     "Hostname resolves to multiple addresses");
	}

	addr = &((struct sockaddr_in *)ai->ai_addr)->sin_addr;
	*res = constant_expr_alloc(&sym->location, &ipaddr_type,
				   BYTEORDER_BIG_ENDIAN,
				   sizeof(*addr) * BITS_PER_BYTE, addr);
	freeaddrinfo(ai);
	return NULL;
}

const struct datatype ipaddr_type = {
	.type		= TYPE_IPADDR,
	.name		= "ipv4_address",
	.desc		= "IPv4 address",
	.byteorder	= BYTEORDER_BIG_ENDIAN,
	.size		= 4 * BITS_PER_BYTE,
	.basetype	= &integer_type,
	.print		= ipaddr_type_print,
	.parse		= ipaddr_type_parse,
	.flags		= DTYPE_F_PREFIX,
};

static void ip6addr_type_print(const struct expr *expr)
{
	struct sockaddr_in6 sin6 = { .sin6_family = AF_INET6 };
	char buf[NI_MAXHOST];
	int err;

	mpz_export_data(&sin6.sin6_addr, expr->value, BYTEORDER_BIG_ENDIAN,
			sizeof(sin6.sin6_addr));

	err = getnameinfo((struct sockaddr *)&sin6, sizeof(sin6), buf,
			  sizeof(buf), NULL, 0,
			  numeric_output ? NI_NUMERICHOST : 0);
	if (err != 0) {
		getnameinfo((struct sockaddr *)&sin6, sizeof(sin6), buf,
			    sizeof(buf), NULL, 0, NI_NUMERICHOST);
	}
	printf("%s", buf);
}

static struct error_record *ip6addr_type_parse(const struct expr *sym,
					       struct expr **res)
{
	struct addrinfo *ai, hints = { .ai_family = AF_INET6,
				       .ai_socktype = SOCK_DGRAM};
	struct in6_addr *addr;
	int err;

	err = getaddrinfo(sym->identifier, NULL, &hints, &ai);
	if (err != 0)
		return error(&sym->location, "Could not resolve hostname: %s",
			     gai_strerror(err));

	if (ai->ai_next != NULL) {
		freeaddrinfo(ai);
		return error(&sym->location,
			     "Hostname resolves to multiple addresses");
	}

	addr = &((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr;
	*res = constant_expr_alloc(&sym->location, &ip6addr_type,
				   BYTEORDER_BIG_ENDIAN,
				   sizeof(*addr) * BITS_PER_BYTE, addr);
	freeaddrinfo(ai);
	return NULL;
}

const struct datatype ip6addr_type = {
	.type		= TYPE_IP6ADDR,
	.name		= "ipv6_address",
	.desc		= "IPv6 address",
	.byteorder	= BYTEORDER_BIG_ENDIAN,
	.size		= 16 * BITS_PER_BYTE,
	.basetype	= &integer_type,
	.print		= ip6addr_type_print,
	.parse		= ip6addr_type_parse,
	.flags		= DTYPE_F_PREFIX,
};

static void inet_protocol_type_print(const struct expr *expr)
{
	struct protoent *p;

	if (numeric_output < NUMERIC_ALL) {
		p = getprotobynumber(mpz_get_uint8(expr->value));
		if (p != NULL) {
			printf("%s", p->p_name);
			return;
		}
	}
	integer_type_print(expr);
}

static struct error_record *inet_protocol_type_parse(const struct expr *sym,
						     struct expr **res)
{
	struct protoent *p;
	uint8_t proto;
	uintmax_t i;
	char *end;

	errno = 0;
	i = strtoumax(sym->identifier, &end, 0);
	if (sym->identifier != end && *end == '\0') {
		if (errno == ERANGE || i > UINT8_MAX)
			return error(&sym->location, "Protocol out of range");

		proto = i;
	} else {
		p = getprotobyname(sym->identifier);
		if (p == NULL)
			return error(&sym->location, "Could not resolve protocol name");

		proto = p->p_proto;
	}

	*res = constant_expr_alloc(&sym->location, &inet_protocol_type,
				   BYTEORDER_HOST_ENDIAN, BITS_PER_BYTE,
				   &proto);
	return NULL;
}

const struct datatype inet_protocol_type = {
	.type		= TYPE_INET_PROTOCOL,
	.name		= "inet_protocol",
	.desc		= "Internet protocol",
	.size		= BITS_PER_BYTE,
	.basetype	= &integer_type,
	.print		= inet_protocol_type_print,
	.parse		= inet_protocol_type_parse,
};

static void inet_service_type_print(const struct expr *expr)
{
	struct sockaddr_in sin = { .sin_family = AF_INET };
	char buf[NI_MAXSERV];
	int err;

	sin.sin_port = mpz_get_be16(expr->value);
	err = getnameinfo((struct sockaddr *)&sin, sizeof(sin), NULL, 0,
			  buf, sizeof(buf),
			  numeric_output < NUMERIC_PORT ? 0 : NI_NUMERICSERV);
	if (err != 0) {
		getnameinfo((struct sockaddr *)&sin, sizeof(sin), NULL,
			    0, buf, sizeof(buf), NI_NUMERICSERV);
	}
	printf("%s", buf);
}

static struct error_record *inet_service_type_parse(const struct expr *sym,
						    struct expr **res)
{
	struct addrinfo *ai;
	uint16_t port;
	uintmax_t i;
	int err;
	char *end;

	errno = 0;
	i = strtoumax(sym->identifier, &end, 0);
	if (sym->identifier != end && *end == '\0') {
		if (errno == ERANGE || i > UINT16_MAX)
			return error(&sym->location, "Service out of range");

		port = htons(i);
	} else {
		err = getaddrinfo(NULL, sym->identifier, NULL, &ai);
		if (err != 0)
			return error(&sym->location, "Could not resolve service: %s",
				     gai_strerror(err));

		port = ((struct sockaddr_in *)ai->ai_addr)->sin_port;
		freeaddrinfo(ai);
	}

	*res = constant_expr_alloc(&sym->location, &inet_service_type,
				   BYTEORDER_BIG_ENDIAN,
				   sizeof(port) * BITS_PER_BYTE, &port);
	return NULL;
}

const struct datatype inet_service_type = {
	.type		= TYPE_INET_SERVICE,
	.name		= "inet_service",
	.desc		= "internet network service",
	.byteorder	= BYTEORDER_BIG_ENDIAN,
	.size		= 2 * BITS_PER_BYTE,
	.basetype	= &integer_type,
	.print		= inet_service_type_print,
	.parse		= inet_service_type_parse,
};

#define RT_SYM_TAB_INITIAL_SIZE		16

struct symbol_table *rt_symbol_table_init(const char *filename)
{
	struct symbolic_constant s;
	struct symbol_table *tbl;
	unsigned int size, nelems, val;
	char buf[512], namebuf[512], *p;
	FILE *f;

	size = RT_SYM_TAB_INITIAL_SIZE;
	tbl = xmalloc(sizeof(*tbl) + size * sizeof(s));
	nelems = 0;

	f = fopen(filename, "r");
	if (f == NULL)
		goto out;

	while (fgets(buf, sizeof(buf), f)) {
		p = buf;
		while (*p == ' ' || *p == '\t')
			p++;
		if (*p == '#' || *p == '\n' || *p == '\0')
			continue;
		if (sscanf(p, "0x%x %511s\n", &val, namebuf) != 2 &&
		    sscanf(p, "0x%x %511s #", &val, namebuf) != 2 &&
		    sscanf(p, "%u %511s\n", &val, namebuf) != 2 &&
		    sscanf(p, "%u %511s #", &val, namebuf) != 2) {
			fprintf(stderr, "iproute database '%s' corrupted\n",
				filename);
			goto out;
		}

		/* One element is reserved for list terminator */
		if (nelems == size - 2) {
			size *= 2;
			tbl = xrealloc(tbl, sizeof(*tbl) + size * sizeof(s));
		}

		tbl->symbols[nelems].identifier = xstrdup(namebuf);
		tbl->symbols[nelems].value = val;
		nelems++;
	}

	fclose(f);
out:
	tbl->symbols[nelems] = SYMBOL_LIST_END;
	return tbl;
}

void rt_symbol_table_free(struct symbol_table *tbl)
{
	const struct symbolic_constant *s;

	for (s = tbl->symbols; s->identifier != NULL; s++)
		xfree(s->identifier);
	xfree(tbl);
}

static struct symbol_table *mark_tbl;
static void __init mark_table_init(void)
{
	mark_tbl = rt_symbol_table_init("/etc/iproute2/rt_marks");
}

static void __exit mark_table_exit(void)
{
	rt_symbol_table_free(mark_tbl);
}

static void mark_type_print(const struct expr *expr)
{
	return symbolic_constant_print(mark_tbl, expr);
}

static struct error_record *mark_type_parse(const struct expr *sym,
					    struct expr **res)
{
	struct error_record *erec;
	const struct symbolic_constant *s;

	for (s = mark_tbl->symbols; s->identifier != NULL; s++) {
		if (!strcmp(sym->identifier, s->identifier)) {
			*res = constant_expr_alloc(&sym->location, sym->dtype,
						   sym->dtype->byteorder,
						   sym->dtype->size,
						   &s->value);
			return NULL;
		}
	}

	*res = NULL;
	erec = sym->dtype->basetype->parse(sym, res);
	if (erec != NULL)
		return erec;
	if (*res)
		return NULL;
	return symbolic_constant_parse(sym, mark_tbl, res);
}

const struct datatype mark_type = {
	.type		= TYPE_MARK,
	.name		= "mark",
	.desc		= "packet mark",
	.size		= 4 * BITS_PER_BYTE,
	.byteorder	= BYTEORDER_HOST_ENDIAN,
	.basetype	= &integer_type,
	.basefmt	= "0x%.8Zx",
	.print		= mark_type_print,
	.parse		= mark_type_parse,
	.flags		= DTYPE_F_PREFIX,
};

static void time_type_print(const struct expr *expr)
{
	uint64_t days, hours, minutes, seconds;

	seconds = mpz_get_uint64(expr->value);

	days = seconds / 86400;
	seconds %= 86400;

	hours = seconds / 3600;
	seconds %= 3600;

	minutes = seconds / 60;
	seconds %= 60;

	printf("\"");

	if (days > 0)
		printf("%"PRIu64"d", days);
	if (hours > 0)
		printf("%"PRIu64"h", hours);
	if (minutes > 0)
		printf("%"PRIu64"m", minutes);
	if (seconds > 0)
		printf("%"PRIu64"s", seconds);

	printf("\"");
}

enum {
	DAY	= (1 << 0),
	HOUR	= (1 << 1),
	MIN 	= (1 << 2),
	SECS	= (1 << 3),
};

static uint32_t str2int(char *tmp, const char *c, int k)
{
	if (k == 0)
		return 0;

	strncpy(tmp, c-k, k+1);
	return atoi(tmp);
}

static struct error_record *time_type_parse(const struct expr *sym,
					    struct expr **res)
{
	int i, len;
	unsigned int k = 0;
	char tmp[8];
	const char *c;
	uint64_t d = 0, h = 0, m = 0, s = 0;
	uint32_t mask = 0;

	c = sym->identifier;
	len = strlen(c);
	for (i = 0; i < len; i++, c++) {
		switch (*c) {
		case 'd':
			if (mask & DAY) {
				return error(&sym->location,
					     "Day has been specified twice");
			}
			d = str2int(tmp, c, k);
			k = 0;
			mask |= DAY;
			break;
		case 'h':
			if (mask & HOUR) {
				return error(&sym->location,
					     "Hour has been specified twice");
			}
			h = str2int(tmp, c, k);
			k = 0;
			if (h > 23) {
				return error(&sym->location,
					     "Hour needs to be 0-23");
			}
			mask |= HOUR;
			break;
		case 'm':
			if (mask & MIN) {
				return error(&sym->location,
					     "Minute has been specified twice");
			}
			m = str2int(tmp, c, k);
			k = 0;
			if (m > 59) {
				return error(&sym->location,
					     "Minute needs to be 0-59");
			}
			mask |= MIN;
			break;
		case 's':
			if (mask & SECS) {
				return error(&sym->location,
					     "Second has been specified twice");
			}
			s = str2int(tmp, c, k);
			k = 0;
			if (s > 59) {
				return error(&sym->location,
					     "second needs to be 0-59");
			}
			mask |= SECS;
			break;
		default:
			if (!isdigit(*c))
				return error(&sym->location, "wrong format");

			if (k++ >= array_size(tmp)) {
				return error(&sym->location,
					     "value too large");
			}
			break;
		}
	}

	/* default to seconds if no unit was specified */
	if (!mask)
		s = atoi(sym->identifier);
	else
		s = 24*60*60*d+60*60*h+60*m+s;

	if (s > UINT32_MAX)
		return error(&sym->location, "value too large");

	*res = constant_expr_alloc(&sym->location, &time_type,
				   BYTEORDER_HOST_ENDIAN,
				   sizeof(uint32_t) * BITS_PER_BYTE, &s);
	return NULL;
}

const struct datatype time_type = {
	.type		= TYPE_TIME,
	.name		= "time",
	.desc		= "relative time",
	.byteorder	= BYTEORDER_HOST_ENDIAN,
	.size		= 8 * BITS_PER_BYTE,
	.basetype	= &integer_type,
	.print		= time_type_print,
	.parse		= time_type_parse,
};

static struct error_record *concat_type_parse(const struct expr *sym,
					      struct expr **res)
{
	return error(&sym->location, "invalid data type, expected %s",
		     sym->dtype->desc);
}

static struct datatype *dtype_alloc(void)
{
	struct datatype *dtype;

	dtype = xzalloc(sizeof(*dtype));
	dtype->flags = DTYPE_F_ALLOC;

	return dtype;
}

const struct datatype *concat_type_alloc(const struct expr *expr)
{
	struct datatype *dtype;
	struct expr *i;
	char desc[256] = "concatenation of (";
	unsigned int type = 0, size = 0;

	list_for_each_entry(i, &expr->expressions, list) {
		if (size != 0)
			strncat(desc, ", ", sizeof(desc) - strlen(desc) - 1);
		strncat(desc, i->dtype->desc, sizeof(desc) - strlen(desc) - 1);

		type <<= 8;
		type  |= i->dtype->type;
		size++;
	}
	strncat(desc, ")", sizeof(desc) - strlen(desc) - 1);

	dtype		= dtype_alloc();
	dtype->type	= type;
	dtype->size	= size;
	dtype->desc	= xstrdup(desc);
	dtype->parse	= concat_type_parse;

	return dtype;
}

void concat_type_destroy(const struct datatype *dtype)
{
	if (dtype->flags & DTYPE_F_ALLOC)
		xfree(dtype);
}
