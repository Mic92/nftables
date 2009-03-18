/*
 * Meta expression/statement related definition and types.
 *
 * Copyright (c) 2008 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Development of this code funded by Astaro AG (http://www.astaro.com/)
 */

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <net/if_arp.h>
#include <pwd.h>
#include <grp.h>
#include <netlink/route/link.h>
#include <netlink/route/tc.h>

#include <nftables.h>
#include <expression.h>
#include <statement.h>
#include <datatype.h>
#include <meta.h>
#include <gmputil.h>
#include <utils.h>
#include <erec.h>

static struct symbol_table *realm_tbl;
static void __init realm_table_init(void)
{
	realm_tbl = rt_symbol_table_init("/etc/iproute2/rt_realms");
}

static void __exit realm_table_exit(void)
{
	rt_symbol_table_free(realm_tbl);
}

static void realm_type_print(const struct expr *expr)
{
	return symbolic_constant_print(realm_tbl, expr);
}

static struct error_record *realm_type_parse(const struct expr *sym,
					     struct expr **res)
{
	return symbolic_constant_parse(sym, realm_tbl, res);
}

static const struct datatype realm_type = {
	.type		= TYPE_REALM,
	.name		= "routing realm",
	.basetype	= &integer_type,
	.print		= realm_type_print,
	.parse		= realm_type_parse,
};

static void tchandle_type_print(const struct expr *expr)
{
	char buf[sizeof("ffff:ffff")];

	printf("%s", rtnl_tc_handle2str(mpz_get_uint32(expr->value),
					buf, sizeof(buf)));
}

static struct error_record *tchandle_type_parse(const struct expr *sym,
						struct expr **res)
{
	uint32_t handle;

	if (rtnl_tc_str2handle(sym->identifier, &handle) < 0)
		return error(&sym->location, "Could not parse %s",
			     sym->sym_type->name);

	*res = constant_expr_alloc(&sym->location, sym->sym_type,
				   BYTEORDER_HOST_ENDIAN,
				   sizeof(handle) * BITS_PER_BYTE, &handle);
	return NULL;
}

static const struct datatype tchandle_type = {
	.type		= TYPE_TC_HANDLE,
	.name		= "TC handle",
	.basetype	= &integer_type,
	.print		= tchandle_type_print,
	.parse		= tchandle_type_parse,
};

static struct nl_cache *link_cache;

static int link_cache_init(void)
{
	struct nl_sock *rt_sock;
	int err;

	rt_sock = nl_socket_alloc();
	if (rt_sock == NULL)
		memory_allocation_error();

	err = nl_connect(rt_sock, NETLINK_ROUTE);
	if (err < 0)
		goto err;
	err = rtnl_link_alloc_cache(rt_sock, &link_cache);
	if (err < 0)
		goto err;
	nl_cache_mngt_provide(link_cache);
	nl_socket_free(rt_sock);
	return 0;

err:
	nl_socket_free(rt_sock);
	return err;
}

static void ifindex_type_print(const struct expr *expr)
{
	char name[IFNAMSIZ];
	int ifindex;

	if (link_cache == NULL)
		link_cache_init();

	ifindex = mpz_get_uint32(expr->value);
	if (link_cache != NULL &&
	    rtnl_link_i2name(link_cache, ifindex, name, sizeof(name)))
		printf("%s", name);
	else
		printf("%d", ifindex);
}

static struct error_record *ifindex_type_parse(const struct expr *sym,
					       struct expr **res)
{
	int ifindex, err;

	if (link_cache == NULL &&
	    (err = link_cache_init()) < 0)
		return error(&sym->location,
			     "Could not initialize link cache: %s",
			     nl_geterror(err));

	ifindex = rtnl_link_name2i(link_cache, sym->identifier);
	if (ifindex == 0)
		return error(&sym->location, "Interface does not exist");

	*res = constant_expr_alloc(&sym->location, sym->sym_type,
				   BYTEORDER_HOST_ENDIAN,
				   sizeof(ifindex) * BITS_PER_BYTE, &ifindex);
	return NULL;
}

static void __exit ifindex_table_free(void)
{
	nl_cache_free(link_cache);
}

static const struct datatype ifindex_type = {
	.type		= TYPE_IFINDEX,
	.name		= "interface index",
	.basetype	= &integer_type,
	.print		= ifindex_type_print,
	.parse		= ifindex_type_parse,
};

static const struct symbol_table arphrd_tbl = {
	.byteorder	= BYTEORDER_HOST_ENDIAN,
	.size		= 2 * BITS_PER_BYTE,
	.symbols	= {
		SYMBOL("ether",		ARPHRD_ETHER),
		SYMBOL("ppp",		ARPHRD_PPP),
		/* dummy types */
		SYMBOL("ipip",		ARPHRD_TUNNEL),
		SYMBOL("ipip6",		ARPHRD_TUNNEL6),
		SYMBOL("loopback",	ARPHRD_LOOPBACK),
		SYMBOL("sit",		ARPHRD_SIT),
		SYMBOL("ipgre",		ARPHRD_IPGRE),
		SYMBOL_LIST_END,
	},
};

const struct datatype arphrd_type = {
	.type		= TYPE_ARPHRD,
	.name		= "hardware type",
	.basetype	= &integer_type,
	.sym_tbl	= &arphrd_tbl,
};

static void uid_type_print(const struct expr *expr)
{
	struct passwd *pw;

	if (numeric_output < NUMERIC_ALL) {
		pw = getpwuid(mpz_get_uint32(expr->value));
		if (pw != NULL) {
			printf("%s", pw->pw_name);
			return;
		}
	}
	expr_basetype(expr)->print(expr);
}

static struct error_record *uid_type_parse(const struct expr *sym,
					   struct expr **res)
{
	struct passwd *pw;

	pw = getpwnam(sym->identifier);
	if (pw == NULL)
		return error(&sym->location, "User does not exist");

	*res = constant_expr_alloc(&sym->location, sym->sym_type,
				   BYTEORDER_HOST_ENDIAN,
				   sizeof(pw->pw_uid) * BITS_PER_BYTE,
				   &pw->pw_uid);
	return NULL;
}

static const struct datatype uid_type = {
	.type		= TYPE_UID,
	.name		= "user ID",
	.basetype	= &integer_type,
	.print		= uid_type_print,
	.parse		= uid_type_parse,
};

static void gid_type_print(const struct expr *expr)
{
	struct group *gr;

	if (numeric_output < NUMERIC_ALL) {
		gr = getgrgid(mpz_get_uint32(expr->value));
		if (gr != NULL) {
			printf("%s", gr->gr_name);
			return;
		}
	}
	expr_basetype(expr)->print(expr);
}

static struct error_record *gid_type_parse(const struct expr *sym,
					   struct expr **res)
{
	struct group *gr;

	gr = getgrnam(sym->identifier);
	if (gr == NULL)
		return error(&sym->location, "Group does not exist");

	*res = constant_expr_alloc(&sym->location, sym->sym_type,
				   BYTEORDER_HOST_ENDIAN,
				   sizeof(gr->gr_gid) * BITS_PER_BYTE,
				   &gr->gr_gid);
	return NULL;
}

static const struct datatype gid_type = {
	.type		= TYPE_GID,
	.name		= "group ID",
	.basetype	= &integer_type,
	.print		= gid_type_print,
	.parse		= gid_type_parse,
};

static const struct meta_template meta_templates[] = {
	[NFT_META_LEN]		= META_TEMPLATE("len",       &integer_type,
						4 * 8, BYTEORDER_HOST_ENDIAN),
	[NFT_META_PROTOCOL]	= META_TEMPLATE("protocol",  &ethertype_type,
						2 * 8, BYTEORDER_BIG_ENDIAN),
	[NFT_META_PRIORITY]	= META_TEMPLATE("priority",  &tchandle_type,
						4 * 8, BYTEORDER_HOST_ENDIAN),
	[NFT_META_MARK]		= META_TEMPLATE("mark",      &mark_type,
						4 * 8, BYTEORDER_HOST_ENDIAN),
	[NFT_META_IIF]		= META_TEMPLATE("iif",       &ifindex_type,
						4 * 8, BYTEORDER_HOST_ENDIAN),
	[NFT_META_IIFNAME]	= META_TEMPLATE("iifname",   &string_type,
						IFNAMSIZ * BITS_PER_BYTE,
						BYTEORDER_INVALID),
	[NFT_META_IIFTYPE]	= META_TEMPLATE("iiftype",   &arphrd_type,
						2 * 8, BYTEORDER_HOST_ENDIAN),
	[NFT_META_OIF]		= META_TEMPLATE("oif",	     &ifindex_type,
						4 * 8, BYTEORDER_HOST_ENDIAN),
	[NFT_META_OIFNAME]	= META_TEMPLATE("oifname",   &string_type,
						IFNAMSIZ * BITS_PER_BYTE,
						BYTEORDER_INVALID),
	[NFT_META_OIFTYPE]	= META_TEMPLATE("oiftype",   &arphrd_type,
						2 * 8, BYTEORDER_HOST_ENDIAN),
	[NFT_META_SKUID]	= META_TEMPLATE("skuid",     &uid_type,
						4 * 8, BYTEORDER_HOST_ENDIAN),
	[NFT_META_SKGID]	= META_TEMPLATE("skgid",     &gid_type,
						4 * 8, BYTEORDER_HOST_ENDIAN),
	[NFT_META_NFTRACE]	= META_TEMPLATE("nftrace",   &integer_type,
						1    , BYTEORDER_HOST_ENDIAN),
	[NFT_META_RTCLASSID]	= META_TEMPLATE("rtclassid", &realm_type,
						4 * 8, BYTEORDER_HOST_ENDIAN),
	[NFT_META_SECMARK]	= META_TEMPLATE("secmark",   &integer_type,
						4 * 8, BYTEORDER_HOST_ENDIAN),
};

static void meta_expr_print(const struct expr *expr)
{
	printf("meta %s", meta_templates[expr->meta.key].token);
}

static const struct expr_ops meta_expr_ops = {
	.type		= EXPR_META,
	.name		= "meta",
	.print		= meta_expr_print,
};

struct expr *meta_expr_alloc(const struct location *loc, enum nft_meta_keys key)
{
	const struct meta_template *tmpl = &meta_templates[key];
	struct expr *expr;

	expr = expr_alloc(loc, &meta_expr_ops, tmpl->dtype,
			  tmpl->byteorder, tmpl->len);
	expr->meta.key = key;
	return expr;
}

static void meta_stmt_print(const struct stmt *stmt)
{
	printf("meta %s set ", meta_templates[stmt->meta.key].token);
	expr_print(stmt->meta.expr);
}

static const struct stmt_ops meta_stmt_ops = {
	.type		= STMT_META,
	.name		= "meta",
	.print		= meta_stmt_print,
};

struct stmt *meta_stmt_alloc(const struct location *loc, enum nft_meta_keys key,
			     struct expr *expr)
{
	struct stmt *stmt;

	stmt = stmt_alloc(loc, &meta_stmt_ops);
	stmt->meta.key	= key;
	stmt->meta.tmpl	= &meta_templates[key];
	stmt->meta.expr	= expr;
	return stmt;
}
