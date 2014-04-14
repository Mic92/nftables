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
#include <string.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <pwd.h>
#include <grp.h>
#include <linux/pkt_sched.h>

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
	.name		= "realm",
	.desc		= "routing realm",
	.byteorder	= BYTEORDER_HOST_ENDIAN,
	.size		= 4 * BITS_PER_BYTE,
	.basetype	= &integer_type,
	.print		= realm_type_print,
	.parse		= realm_type_parse,
	.flags		= DTYPE_F_PREFIX,
};

static void tchandle_type_print(const struct expr *expr)
{
	uint32_t handle = mpz_get_uint32(expr->value);

	switch(handle) {
	case TC_H_ROOT:
		printf("root\n");
	case TC_H_UNSPEC:
		printf("none\n");
	default:
		if (TC_H_MAJ(handle) == 0)
			printf(":%04x", TC_H_MIN(handle));
		else if (TC_H_MIN(handle) == 0)
			printf("%04x:", TC_H_MAJ(handle) >> 16);
		else {
			printf("%04x:%04x",
			       TC_H_MAJ(handle) >> 16, TC_H_MIN(handle));
		}
		break;
	}
}

static struct error_record *tchandle_type_parse(const struct expr *sym,
						struct expr **res)
{
	uint32_t handle;

	if (strcmp(sym->identifier, "root") == 0)
		handle = TC_H_ROOT;
	else if (strcmp(sym->identifier, "none") == 0)
		handle = TC_H_UNSPEC;
	else if (sym->identifier[0] == ':') {
		if (sscanf(sym->identifier, ":%04x", &handle) < 0)
			goto err;
	} else if (sym->identifier[strlen(sym->identifier)-1] == ':') {
		if (sscanf(sym->identifier, "%04x:", &handle) < 0)
			goto err;

		handle <<= 16;
	} else {
		uint32_t min, max;

		if (sscanf(sym->identifier, "%04x:%04x", &min, &max) < 0)
			goto err;

		handle = max << 16 | min;
	}
	*res = constant_expr_alloc(&sym->location, sym->dtype,
				   BYTEORDER_HOST_ENDIAN,
				   sizeof(handle) * BITS_PER_BYTE, &handle);
	return NULL;
err:
	return error(&sym->location, "Could not parse %s",
		     sym->dtype->desc);
}

static const struct datatype tchandle_type = {
	.type		= TYPE_TC_HANDLE,
	.name		= "tc_handle",
	.desc		= "TC handle",
	.byteorder	= BYTEORDER_BIG_ENDIAN,
	.size		= 4 * BITS_PER_BYTE,
	.basetype	= &integer_type,
	.print		= tchandle_type_print,
	.parse		= tchandle_type_parse,
};

static void ifindex_type_print(const struct expr *expr)
{
	char name[IFNAMSIZ];
	int ifindex;

	ifindex = mpz_get_uint32(expr->value);
	if (if_indextoname(ifindex, name))
		printf("%s", name);
	else
		printf("%d", ifindex);
}

static struct error_record *ifindex_type_parse(const struct expr *sym,
					       struct expr **res)
{
	int ifindex;

	ifindex = if_nametoindex(sym->identifier);
	if (ifindex == 0)
		return error(&sym->location, "Interface does not exist");

	*res = constant_expr_alloc(&sym->location, sym->dtype,
				   BYTEORDER_HOST_ENDIAN,
				   sizeof(ifindex) * BITS_PER_BYTE, &ifindex);
	return NULL;
}

static const struct datatype ifindex_type = {
	.type		= TYPE_IFINDEX,
	.name		= "iface_index",
	.desc		= "network interface index",
	.byteorder	= BYTEORDER_HOST_ENDIAN,
	.size		= 4 * BITS_PER_BYTE,
	.basetype	= &integer_type,
	.print		= ifindex_type_print,
	.parse		= ifindex_type_parse,
};

static const struct symbol_table arphrd_tbl = {
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
	.name		= "iface_type",
	.desc		= "network interface type",
	.byteorder	= BYTEORDER_HOST_ENDIAN,
	.size		= 2 * BITS_PER_BYTE,
	.basetype	= &integer_type,
	.sym_tbl	= &arphrd_tbl,
};

static void uid_type_print(const struct expr *expr)
{
	struct passwd *pw;

	if (numeric_output < NUMERIC_ALL) {
		uint32_t uid = mpz_get_uint32(expr->value);

		pw = getpwuid(uid);
		if (pw != NULL)
			printf("%s", pw->pw_name);
		else
			printf("%d", uid);
		return;
	}
	expr_basetype(expr)->print(expr);
}

static struct error_record *uid_type_parse(const struct expr *sym,
					   struct expr **res)
{
	struct passwd *pw;
	uint64_t uid;
	char *endptr = NULL;

	pw = getpwnam(sym->identifier);
	if (pw != NULL)
		uid = pw->pw_uid;
	else {
		uid = strtoull(sym->identifier, &endptr, 10);
		if (uid > UINT32_MAX)
			return error(&sym->location, "Value too large");
		else if (*endptr)
			return error(&sym->location, "User does not exist");
	}

	*res = constant_expr_alloc(&sym->location, sym->dtype,
				   BYTEORDER_HOST_ENDIAN,
				   sizeof(pw->pw_uid) * BITS_PER_BYTE, &uid);
	return NULL;
}

static const struct datatype uid_type = {
	.type		= TYPE_UID,
	.name		= "uid",
	.desc		= "user ID",
	.byteorder	= BYTEORDER_HOST_ENDIAN,
	.size		= sizeof(uid_t) * BITS_PER_BYTE,
	.basetype	= &integer_type,
	.print		= uid_type_print,
	.parse		= uid_type_parse,
};

static void gid_type_print(const struct expr *expr)
{
	struct group *gr;

	if (numeric_output < NUMERIC_ALL) {
		uint32_t gid = mpz_get_uint32(expr->value);

		gr = getgrgid(gid);
		if (gr != NULL)
			printf("%s", gr->gr_name);
		else
			printf("%u", gid);
		return;
	}
	expr_basetype(expr)->print(expr);
}

static struct error_record *gid_type_parse(const struct expr *sym,
					   struct expr **res)
{
	struct group *gr;
	uint64_t gid;
	char *endptr = NULL;

	gr = getgrnam(sym->identifier);
	if (gr != NULL)
		gid = gr->gr_gid;
	else {
		gid = strtoull(sym->identifier, &endptr, 0);
		if (gid > UINT32_MAX)
			return error(&sym->location, "Value too large");
		else if (*endptr)
			return error(&sym->location, "Group does not exist");
	}

	*res = constant_expr_alloc(&sym->location, sym->dtype,
				   BYTEORDER_HOST_ENDIAN,
				   sizeof(gr->gr_gid) * BITS_PER_BYTE, &gid);
	return NULL;
}

static const struct datatype gid_type = {
	.type		= TYPE_GID,
	.name		= "gid",
	.desc		= "group ID",
	.byteorder	= BYTEORDER_HOST_ENDIAN,
	.size		= sizeof(gid_t) * BITS_PER_BYTE,
	.basetype	= &integer_type,
	.print		= gid_type_print,
	.parse		= gid_type_parse,
};

static const struct meta_template meta_templates[] = {
	[NFT_META_LEN]		= META_TEMPLATE("length",    &integer_type,
						4 * 8, BYTEORDER_HOST_ENDIAN),
	[NFT_META_PROTOCOL]	= META_TEMPLATE("protocol",  &ethertype_type,
						2 * 8, BYTEORDER_BIG_ENDIAN),
	[NFT_META_NFPROTO]	= META_TEMPLATE("nfproto",   &nfproto_type,
						1 * 8, BYTEORDER_HOST_ENDIAN),
	[NFT_META_L4PROTO]	= META_TEMPLATE("l4proto",   &inet_protocol_type,
						1 * 8, BYTEORDER_HOST_ENDIAN),
	[NFT_META_PRIORITY]	= META_TEMPLATE("priority",  &tchandle_type,
						4 * 8, BYTEORDER_HOST_ENDIAN),
	[NFT_META_MARK]		= META_TEMPLATE("mark",      &mark_type,
						4 * 8, BYTEORDER_HOST_ENDIAN),
	[NFT_META_IIF]		= META_TEMPLATE("iif",       &ifindex_type,
						4 * 8, BYTEORDER_HOST_ENDIAN),
	[NFT_META_IIFNAME]	= META_TEMPLATE("iifname",   &string_type,
						IFNAMSIZ * BITS_PER_BYTE,
						BYTEORDER_HOST_ENDIAN),
	[NFT_META_IIFTYPE]	= META_TEMPLATE("iiftype",   &arphrd_type,
						2 * 8, BYTEORDER_HOST_ENDIAN),
	[NFT_META_OIF]		= META_TEMPLATE("oif",	     &ifindex_type,
						4 * 8, BYTEORDER_HOST_ENDIAN),
	[NFT_META_OIFNAME]	= META_TEMPLATE("oifname",   &string_type,
						IFNAMSIZ * BITS_PER_BYTE,
						BYTEORDER_HOST_ENDIAN),
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
	[NFT_META_BRI_IIFNAME]	= META_TEMPLATE("ibriport",  &string_type,
						IFNAMSIZ * BITS_PER_BYTE,
						BYTEORDER_HOST_ENDIAN),
	[NFT_META_BRI_OIFNAME]	= META_TEMPLATE("obriport",  &string_type,
						IFNAMSIZ * BITS_PER_BYTE,
						BYTEORDER_HOST_ENDIAN),
};

static void meta_expr_print(const struct expr *expr)
{
	switch (expr->meta.key) {
	case NFT_META_LEN:
	case NFT_META_NFPROTO:
	case NFT_META_L4PROTO:
	case NFT_META_PROTOCOL:
	case NFT_META_PRIORITY:
		printf("meta %s", meta_templates[expr->meta.key].token);
		break;
	default:
		printf("%s", meta_templates[expr->meta.key].token);
		break;
	}
}

static bool meta_expr_cmp(const struct expr *e1, const struct expr *e2)
{
	return e1->meta.key == e2->meta.key;
}

static void meta_expr_clone(struct expr *new, const struct expr *expr)
{
	new->meta.key = expr->meta.key;
}

/**
 * meta_expr_pctx_update - update protocol context based on meta match
 *
 * @ctx:	protocol context
 * @expr:	relational meta expression
 *
 * Update LL protocol context based on IIFTYPE meta match in non-LL hooks.
 */
static void meta_expr_pctx_update(struct proto_ctx *ctx,
				  const struct expr *expr)
{
	const struct hook_proto_desc *h = &hook_proto_desc[ctx->family];
	const struct expr *left = expr->left, *right = expr->right;
	const struct proto_desc *desc;

	assert(expr->op == OP_EQ);

	switch (left->meta.key) {
	case NFT_META_IIFTYPE:
		if (h->base < PROTO_BASE_NETWORK_HDR)
			return;

		desc = proto_dev_desc(mpz_get_uint16(right->value));
		if (desc == NULL)
			desc = &proto_unknown;

		proto_ctx_update(ctx, PROTO_BASE_LL_HDR, &expr->location, desc);
		break;
	case NFT_META_NFPROTO:
		desc = proto_find_upper(h->desc, mpz_get_uint8(right->value));
		if (desc == NULL)
			desc = &proto_unknown;

		proto_ctx_update(ctx, PROTO_BASE_NETWORK_HDR, &expr->location, desc);
		break;
	case NFT_META_L4PROTO:
		desc = proto_find_upper(&proto_inet_service,
					mpz_get_uint8(right->value));
		if (desc == NULL)
			desc = &proto_unknown;

		proto_ctx_update(ctx, PROTO_BASE_TRANSPORT_HDR, &expr->location, desc);
		break;
	default:
		break;
	}
}

static const struct expr_ops meta_expr_ops = {
	.type		= EXPR_META,
	.name		= "meta",
	.print		= meta_expr_print,
	.cmp		= meta_expr_cmp,
	.clone		= meta_expr_clone,
	.pctx_update	= meta_expr_pctx_update,
};

struct expr *meta_expr_alloc(const struct location *loc, enum nft_meta_keys key)
{
	const struct meta_template *tmpl = &meta_templates[key];
	struct expr *expr;

	expr = expr_alloc(loc, &meta_expr_ops, tmpl->dtype,
			  tmpl->byteorder, tmpl->len);
	expr->meta.key = key;

	switch (key) {
	case NFT_META_IIFTYPE:
		expr->flags |= EXPR_F_PROTOCOL;
		break;
	case NFT_META_NFPROTO:
		expr->flags |= EXPR_F_PROTOCOL;
		expr->meta.base = PROTO_BASE_LL_HDR;
		break;
	case NFT_META_L4PROTO:
		expr->flags |= EXPR_F_PROTOCOL;
		expr->meta.base = PROTO_BASE_NETWORK_HDR;
		break;
	default:
		break;
	}

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

static void __init meta_init(void)
{
	datatype_register(&ifindex_type);
	datatype_register(&realm_type);
	datatype_register(&tchandle_type);
	datatype_register(&uid_type);
	datatype_register(&gid_type);
}
