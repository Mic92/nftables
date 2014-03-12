/*
 * Conntrack expression related definitions and types.
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

#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <linux/netfilter/nf_conntrack_tuple_common.h>

#include <erec.h>
#include <expression.h>
#include <datatype.h>
#include <gmputil.h>
#include <ct.h>
#include <gmputil.h>
#include <utils.h>
#include <statement.h>

static const struct symbol_table ct_state_tbl = {
	.symbols	= {
		SYMBOL("invalid",	NF_CT_STATE_INVALID_BIT),
		SYMBOL("new",		NF_CT_STATE_BIT(IP_CT_NEW)),
		SYMBOL("established",	NF_CT_STATE_BIT(IP_CT_ESTABLISHED)),
		SYMBOL("related",	NF_CT_STATE_BIT(IP_CT_RELATED)),
		SYMBOL("untracked",	NF_CT_STATE_UNTRACKED_BIT),
		SYMBOL_LIST_END
	}
};

static const struct datatype ct_state_type = {
	.type		= TYPE_CT_STATE,
	.name		= "ct_state",
	.desc		= "conntrack state",
	.byteorder	= BYTEORDER_HOST_ENDIAN,
	.size		= 4 * BITS_PER_BYTE,
	.basetype	= &bitmask_type,
	.sym_tbl	= &ct_state_tbl,
};

static const struct symbol_table ct_dir_tbl = {
	.symbols	= {
		SYMBOL("original",	IP_CT_DIR_ORIGINAL),
		SYMBOL("reply",		IP_CT_DIR_REPLY),
		SYMBOL_LIST_END
	}
};

static const struct datatype ct_dir_type = {
	.type		= TYPE_CT_DIR,
	.name		= "ct_dir",
	.desc		= "conntrack direction",
	.byteorder	= BYTEORDER_INVALID,
	.size		= BITS_PER_BYTE,
	.basetype	= &integer_type,
	.sym_tbl	= &ct_dir_tbl,
};

static const struct symbol_table ct_status_tbl = {
	/*
	 * There are more, but most of them don't make sense for filtering.
	 */
	.symbols	= {
		SYMBOL("expected",	IPS_EXPECTED),
		SYMBOL("seen-reply",	IPS_SEEN_REPLY),
		SYMBOL("assured",	IPS_ASSURED),
		SYMBOL("confirmed",	IPS_CONFIRMED),
		SYMBOL("snat",		IPS_SRC_NAT),
		SYMBOL("dnat",		IPS_DST_NAT),
		SYMBOL("dying",		IPS_DYING),
		SYMBOL_LIST_END
	},
};

static const struct datatype ct_status_type = {
	.type		= TYPE_CT_STATUS,
	.name		= "ct_status",
	.desc		= "conntrack status",
	.byteorder	= BYTEORDER_HOST_ENDIAN,
	.size		= 4 * BITS_PER_BYTE,
	.basetype	= &bitmask_type,
	.sym_tbl	= &ct_status_tbl,
};

static struct symbol_table *ct_label_tbl;

#define CT_LABEL_BIT_SIZE 128

static void ct_label_type_print(const struct expr *expr)
{
	unsigned long bit = mpz_scan1(expr->value, 0);
	const struct symbolic_constant *s;

	for (s = ct_label_tbl->symbols; s->identifier != NULL; s++) {
		if (bit != s->value)
			continue;
		printf("%s", s->identifier);
		return;
	}
	/* can happen when connlabel.conf is altered after rules were added */
	gmp_printf("0x%Zx", expr->value);
}

static struct error_record *ct_label_type_parse(const struct expr *sym,
						struct expr **res)
{
	const struct symbolic_constant *s;
	const struct datatype *dtype;
	uint8_t data[CT_LABEL_BIT_SIZE];
	mpz_t value;

	for (s = ct_label_tbl->symbols; s->identifier != NULL; s++) {
		if (!strcmp(sym->identifier, s->identifier))
			break;
	}

	dtype = sym->dtype;
	if (s->identifier == NULL)
		return error(&sym->location, "Could not parse %s", dtype->desc);

	if (s->value >= CT_LABEL_BIT_SIZE)
		return error(&sym->location, "%s: out of range (%u max)",
			     s->identifier, s->value, CT_LABEL_BIT_SIZE);

	mpz_init2(value, dtype->size);
	mpz_setbit(value, s->value);
	mpz_export_data(data, value, BYTEORDER_HOST_ENDIAN, sizeof(data));

	*res = constant_expr_alloc(&sym->location, dtype,
				   dtype->byteorder, sizeof(data),
				   data);
	mpz_clear(value);
	return NULL;
}

static const struct datatype ct_label_type = {
	.type		= TYPE_CT_LABEL,
	.name		= "ct_label",
	.desc		= "conntrack label",
	.byteorder	= BYTEORDER_HOST_ENDIAN,
	.size		= CT_LABEL_BIT_SIZE,
	.basetype	= &bitmask_type,
	.print		= ct_label_type_print,
	.parse		= ct_label_type_parse,
};

static void __init ct_label_table_init(void)
{
	ct_label_tbl = rt_symbol_table_init("/etc/xtables/connlabel.conf");
}

static const struct ct_template ct_templates[] = {
	[NFT_CT_STATE]		= CT_TEMPLATE("state",	    &ct_state_type,
					      BYTEORDER_HOST_ENDIAN,
					      4 * BITS_PER_BYTE),
	[NFT_CT_DIRECTION]	= CT_TEMPLATE("direction",  &ct_dir_type,
					      BYTEORDER_HOST_ENDIAN,
					      BITS_PER_BYTE),
	[NFT_CT_STATUS]		= CT_TEMPLATE("status",	    &ct_status_type,
					      BYTEORDER_HOST_ENDIAN,
					      4 * BITS_PER_BYTE),
	[NFT_CT_MARK]		= CT_TEMPLATE("mark",	    &mark_type,
					      BYTEORDER_HOST_ENDIAN,
					      4 * BITS_PER_BYTE),
	[NFT_CT_EXPIRATION]	= CT_TEMPLATE("expiration", &time_type,
					      BYTEORDER_HOST_ENDIAN,
					      4 * BITS_PER_BYTE),
	[NFT_CT_HELPER]		= CT_TEMPLATE("helper",	    &string_type,
					      BYTEORDER_HOST_ENDIAN, 0),
	[NFT_CT_L3PROTOCOL]	= CT_TEMPLATE("l3proto",    &invalid_type,
					      BYTEORDER_INVALID,
					      BITS_PER_BYTE),
	[NFT_CT_SRC]		= CT_TEMPLATE("saddr",	    &invalid_type,
					      BYTEORDER_BIG_ENDIAN, 0),
	[NFT_CT_DST]		= CT_TEMPLATE("daddr",	    &invalid_type,
					      BYTEORDER_BIG_ENDIAN, 0),
	[NFT_CT_PROTOCOL]	= CT_TEMPLATE("protocol",   &inet_protocol_type,
					      BYTEORDER_BIG_ENDIAN,
					      BITS_PER_BYTE),
	[NFT_CT_PROTO_SRC]	= CT_TEMPLATE("proto-src",  &invalid_type,
					      BYTEORDER_BIG_ENDIAN,
					      2 * BITS_PER_BYTE),
	[NFT_CT_PROTO_DST]	= CT_TEMPLATE("proto-dst",  &invalid_type,
					      BYTEORDER_BIG_ENDIAN,
					      2 * BITS_PER_BYTE),
	[NFT_CT_LABEL]		= CT_TEMPLATE("label", &ct_label_type,
					      BYTEORDER_HOST_ENDIAN,
					      CT_LABEL_BIT_SIZE),
};

static void ct_expr_print(const struct expr *expr)
{
	printf("ct %s", ct_templates[expr->ct.key].token);
}

static bool ct_expr_cmp(const struct expr *e1, const struct expr *e2)
{
	return e1->ct.key == e2->ct.key;
}

static void ct_expr_clone(struct expr *new, const struct expr *expr)
{
	new->ct.key = expr->ct.key;
}

static void ct_expr_pctx_update(struct proto_ctx *ctx, const struct expr *expr)
{
	const struct expr *left = expr->left, *right = expr->right;
	const struct proto_desc *base, *desc;

	assert(expr->op == OP_EQ);

	switch (left->ct.key) {
	case NFT_CT_PROTOCOL:
		base = ctx->protocol[PROTO_BASE_NETWORK_HDR].desc;
		desc = proto_find_upper(base, mpz_get_uint32(right->value));

		proto_ctx_update(ctx, PROTO_BASE_TRANSPORT_HDR,
				 &expr->location, desc);
		break;
	default:
		break;
	}
}

static const struct expr_ops ct_expr_ops = {
	.type		= EXPR_CT,
	.name		= "ct",
	.print		= ct_expr_print,
	.cmp		= ct_expr_cmp,
	.clone		= ct_expr_clone,
	.pctx_update	= ct_expr_pctx_update,
};

struct expr *ct_expr_alloc(const struct location *loc, enum nft_ct_keys key)
{
	const struct ct_template *tmpl = &ct_templates[key];
	struct expr *expr;

	expr = expr_alloc(loc, &ct_expr_ops, tmpl->dtype,
			  tmpl->byteorder, tmpl->len);
	expr->ct.key = key;

	switch (key) {
	case NFT_CT_PROTOCOL:
		expr->flags = EXPR_F_PROTOCOL;
		break;
	default:
		break;
	}

	return expr;
}

void ct_expr_update_type(struct proto_ctx *ctx, struct expr *expr)
{
	const struct proto_desc *desc;

	switch (expr->ct.key) {
	case NFT_CT_SRC:
	case NFT_CT_DST:
		desc = ctx->protocol[PROTO_BASE_NETWORK_HDR].desc;
		if (desc == &proto_ip)
			expr->dtype = &ipaddr_type;
		else if (desc == &proto_ip6)
			expr->dtype = &ip6addr_type;

		expr->len = expr->dtype->size;
		break;
	case NFT_CT_PROTO_SRC:
	case NFT_CT_PROTO_DST:
		desc = ctx->protocol[PROTO_BASE_TRANSPORT_HDR].desc;
		if (desc == NULL)
			break;
		expr->dtype = &inet_service_type;
		break;
	default:
		break;
	}
}

static void ct_stmt_print(const struct stmt *stmt)
{
	printf("ct %s set ", ct_templates[stmt->ct.key].token);
	expr_print(stmt->ct.expr);
}

static const struct stmt_ops ct_stmt_ops = {
	.type		= STMT_CT,
	.name		= "ct",
	.print		= ct_stmt_print,
};

struct stmt *ct_stmt_alloc(const struct location *loc, enum nft_ct_keys key,
			     struct expr *expr)
{
	struct stmt *stmt;

	stmt = stmt_alloc(loc, &ct_stmt_ops);
	stmt->ct.key	= key;
	stmt->ct.tmpl	= &ct_templates[key];
	stmt->ct.expr	= expr;
	return stmt;
}

static void __init ct_init(void)
{
	datatype_register(&ct_state_type);
	datatype_register(&ct_dir_type);
	datatype_register(&ct_status_type);
}
