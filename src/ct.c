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

#include <expression.h>
#include <datatype.h>
#include <ct.h>
#include <utils.h>

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
	.basetype	= &bitmask_type,
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
};

static void ct_expr_print(const struct expr *expr)
{
	printf("ct %s", ct_templates[expr->ct.key].token);
}

static void ct_expr_clone(struct expr *new, const struct expr *expr)
{
	new->ct.key = expr->ct.key;
}

static const struct expr_ops ct_expr_ops = {
	.type		= EXPR_CT,
	.name		= "ct",
	.print		= ct_expr_print,
	.clone		= ct_expr_clone,
};

struct expr *ct_expr_alloc(const struct location *loc, enum nft_ct_keys key)
{
	const struct ct_template *tmpl = &ct_templates[key];
	struct expr *expr;

	expr = expr_alloc(loc, &ct_expr_ops, tmpl->dtype,
			  tmpl->byteorder, tmpl->len);
	expr->ct.key = key;
	return expr;
}

static void __init ct_init(void)
{
	datatype_register(&ct_state_type);
	datatype_register(&ct_dir_type);
	datatype_register(&ct_status_type);
}
