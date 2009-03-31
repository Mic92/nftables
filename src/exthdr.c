/*
 * Exthdr expression protocol and type definitions and related functions.
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
#include <netinet/in.h>
#include <netinet/ip6.h>

#include <utils.h>
#include <headers.h>
#include <expression.h>

static void exthdr_expr_print(const struct expr *expr)
{
	printf("%s %s", expr->exthdr.desc->name, expr->exthdr.tmpl->token);
}

static void exthdr_expr_clone(struct expr *new, const struct expr *expr)
{
	new->exthdr.desc = expr->exthdr.desc;
	new->exthdr.tmpl = expr->exthdr.tmpl;
}

static const struct expr_ops exthdr_expr_ops = {
	.type		= EXPR_EXTHDR,
	.name		= "exthdr",
	.print		= exthdr_expr_print,
	.clone		= exthdr_expr_clone,
};

static const struct payload_template exthdr_unknown_template =
	PAYLOAD_TEMPLATE("unknown", &invalid_type, 0, 0);

struct expr *exthdr_expr_alloc(const struct location *loc,
			       const struct exthdr_desc *desc,
			       uint8_t type)
{
	const struct payload_template *tmpl;
	struct expr *expr;

	if (desc != NULL)
		tmpl = &desc->templates[type];
	else
		tmpl = &exthdr_unknown_template;

	expr = expr_alloc(loc, &exthdr_expr_ops, tmpl->dtype,
			  BYTEORDER_BIG_ENDIAN, tmpl->len);
	expr->exthdr.desc = desc;
	expr->exthdr.tmpl = tmpl;
	return expr;
}

static const struct exthdr_desc *exthdr_protocols[IPPROTO_MAX] = {
	[IPPROTO_HOPOPTS]	= &exthdr_hbh,
	[IPPROTO_ROUTING]	= &exthdr_rt,
	[IPPROTO_FRAGMENT]	= &exthdr_frag,
	[IPPROTO_DSTOPTS]	= &exthdr_dst,
	[IPPROTO_MH]		= &exthdr_mh,
};

void exthdr_init_raw(struct expr *expr, uint8_t type,
		     unsigned int offset, unsigned int len)
{
	const struct payload_template *tmpl;
	unsigned int i;

	assert(expr->ops->type == EXPR_EXTHDR);

	expr->len = len;
	expr->exthdr.desc = exthdr_protocols[type];
	assert(expr->exthdr.desc != NULL);

	for (i = 0; i < array_size(expr->exthdr.desc->templates); i++) {
		tmpl = &expr->exthdr.desc->templates[i];
		if (tmpl->offset != offset ||
		    tmpl->len    != len)
			continue;
		expr->dtype	  = tmpl->dtype;
		expr->exthdr.tmpl = tmpl;
		return;
	}
}

#define HDR_TEMPLATE(__name, __dtype, __type, __member)			\
	PAYLOAD_TEMPLATE(__name, __dtype,				\
			 offsetof(__type, __member) * 8,		\
			 field_sizeof(__type, __member) * 8)

/*
 * Hop-by-hop options
 */

#define HBH_FIELD(__name, __member, __dtype) \
	HDR_TEMPLATE(__name, __dtype, struct ip6_hbh, __member)

const struct exthdr_desc exthdr_hbh = {
	.name		= "hbh",
	.type		= IPPROTO_HOPOPTS,
	.templates	= {
		[HBHHDR_NEXTHDR]	= HBH_FIELD("nexthdr", ip6h_nxt, &inet_protocol_type),
		[HBHHDR_HDRLENGTH]	= HBH_FIELD("hdrlength", ip6h_len, &integer_type),
	},
};

/*
 * Routing header
 */

const struct exthdr_desc exthdr_rt2 = {
	.templates	= {
		[RT2HDR_RESERVED]	= {},
		[RT2HDR_ADDR]		= {},
	},
};

#define RT0_FIELD(__name, __member, __dtype) \
	HDR_TEMPLATE(__name, __dtype, struct ip6_rthdr0, __member)

const struct exthdr_desc exthdr_rt0 = {
	.templates	= {
		[RT0HDR_RESERVED]	= RT0_FIELD("reserved", ip6r0_reserved, &integer_type),
		[RT0HDR_ADDR_1]		= RT0_FIELD("addr[1]", ip6r0_addr[0], &ip6addr_type),
		[RT0HDR_ADDR_1 + 1]	= RT0_FIELD("addr[2]", ip6r0_addr[0], &ip6addr_type),
		// ...
	},
};

#define RT_FIELD(__name, __member, __dtype) \
	HDR_TEMPLATE(__name, __dtype, struct ip6_rthdr, __member)

const struct exthdr_desc exthdr_rt = {
	.name		= "rt",
	.type		= IPPROTO_ROUTING,
#if 0
	.protocol_key	= RTHDR_TYPE,
	.protocols	= {
		[0]	= &exthdr_rt0,
		[2]	= &exthdr_rt2,
	},
#endif
	.templates	= {
		[RTHDR_NEXTHDR]		= RT_FIELD("nexthdr", ip6r_nxt, &inet_protocol_type),
		[RTHDR_HDRLENGTH]	= RT_FIELD("hdrlength", ip6r_len, &integer_type),
		[RTHDR_TYPE]		= RT_FIELD("type", ip6r_type, &integer_type),
		[RTHDR_SEG_LEFT]	= RT_FIELD("seg-left", ip6r_segleft, &integer_type),
	},
};

/*
 * Fragment header
 */

#define FRAG_FIELD(__name, __member, __dtype) \
	HDR_TEMPLATE(__name, __dtype, struct ip6_frag, __member)

const struct exthdr_desc exthdr_frag = {
	.name		= "frag",
	.type		= IPPROTO_FRAGMENT,
	.templates	= {
		[FRAGHDR_NEXTHDR]	= FRAG_FIELD("nexthdr", ip6f_nxt, &inet_protocol_type),
		[FRAGHDR_RESERVED]	= FRAG_FIELD("reserved", ip6f_reserved, &integer_type),
		[FRAGHDR_FRAG_OFF]	= PAYLOAD_TEMPLATE("frag-off", &integer_type,
							   16, 13),
		[FRAGHDR_RESERVED2]	= PAYLOAD_TEMPLATE("reserved2", &integer_type,
							   29, 2),
		[FRAGHDR_MFRAGS]	= PAYLOAD_TEMPLATE("more-fragments", &integer_type,
							   31, 1),
		[FRAGHDR_ID]		= FRAG_FIELD("id", ip6f_ident, &integer_type),
	},
};

/*
 * DST options
 */

#define DST_FIELD(__name, __member, __dtype) \
	HDR_TEMPLATE(__name, __dtype, struct ip6_dest, __member)

const struct exthdr_desc exthdr_dst = {
	.name		= "dst",
	.type		= IPPROTO_DSTOPTS,
	.templates	= {
		[DSTHDR_NEXTHDR]	= DST_FIELD("nexthdr", ip6d_nxt, &inet_protocol_type),
		[DSTHDR_HDRLENGTH]	= DST_FIELD("hdrlength", ip6d_len, &integer_type),
	},
};

/*
 * Mobility header
 */

#define MH_FIELD(__name, __member, __dtype) \
	HDR_TEMPLATE(__name, __dtype, struct ip6_mh, __member)

static const struct symbol_table mh_type_tbl = {
	.symbols	= {
		SYMBOL("binding-refresh-request",	IP6_MH_TYPE_BRR),
		SYMBOL("home-test-init",		IP6_MH_TYPE_HOTI),
		SYMBOL("careof-test-init",		IP6_MH_TYPE_COTI),
		SYMBOL("home-test",			IP6_MH_TYPE_HOT),
		SYMBOL("careof-test",			IP6_MH_TYPE_COT),
		SYMBOL("binding-update",		IP6_MH_TYPE_BU),
		SYMBOL("binding-acknowledgement",	IP6_MH_TYPE_BACK),
		SYMBOL("binding-error",			IP6_MH_TYPE_BERROR),
		SYMBOL("fast-binding-update",		IP6_MH_TYPE_FBU),
		SYMBOL("fast-binding-acknowledgement",	IP6_MH_TYPE_FBACK),
		SYMBOL("fast-binding-advertisement",	IP6_MH_TYPE_FNA),
		SYMBOL("experimental-mobility-header",	IP6_MH_TYPE_EMH),
		SYMBOL("home-agent-switch-message",	IP6_MH_TYPE_HASM),
		SYMBOL_LIST_END
	},
};

static const struct datatype mh_type_type = {
	.type		= TYPE_MH_TYPE,
	.name		= "mh_type",
	.desc		= "Mobility Header Type",
	.byteorder	= BYTEORDER_BIG_ENDIAN,
	.size		= BITS_PER_BYTE,
	.basetype	= &integer_type,
	.sym_tbl	= &mh_type_tbl,
};

const struct exthdr_desc exthdr_mh = {
	.name		= "mh",
	.type		= IPPROTO_MH,
	.templates	= {
		[MHHDR_NEXTHDR]		= MH_FIELD("nexthdr", ip6mh_proto, &inet_protocol_type),
		[MHHDR_HDRLENGTH]	= MH_FIELD("hdrlength", ip6mh_hdrlen, &integer_type),
		[MHHDR_TYPE]		= MH_FIELD("type", ip6mh_type, &mh_type_type),
		[MHHDR_RESERVED]	= MH_FIELD("reserved", ip6mh_reserved, &integer_type),
		[MHHDR_CHECKSUM]	= MH_FIELD("checksum", ip6mh_cksum, &integer_type),
	},
};

static void __init exthdr_init(void)
{
	datatype_register(&mh_type_type);
}
