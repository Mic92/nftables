/*
 * Payload expression protocol and type definitions and related functions.
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
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>

#include <rule.h>
#include <expression.h>
#include <payload.h>
#include <headers.h>
#include <gmputil.h>
#include <utils.h>

static const char *payload_base_names[] = {
	[PAYLOAD_BASE_INVALID]		= "invalid",
	[PAYLOAD_BASE_LL_HDR]		= "link layer",
	[PAYLOAD_BASE_NETWORK_HDR]	= "network layer",
	[PAYLOAD_BASE_TRANSPORT_HDR]	= "transport layer",
};

static const char *payload_base_tokens[] = {
	[PAYLOAD_BASE_INVALID]		= "invalid",
	[PAYLOAD_BASE_LL_HDR]		= "ll",
	[PAYLOAD_BASE_NETWORK_HDR]	= "nh",
	[PAYLOAD_BASE_TRANSPORT_HDR]	= "th",
};

static const struct payload_template payload_unknown_template =
	PAYLOAD_TEMPLATE("unknown", &invalid_type, 0, 0);

static const struct payload_desc payload_unknown_desc = {
	.name		= "unknown",
	.base		= PAYLOAD_BASE_INVALID,
};

static void payload_expr_print(const struct expr *expr)
{
	const struct payload_desc *desc;
	const struct payload_template *tmpl;

	desc = expr->payload.desc;
	tmpl = expr->payload.tmpl;
	if (desc != NULL && tmpl != NULL)
		printf("%s %s", desc->name, tmpl->token);
	else
		printf("payload @%s,%u,%u",
		       payload_base_tokens[expr->payload.base],
		       expr->payload.offset, expr->len);
}

static void payload_expr_clone(struct expr *new, const struct expr *expr)
{
	new->payload.desc   = expr->payload.desc;
	new->payload.tmpl   = expr->payload.tmpl;
	new->payload.base   = expr->payload.base;
	new->payload.offset = expr->payload.offset;
	new->payload.flags  = expr->payload.flags;
}

static const struct expr_ops payload_expr_ops = {
	.type		= EXPR_PAYLOAD,
	.name		= "payload",
	.print		= payload_expr_print,
	.clone		= payload_expr_clone,
};

struct expr *payload_expr_alloc(const struct location *loc,
				const struct payload_desc *desc,
				unsigned int type)
{
	const struct payload_template *tmpl;
	enum payload_bases base;
	struct expr *expr;
	unsigned int flags = 0;

	if (desc != NULL) {
		tmpl = &desc->templates[type];
		base = desc->base;
		if (type == desc->protocol_key)
			flags = PAYLOAD_PROTOCOL_EXPR;
	} else {
		tmpl = &payload_unknown_template;
		base = PAYLOAD_BASE_INVALID;
	}

	expr = expr_alloc(loc, &payload_expr_ops, tmpl->dtype,
			  tmpl->dtype->byteorder, tmpl->len);
	expr->payload.desc   = desc;
	expr->payload.tmpl   = tmpl;
	expr->payload.base   = base;
	expr->payload.offset = tmpl->offset;
	expr->payload.flags  = flags;
	return expr;
}

void payload_init_raw(struct expr *expr, enum payload_bases base,
		      unsigned int offset, unsigned int len)
{
	expr->payload.base	= base;
	expr->payload.offset	= offset;
	expr->len		= len;
}

/**
 * payload_select_proto - find protocol description by protocol value linking
 * 			  it to lower layer protocol
 *
 * @base:	lower layer protocol description
 * @num:	protocol value
 */
static const struct payload_desc *
payload_select_proto(const struct payload_desc *base, unsigned int num)
{
	unsigned int i;

	for (i = 0; i < array_size(base->protocols); i++) {
		if (base->protocols[i].num == num)
			return base->protocols[i].desc;
	}
	return NULL;
}

/**
 * payload_proto_val - return protocol number linking two protocols together
 *
 * @base:	lower layer protocol description
 * @desc:	upper layer protocol description
 */
static int payload_proto_val(const struct payload_desc *base,
			     const struct payload_desc *desc)
{
	unsigned int i;

	for (i = 0; i < array_size(base->protocols); i++) {
		if (base->protocols[i].desc == desc)
			return base->protocols[i].num;
	}
	return -1;
}

static const struct dev_payload_desc dev_payload_desc[] = {
	DEV_PAYLOAD_DESC(ARPHRD_ETHER, &payload_eth),
};

/**
 * payload_dev_type - return arphrd type linking a device and a protocol together
 *
 * @desc:	the protocol description
 * @res:	pointer to result
 */
static int payload_dev_type(const struct payload_desc *desc, uint16_t *res)
{
	unsigned int i;

	for (i = 0; i < array_size(dev_payload_desc); i++) {
		if (dev_payload_desc[i].desc == desc) {
			*res = dev_payload_desc[i].type;
			return 0;
		}
	}
	return -1;
}

/**
 * payload_dev_desc - return protocol description for an arphrd type
 *
 * @type:	the arphrd type
 */
static const struct payload_desc *payload_dev_desc(uint16_t type)
{
	unsigned int i;

	for (i = 0; i < array_size(dev_payload_desc); i++) {
		if (dev_payload_desc[i].type == type)
			return dev_payload_desc[i].desc;
	}
	return NULL;
}

static const struct payload_hook_desc payload_hooks[] = {
	[NFPROTO_BRIDGE]	= PAYLOAD_HOOK(PAYLOAD_BASE_LL_HDR, &payload_eth),
	[NFPROTO_IPV4]		= PAYLOAD_HOOK(PAYLOAD_BASE_NETWORK_HDR, &payload_ip),
	[NFPROTO_IPV6]		= PAYLOAD_HOOK(PAYLOAD_BASE_NETWORK_HDR, &payload_ip6),
	[NFPROTO_ARP]		= PAYLOAD_HOOK(PAYLOAD_BASE_NETWORK_HDR, &payload_arp),
};

/**
 * payload_ctx_init - initialize payload context for a given hook family
 *
 * @ctx:	payload context
 * @family:	hook family
 */
void payload_ctx_init(struct payload_ctx *ctx, unsigned int family)
{
	const struct payload_hook_desc *h = &payload_hooks[family];

	memset(ctx, 0, sizeof(*ctx));
	ctx->family = family;
	ctx->protocol[h->base].desc = h->desc;
}

/**
 * payload_ctx_update_meta - update payload context with meta expression
 *
 * @ctx:	payload context
 * @expr:	relational meta expression
 *
 * Update LL payload context based on IIFTYPE meta match in non-LL hooks.
 */
void payload_ctx_update_meta(struct payload_ctx *ctx, const struct expr *expr)
{
	const struct payload_hook_desc *h = &payload_hooks[ctx->family];
	const struct expr *left = expr->left, *right = expr->right;
	const struct payload_desc *desc;

	if (left->meta.key != NFT_META_IIFTYPE)
		return;

	assert(expr->op == OP_EQ);
	if (h->base < PAYLOAD_BASE_NETWORK_HDR)
		return;

	desc = payload_dev_desc(mpz_get_uint16(right->value));
	if (desc == NULL)
		desc = &payload_unknown_desc;

	ctx->protocol[PAYLOAD_BASE_LL_HDR].location = expr->location;
	ctx->protocol[PAYLOAD_BASE_LL_HDR].desc = desc;
}

/**
 * payload_ctx_update - update payload context
 *
 * @ctx:	payload context
 * @expr:	relational payload expression
 *
 * Update payload context for relational payload expressions.
 */
void payload_ctx_update(struct payload_ctx *ctx, const struct expr *expr)
{
	const struct expr *left = expr->left, *right = expr->right;
	const struct payload_desc *base, *desc;

	if (!(left->payload.flags & PAYLOAD_PROTOCOL_EXPR))
		return;

	assert(expr->op == OP_EQ);
	base = ctx->protocol[left->payload.base].desc;
	desc = payload_select_proto(base, mpz_get_uint32(right->value));

	ctx->protocol[left->payload.base + 1].location = expr->location;
	ctx->protocol[left->payload.base + 1].desc = desc;
}

/**
 * payload_gen_dependency - generate match expression on payload dependency
 *
 * @ctx:	evaluation context
 * @expr:	payload expression
 * @res:	dependency expression
 *
 * Generate matches on protocol dependencies. There are two different kinds
 * of dependencies:
 *
 * - A payload expression for a base above the hook base requires a match
 *   on the protocol value in the lower layer header.
 *
 * - A payload expression for a base below the hook base is invalid in the
 *   output path since the lower layer header does not exist when the packet
 *   is classified. In the input path a payload expressions for a base exactly
 *   one below the hook base is valid. In this case a match on the device type
 *   is required to verify that we're dealing with the expected protocol.
 *
 *   Note: since it is unknown to userspace which hooks a chain is called from,
 *   it is not explicitly verified. The NFT_META_IIFTYPE match will only match
 *   in the input path though.
 */
int payload_gen_dependency(struct eval_ctx *ctx, const struct expr *expr,
			   struct expr **res)
{
	const struct payload_hook_desc *h = &payload_hooks[ctx->pctx.family];
	const struct payload_desc *desc;
	const struct payload_template *tmpl;
	struct expr *dep, *left, *right;
	int protocol;
	uint16_t type;

	if (expr->payload.base < h->base) {
		if (expr->payload.base < h->base - 1)
			return expr_error(ctx, expr,
					  "payload base is invalid for this "
					  "family");

		if (payload_dev_type(expr->payload.desc, &type) < 0)
			return expr_error(ctx, expr,
					  "protocol specification is invalid "
					  "for this family");

		left = meta_expr_alloc(&expr->location, NFT_META_IIFTYPE);
		right = constant_expr_alloc(&expr->location, &arphrd_type,
					    BYTEORDER_HOST_ENDIAN,
					    2 * BITS_PER_BYTE, &type);

		dep = relational_expr_alloc(&expr->location, OP_EQ, left, right);
		*res = dep;
		return 0;
	}

	desc = ctx->pctx.protocol[expr->payload.base - 1].desc;
	if (desc == NULL)
		return expr_error(ctx, expr,
				  "ambiguous payload specification: "
				  "no %s protocol specified",
				  payload_base_names[expr->payload.base - 1]);

	protocol = payload_proto_val(desc, expr->payload.desc);
	if (protocol < 0)
		return expr_error(ctx, expr,
				  "conflicting protocols specified: %s vs. %s",
				  desc->name, expr->payload.desc->name);

	tmpl = &desc->templates[desc->protocol_key];
	left = payload_expr_alloc(&expr->location, desc, desc->protocol_key);
	right = constant_expr_alloc(&expr->location, tmpl->dtype,
				    BYTEORDER_HOST_ENDIAN,
				    tmpl->len, &protocol);

	dep = relational_expr_alloc(&expr->location, OP_EQ, left, right);
	payload_ctx_update(&ctx->pctx, dep);
	*res = dep;
	return 0;
}

/**
 * payload_expr_complete - fill in type information of a raw payload expr
 *
 * @expr:	the payload expression
 * @ctx:	payload context
 *
 * Complete the type of a raw payload expression based on the context. If
 * insufficient information is available the expression remains unchanged.
 */
void payload_expr_complete(struct expr *expr, const struct payload_ctx *ctx)
{
	const struct payload_desc *desc;
	const struct payload_template *tmpl;
	unsigned int i;

	assert(expr->ops->type == EXPR_PAYLOAD);

	desc = ctx->protocol[expr->payload.base].desc;
	if (desc == NULL)
		return;
	assert(desc->base == expr->payload.base);

	for (i = 0; i < array_size(desc->templates); i++) {
		tmpl = &desc->templates[i];
		if (tmpl->offset != expr->payload.offset ||
		    tmpl->len    != expr->len)
			continue;
		expr->dtype	   = tmpl->dtype;
		expr->payload.desc = desc;
		expr->payload.tmpl = tmpl;
		return;
	}
}

/**
 * payload_expr_expand - expand raw merged adjacent payload expressions into its
 * 			 original components
 *
 * @list:	list to append expanded payload expressions to
 * @expr:	the payload expression to expand
 * @ctx:	payload context
 *
 * Expand a merged adjacent payload expression into its original components
 * by splitting elements off the beginning matching a payload template.
 *
 * Note: this requires all payload templates to be specified in ascending
 * 	 offset order.
 */
void payload_expr_expand(struct list_head *list, struct expr *expr,
			 const struct payload_ctx *ctx)
{
	const struct payload_desc *desc;
	const struct payload_template *tmpl;
	struct expr *new;
	unsigned int i;

	assert(expr->ops->type == EXPR_PAYLOAD);

	desc = ctx->protocol[expr->payload.base].desc;
	if (desc == NULL)
		goto raw;
	assert(desc->base == expr->payload.base);

	for (i = 1; i < array_size(desc->templates); i++) {
		tmpl = &desc->templates[i];
		if (tmpl->offset != expr->payload.offset)
			continue;

		if (tmpl->len <= expr->len) {
			new = payload_expr_alloc(&expr->location, desc, i);
			list_add_tail(&new->list, list);
			expr->len	     -= tmpl->len;
			expr->payload.offset += tmpl->len;
			if (expr->len == 0)
				return;
		} else
			break;
	}
raw:
	new = payload_expr_alloc(&expr->location, NULL, 0);
	payload_init_raw(new, expr->payload.base, expr->payload.offset,
			 expr->len);
	list_add_tail(&new->list, list);
}

/**
 * payload_is_adjacent - return whether two payload expressions refer to
 * 			 adjacent header locations
 *
 * @e1:		first payload expression
 * @e2:		second payload expression
 */
bool payload_is_adjacent(const struct expr *e1, const struct expr *e2)
{
	if (e1->payload.base		 == e2->payload.base &&
	    e1->payload.offset + e1->len == e2->payload.offset)
		return true;
	return false;
}

/**
 * payload_expr_join - join two adjacent payload expressions
 *
 * @e1:		first payload expression
 * @e2:		second payload expression
 */
struct expr *payload_expr_join(const struct expr *e1, const struct expr *e2)
{
	struct expr *expr;

	assert(payload_is_adjacent(e1, e2));

	expr = payload_expr_alloc(&internal_location, NULL, 0);
	expr->payload.base   = e1->payload.base;
	expr->payload.offset = e1->payload.offset;
	expr->len	     = e1->len + e2->len;
	return expr;
}

#define HDR_TEMPLATE(__name, __dtype, __type, __member)			\
	PAYLOAD_TEMPLATE(__name, __dtype,				\
			 offsetof(__type, __member) * 8,		\
			 field_sizeof(__type, __member) * 8)

#define HDR_FIELD(__name, __struct, __member)				\
	HDR_TEMPLATE(__name, &integer_type, __struct, __member)
#define HDR_BITFIELD(__name, __dtype,  __offset, __len)			\
	PAYLOAD_TEMPLATE(__name, __dtype, __offset, __len)
#define HDR_TYPE(__name, __dtype, __struct, __member)			\
	HDR_TEMPLATE(__name, __dtype, __struct, __member)

#define INET_PROTOCOL(__name, __struct, __member)			\
	HDR_TYPE(__name, &inet_protocol_type, __struct, __member)
#define INET_SERVICE(__name, __struct, __member)			\
	HDR_TYPE(__name, &inet_service_type, __struct, __member)

/*
 * AH
 */

#define AHHDR_FIELD(__name, __member) \
	HDR_FIELD(__name, struct ip_auth_hdr, __member)

const struct payload_desc payload_ah = {
	.name		= "ah",
	.base		= PAYLOAD_BASE_TRANSPORT_HDR,
	.protocol_key	= AHHDR_NEXTHDR,
	.protocols	= {
		PAYLOAD_PROTO(IPPROTO_ESP,	&payload_esp),
		PAYLOAD_PROTO(IPPROTO_AH,	&payload_ah),
		PAYLOAD_PROTO(IPPROTO_COMP,	&payload_comp),
		PAYLOAD_PROTO(IPPROTO_UDP,	&payload_udp),
		PAYLOAD_PROTO(IPPROTO_UDPLITE,	&payload_udplite),
		PAYLOAD_PROTO(IPPROTO_TCP,	&payload_tcp),
		PAYLOAD_PROTO(IPPROTO_DCCP,	&payload_dccp),
		PAYLOAD_PROTO(IPPROTO_SCTP,	&payload_sctp),
	},
	.templates	= {
		[AHHDR_NEXTHDR]		= INET_PROTOCOL("nexthdr", struct ip_auth_hdr, nexthdr),
		[AHHDR_HDRLENGTH]	= AHHDR_FIELD("hdrlength", hdrlen),
		[AHHDR_RESERVED]	= AHHDR_FIELD("reserved", reserved),
		[AHHDR_SPI]		= AHHDR_FIELD("spi", spi),
		[AHHDR_SEQUENCE]	= AHHDR_FIELD("sequence", seq_no),
	},
};

/*
 * ESP
 */

#define ESPHDR_FIELD(__name, __member) \
	HDR_FIELD(__name, struct ip_esp_hdr, __member)

const struct payload_desc payload_esp = {
	.name		= "esp",
	.base		= PAYLOAD_BASE_TRANSPORT_HDR,
	.templates	= {
		[ESPHDR_SPI]		= ESPHDR_FIELD("spi", spi),
		[ESPHDR_SEQUENCE]	= ESPHDR_FIELD("sequence", seq_no),
	},
};

/*
 * IPCOMP
 */

#define COMPHDR_FIELD(__name, __member) \
	HDR_FIELD(__name, struct ip_comp_hdr, __member)

const struct payload_desc payload_comp = {
	.name		= "comp",
	.base		= PAYLOAD_BASE_TRANSPORT_HDR,
	.protocol_key	= COMPHDR_NEXTHDR,
	.protocols	= {
		PAYLOAD_PROTO(IPPROTO_ESP,	&payload_esp),
		PAYLOAD_PROTO(IPPROTO_AH,	&payload_ah),
		PAYLOAD_PROTO(IPPROTO_COMP,	&payload_comp),
		PAYLOAD_PROTO(IPPROTO_UDP,	&payload_udp),
		PAYLOAD_PROTO(IPPROTO_UDPLITE,	&payload_udplite),
		PAYLOAD_PROTO(IPPROTO_TCP,	&payload_tcp),
		PAYLOAD_PROTO(IPPROTO_DCCP,	&payload_dccp),
		PAYLOAD_PROTO(IPPROTO_SCTP,	&payload_sctp),
	},
	.templates	= {
		[COMPHDR_NEXTHDR]	= INET_PROTOCOL("nexthdr", struct ip_comp_hdr, nexthdr),
		[COMPHDR_FLAGS]		= COMPHDR_FIELD("flags", flags),
		[COMPHDR_CPI]		= COMPHDR_FIELD("cpi", cpi),
	},
};

/*
 * ICMP
 */

#include <netinet/ip_icmp.h>

static const struct symbol_table icmp_type_tbl = {
	.symbols	= {
		SYMBOL("echo-reply",			ICMP_ECHOREPLY),
		SYMBOL("destination-unreachable",	ICMP_DEST_UNREACH),
		SYMBOL("source-quench",			ICMP_SOURCE_QUENCH),
		SYMBOL("redirect",			ICMP_REDIRECT),
		SYMBOL("echo-request",			ICMP_ECHO),
		SYMBOL("time-exceeded",			ICMP_TIME_EXCEEDED),
		SYMBOL("parameter-problem",		ICMP_PARAMETERPROB),
		SYMBOL("timestamp-request",		ICMP_TIMESTAMP),
		SYMBOL("timestamp-reply",		ICMP_TIMESTAMPREPLY),
		SYMBOL("info-request",			ICMP_INFO_REQUEST),
		SYMBOL("info-reply",			ICMP_INFO_REPLY),
		SYMBOL("address-mask-request",		ICMP_ADDRESS),
		SYMBOL("address-mask-reply",		ICMP_ADDRESSREPLY),
		SYMBOL_LIST_END
	},
};

static const struct datatype icmp_type_type = {
	.type		= TYPE_ICMP_TYPE,
	.name		= "icmp_type",
	.desc		= "ICMP type",
	.byteorder	= BYTEORDER_BIG_ENDIAN,
	.size		= BITS_PER_BYTE,
	.basetype	= &integer_type,
	.sym_tbl	= &icmp_type_tbl,
};

#define ICMPHDR_FIELD(__name, __member) \
	HDR_FIELD(__name, struct icmphdr, __member)
#define ICMPHDR_TYPE(__name, __type, __member) \
	HDR_TYPE(__name, __type, struct icmphdr, __member)

const struct payload_desc payload_icmp = {
	.name		= "icmp",
	.base		= PAYLOAD_BASE_TRANSPORT_HDR,
	.templates	= {
		[ICMPHDR_TYPE]		= ICMPHDR_TYPE("type", &icmp_type_type, type),
		[ICMPHDR_CODE]		= ICMPHDR_FIELD("code", code),
		[ICMPHDR_CHECKSUM]	= ICMPHDR_FIELD("checksum", checksum),
		[ICMPHDR_ID]		= ICMPHDR_FIELD("id", un.echo.id),
		[ICMPHDR_SEQ]		= ICMPHDR_FIELD("sequence", un.echo.sequence),
		[ICMPHDR_GATEWAY]	= ICMPHDR_FIELD("gateway", un.gateway),
		[ICMPHDR_MTU]		= ICMPHDR_FIELD("mtu", un.frag.mtu),
	},
};

/*
 * UDP/UDP-Lite
 */

#include <netinet/udp.h>
#define UDPHDR_FIELD(__name, __member) \
	HDR_FIELD(__name, struct udphdr, __member)

const struct payload_desc payload_udp = {
	.name		= "udp",
	.base		= PAYLOAD_BASE_TRANSPORT_HDR,
	.templates	= {
		[UDPHDR_SPORT]		= INET_SERVICE("sport", struct udphdr, source),
		[UDPHDR_DPORT]		= INET_SERVICE("dport", struct udphdr, dest),
		[UDPHDR_LENGTH]		= UDPHDR_FIELD("length", len),
		[UDPHDR_CHECKSUM]	= UDPHDR_FIELD("checksum", check),
	},
};

const struct payload_desc payload_udplite = {
	.name		= "udplite",
	.base		= PAYLOAD_BASE_TRANSPORT_HDR,
	.templates	= {
		[UDPHDR_SPORT]		= INET_SERVICE("sport", struct udphdr, source),
		[UDPHDR_DPORT]		= INET_SERVICE("dport", struct udphdr, dest),
		[UDPHDR_CSUMCOV]	= UDPHDR_FIELD("csumcov", len),
		[UDPHDR_CHECKSUM]	= UDPHDR_FIELD("checksum", check),
	},
};

/*
 * TCP
 */

#include <netinet/tcp.h>

static const struct symbol_table tcp_flag_tbl = {
	.symbols	= {
		SYMBOL("fin",	TCP_FLAG_FIN),
		SYMBOL("syn",	TCP_FLAG_SYN),
		SYMBOL("rst",	TCP_FLAG_RST),
		SYMBOL("psh",	TCP_FLAG_PSH),
		SYMBOL("ack",	TCP_FLAG_ACK),
		SYMBOL("urg",	TCP_FLAG_URG),
		SYMBOL("ecn",	TCP_FLAG_ECN),
		SYMBOL("cwr",	TCP_FLAG_CWR),
		SYMBOL_LIST_END
	},
};

static const struct datatype tcp_flag_type = {
	.type		= TYPE_TCP_FLAG,
	.name		= "tcp_flag",
	.desc		= "TCP flag",
	.byteorder	= BYTEORDER_BIG_ENDIAN,
	.size		= BITS_PER_BYTE,
	.basetype	= &bitmask_type,
	.sym_tbl	= &tcp_flag_tbl,
};

#define TCPHDR_FIELD(__name, __member) \
	HDR_FIELD(__name, struct tcphdr, __member)

const struct payload_desc payload_tcp = {
	.name		= "tcp",
	.base		= PAYLOAD_BASE_TRANSPORT_HDR,
	.templates	= {
		[TCPHDR_SPORT]		= INET_SERVICE("sport", struct tcphdr, source),
		[TCPHDR_DPORT]		= INET_SERVICE("dport", struct tcphdr, dest),
		[TCPHDR_SEQ]		= TCPHDR_FIELD("sequence", seq),
		[TCPHDR_ACKSEQ]		= TCPHDR_FIELD("ackseq", ack_seq),
		[TCPHDR_DOFF]		= {},
		[TCPHDR_RESERVED]	= {},
		[TCPHDR_FLAGS]		= HDR_BITFIELD("flags", &tcp_flag_type,
						       13 * BITS_PER_BYTE,
						       BITS_PER_BYTE),
		[TCPHDR_WINDOW]		= TCPHDR_FIELD("window", window),
		[TCPHDR_CHECKSUM]	= TCPHDR_FIELD("checksum", check),
		[TCPHDR_URGPTR]		= TCPHDR_FIELD("urgptr", urg_ptr),
	},
};

/*
 * DCCP
 */

static const struct symbol_table dccp_pkttype_tbl = {
	.symbols	= {
		SYMBOL("request",	DCCP_PKT_REQUEST),
		SYMBOL("response",	DCCP_PKT_RESPONSE),
		SYMBOL("data",		DCCP_PKT_DATA),
		SYMBOL("ack",		DCCP_PKT_ACK),
		SYMBOL("dataack",	DCCP_PKT_DATAACK),
		SYMBOL("closereq",	DCCP_PKT_CLOSEREQ),
		SYMBOL("close",		DCCP_PKT_CLOSE),
		SYMBOL("reset",		DCCP_PKT_RESET),
		SYMBOL("sync",		DCCP_PKT_SYNC),
		SYMBOL("syncack",	DCCP_PKT_SYNCACK),
		SYMBOL_LIST_END
	},
};

static const struct datatype dccp_pkttype_type = {
	.type		= TYPE_DCCP_PKTTYPE,
	.name		= "dccp_pkttype",
	.desc		= "DCCP packet type",
	.byteorder	= BYTEORDER_INVALID,
	.size		= 4,
	.basetype	= &integer_type,
	.sym_tbl	= &dccp_pkttype_tbl,
};


#define DCCPHDR_FIELD(__name, __member) \
	HDR_FIELD(__name, struct dccp_hdr, __member)

const struct payload_desc payload_dccp = {
	.name		= "dccp",
	.base		= PAYLOAD_BASE_TRANSPORT_HDR,
	.templates	= {
		[DCCPHDR_SPORT]		= INET_SERVICE("sport", struct dccp_hdr, dccph_sport),
		[DCCPHDR_DPORT]		= INET_SERVICE("dport", struct dccp_hdr, dccph_dport),
		[DCCPHDR_TYPE]		= HDR_BITFIELD("type", &dccp_pkttype_type, 67, 4),
	},
};

/*
 * SCTP
 */

#define SCTPHDR_FIELD(__name, __member) \
	HDR_FIELD(__name, struct sctphdr, __member)

const struct payload_desc payload_sctp = {
	.name		= "sctp",
	.base		= PAYLOAD_BASE_TRANSPORT_HDR,
	.templates	= {
		[SCTPHDR_SPORT]		= INET_SERVICE("sport", struct sctphdr, source),
		[SCTPHDR_DPORT]		= INET_SERVICE("dport", struct sctphdr, dest),
		[SCTPHDR_VTAG]		= SCTPHDR_FIELD("vtag", vtag),
		[SCTPHDR_CHECKSUM]	= SCTPHDR_FIELD("checksum", checksum),
	},
};

/*
 * IPv4
 */

#include <netinet/ip.h>
#define IPHDR_FIELD(__name, __member) \
	HDR_FIELD(__name, struct iphdr, __member)
#define IPHDR_ADDR(__name, __member) \
	HDR_TYPE(__name, &ipaddr_type, struct iphdr, __member)

const struct payload_desc payload_ip = {
	.name		= "ip",
	.base		= PAYLOAD_BASE_NETWORK_HDR,
	.protocol_key	= IPHDR_PROTOCOL,
	.protocols	= {
		PAYLOAD_PROTO(IPPROTO_ICMP,	&payload_icmp),
		PAYLOAD_PROTO(IPPROTO_ESP,	&payload_esp),
		PAYLOAD_PROTO(IPPROTO_AH,	&payload_ah),
		PAYLOAD_PROTO(IPPROTO_COMP,	&payload_comp),
		PAYLOAD_PROTO(IPPROTO_UDP,	&payload_udp),
		PAYLOAD_PROTO(IPPROTO_UDPLITE,	&payload_udplite),
		PAYLOAD_PROTO(IPPROTO_TCP,	&payload_tcp),
		PAYLOAD_PROTO(IPPROTO_DCCP,	&payload_dccp),
		PAYLOAD_PROTO(IPPROTO_SCTP,	&payload_sctp),
	},
	.templates	= {
		[IPHDR_VERSION]		= HDR_BITFIELD("version", &integer_type, 0, 4),
		[IPHDR_HDRLENGTH]	= HDR_BITFIELD("hdrlength", &integer_type, 4, 4),
		[IPHDR_TOS]		= IPHDR_FIELD("tos",		tos),
		[IPHDR_LENGTH]		= IPHDR_FIELD("length",		tot_len),
		[IPHDR_ID]		= IPHDR_FIELD("id",		id),
		[IPHDR_FRAG_OFF]	= IPHDR_FIELD("frag-off",	frag_off),
		[IPHDR_TTL]		= IPHDR_FIELD("ttl",		ttl),
		[IPHDR_PROTOCOL]	= INET_PROTOCOL("protocol", struct iphdr, protocol),
		[IPHDR_CHECKSUM]	= IPHDR_FIELD("checksum",	check),
		[IPHDR_SADDR]		= IPHDR_ADDR("saddr",		saddr),
		[IPHDR_DADDR]		= IPHDR_ADDR("daddr",		daddr),
	},
};

/*
 * ICMPv6
 */

#include <netinet/icmp6.h>

static const struct symbol_table icmp6_type_tbl = {
	.symbols	= {
		SYMBOL("destination-unreachable",	ICMP6_DST_UNREACH),
		SYMBOL("packet-too-big",		ICMP6_PACKET_TOO_BIG),
		SYMBOL("time-exceeded",			ICMP6_TIME_EXCEEDED),
		SYMBOL("param-problem",			ICMP6_PARAM_PROB),
		SYMBOL("echo-request",			ICMP6_ECHO_REQUEST),
		SYMBOL("echo-reply",			ICMP6_ECHO_REPLY),
		SYMBOL("mld-listener-query",		MLD_LISTENER_QUERY),
		SYMBOL("mld-listener-report",		MLD_LISTENER_REPORT),
		SYMBOL("mld-listener-reduction",	MLD_LISTENER_REDUCTION),
		SYMBOL("nd-router-solicit",		ND_ROUTER_SOLICIT),
		SYMBOL("nd-router-advert",		ND_ROUTER_ADVERT),
		SYMBOL("nd-neighbor-solicit",		ND_NEIGHBOR_SOLICIT),
		SYMBOL("nd-neighbor-advert",		ND_NEIGHBOR_ADVERT),
		SYMBOL("nd-redirect",			ND_REDIRECT),
		SYMBOL("router-renumbering",		ICMP6_ROUTER_RENUMBERING),
		SYMBOL_LIST_END
	},
};

static const struct datatype icmp6_type_type = {
	.type		= TYPE_ICMP6_TYPE,
	.name		= "icmpv6_type",
	.desc		= "ICMPv6 type",
	.byteorder	= BYTEORDER_BIG_ENDIAN,
	.size		= BITS_PER_BYTE,
	.basetype	= &integer_type,
	.sym_tbl	= &icmp6_type_tbl,
};

#define ICMP6HDR_FIELD(__name, __member) \
	HDR_FIELD(__name, struct icmp6_hdr, __member)
#define ICMP6HDR_TYPE(__name, __type, __member) \
	HDR_TYPE(__name, __type, struct icmp6_hdr, __member)

const struct payload_desc payload_icmp6 = {
	.name		= "icmpv6",
	.base		= PAYLOAD_BASE_TRANSPORT_HDR,
	.templates	= {
		[ICMP6HDR_TYPE]		= ICMP6HDR_TYPE("type", &icmp6_type_type, icmp6_type),
		[ICMP6HDR_CODE]		= ICMP6HDR_FIELD("code", icmp6_code),
		[ICMP6HDR_CHECKSUM]	= ICMP6HDR_FIELD("checksum", icmp6_cksum),
		[ICMP6HDR_PPTR]		= ICMP6HDR_FIELD("parameter-problem", icmp6_pptr),
		[ICMP6HDR_MTU]		= ICMP6HDR_FIELD("packet-too-big", icmp6_mtu),
		[ICMP6HDR_ID]		= ICMP6HDR_FIELD("id", icmp6_id),
		[ICMP6HDR_SEQ]		= ICMP6HDR_FIELD("sequence", icmp6_seq),
		[ICMP6HDR_MAXDELAY]	= ICMP6HDR_FIELD("max-delay", icmp6_maxdelay),
	},
};

/*
 * IPv6
 */

#define IP6HDR_FIELD(__name,  __member) \
	HDR_FIELD(__name, struct ipv6hdr, __member)
#define IP6HDR_ADDR(__name, __member) \
	HDR_TYPE(__name, &ip6addr_type, struct ipv6hdr, __member)
#define IP6HDR_PROTOCOL(__name, __member) \
	HDR_TYPE(__name, &inet_service_type, struct ipv6hdr, __member)

const struct payload_desc payload_ip6 = {
	.name		= "ip6",
	.base		= PAYLOAD_BASE_NETWORK_HDR,
	.protocol_key	= IP6HDR_NEXTHDR,
	.protocols	= {
		PAYLOAD_PROTO(IPPROTO_ESP,	&payload_esp),
		PAYLOAD_PROTO(IPPROTO_AH,	&payload_ah),
		PAYLOAD_PROTO(IPPROTO_COMP,	&payload_comp),
		PAYLOAD_PROTO(IPPROTO_UDP,	&payload_udp),
		PAYLOAD_PROTO(IPPROTO_UDPLITE,	&payload_udplite),
		PAYLOAD_PROTO(IPPROTO_TCP,	&payload_tcp),
		PAYLOAD_PROTO(IPPROTO_DCCP,	&payload_dccp),
		PAYLOAD_PROTO(IPPROTO_SCTP,	&payload_sctp),
		PAYLOAD_PROTO(IPPROTO_ICMPV6,	&payload_icmp6),
	},
	.templates	= {
		[IP6HDR_VERSION]	= HDR_BITFIELD("version", &integer_type, 0, 4),
		[IP6HDR_PRIORITY]	= HDR_BITFIELD("priority", &integer_type, 4, 4),
		[IP6HDR_FLOWLABEL]	= IP6HDR_FIELD("flowlabel",	flow_lbl),
		[IP6HDR_LENGTH]		= IP6HDR_FIELD("length",	payload_len),
		[IP6HDR_NEXTHDR]	= INET_PROTOCOL("nexthdr", struct ipv6hdr, nexthdr),
		[IP6HDR_HOPLIMIT]	= IP6HDR_FIELD("hoplimit",	hop_limit),
		[IP6HDR_SADDR]		= IP6HDR_ADDR("saddr",		saddr),
		[IP6HDR_DADDR]		= IP6HDR_ADDR("daddr",		daddr),
	},
};

/*
 * ARP
 */

#include <net/if_arp.h>

static const struct symbol_table arpop_tbl = {
	.symbols	= {
		SYMBOL("request",	ARPOP_REQUEST),
		SYMBOL("reply",		ARPOP_REPLY),
		SYMBOL("rrequest",	ARPOP_RREQUEST),
		SYMBOL("rreply",	ARPOP_REPLY),
		SYMBOL("inrequest",	ARPOP_InREQUEST),
		SYMBOL("inreply",	ARPOP_InREPLY),
		SYMBOL("nak",		ARPOP_NAK),
		SYMBOL_LIST_END
	},
};

static const struct datatype arpop_type = {
	.type		= TYPE_ARPOP,
	.name		= "arp_op",
	.desc		= "ARP operation",
	.byteorder	= BYTEORDER_BIG_ENDIAN,
	.size		= 2 * BITS_PER_BYTE,
	.basetype	= &integer_type,
	.sym_tbl	= &arpop_tbl,
};

#define ARPHDR_TYPE(__name, __type, __member) \
	HDR_TYPE(__name, __type, struct arphdr, __member)
#define ARPHDR_FIELD(__name, __member) \
	HDR_FIELD(__name, struct arphdr, __member)

const struct payload_desc payload_arp = {
	.name		= "arp",
	.base		= PAYLOAD_BASE_NETWORK_HDR,
	.templates	= {
		[ARPHDR_HRD]		= ARPHDR_FIELD("htype",	ar_hrd),
		[ARPHDR_PRO]		= ARPHDR_TYPE("ptype", &ethertype_type, ar_pro),
		[ARPHDR_HLN]		= ARPHDR_FIELD("hlen", ar_hln),
		[ARPHDR_PLN]		= ARPHDR_FIELD("plen", ar_pln),
		[ARPHDR_OP]		= ARPHDR_TYPE("operation", &arpop_type, ar_op),
	},
};

/*
 * VLAN
 */

#include <net/ethernet.h>

#define VLANHDR_BITFIELD(__name, __offset, __len) \
	HDR_BITFIELD(__name, &integer_type, __offset, __len)
#define VLANHDR_TYPE(__name, __type, __member) \
	HDR_TYPE(__name, __type, struct vlan_hdr, __member)

const struct payload_desc payload_vlan = {
	.name		= "vlan",
	.base		= PAYLOAD_BASE_LL_HDR,
	.protocol_key	= VLANHDR_TYPE,
	.protocols	= {
		PAYLOAD_PROTO(ETH_P_IP,		&payload_ip),
		PAYLOAD_PROTO(ETH_P_ARP,	&payload_arp),
		PAYLOAD_PROTO(ETH_P_IPV6,	&payload_ip6),
		PAYLOAD_PROTO(ETH_P_8021Q,	&payload_vlan),

	},
	.templates	= {
		[VLANHDR_VID]		= VLANHDR_BITFIELD("id", 0, 12),
		[VLANHDR_CFI]		= VLANHDR_BITFIELD("cfi", 12, 1),
		[VLANHDR_PCP]		= VLANHDR_BITFIELD("pcp", 13, 3),
		[VLANHDR_TYPE]		= VLANHDR_TYPE("type", &ethertype_type, vlan_type),
	},
};

/*
 * Ethernet
 */

const struct datatype etheraddr_type = {
	.type		= TYPE_ETHERADDR,
	.name		= "etheraddr",
	.desc		= "Ethernet address",
	.byteorder	= BYTEORDER_HOST_ENDIAN,
	.size		= ETH_ALEN * BITS_PER_BYTE,
	.basetype	= &lladdr_type,
};

static const struct symbol_table ethertype_tbl = {
	.symbols	= {
		SYMBOL("ip",		ETH_P_IP),
		SYMBOL("arp",		ETH_P_ARP),
		SYMBOL("ip6",		ETH_P_IPV6),
		SYMBOL("vlan",		ETH_P_8021Q),
		SYMBOL_LIST_END
	},
};

static struct error_record *ethertype_parse(const struct expr *sym,
					    struct expr **res)
{
	struct error_record *erec;

	*res = NULL;
	erec = sym->dtype->basetype->parse(sym, res);
	if (erec != NULL)
		return erec;
	if (*res)
		return NULL;
	return symbolic_constant_parse(sym, &ethertype_tbl, res);
}

static void ethertype_print(const struct expr *expr)
{
	return symbolic_constant_print(&ethertype_tbl, expr);
}

const struct datatype ethertype_type = {
	.type		= TYPE_ETHERTYPE,
	.name		= "ethertype",
	.desc		= "Ethernet protocol",
	.byteorder	= BYTEORDER_BIG_ENDIAN,
	.size		= 2 * BITS_PER_BYTE,
	.basetype	= &integer_type,
	.basefmt	= "0x%.4Zx",
	.print		= ethertype_print,
	.parse		= ethertype_parse,
};

#define ETHHDR_TEMPLATE(__name, __dtype, __member) \
	HDR_TEMPLATE(__name, __dtype, struct ether_header, __member)
#define ETHHDR_TYPE(__name, __member) \
	ETHHDR_TEMPLATE(__name, &ethertype_type, __member)
#define ETHHDR_ADDR(__name, __member) \
	ETHHDR_TEMPLATE(__name, &etheraddr_type, __member)

const struct payload_desc payload_eth = {
	.name		= "ether",
	.base		= PAYLOAD_BASE_LL_HDR,
	.protocol_key	= ETHHDR_TYPE,
	.protocols	= {
		PAYLOAD_PROTO(ETH_P_IP,		&payload_ip),
		PAYLOAD_PROTO(ETH_P_ARP,	&payload_arp),
		PAYLOAD_PROTO(ETH_P_IPV6,	&payload_ip6),
		PAYLOAD_PROTO(ETH_P_8021Q,	&payload_vlan),
	},
	.templates	= {
		[ETHHDR_DADDR]		= ETHHDR_ADDR("daddr", ether_dhost),
		[ETHHDR_SADDR]		= ETHHDR_ADDR("saddr", ether_shost),
		[ETHHDR_TYPE]		= ETHHDR_TYPE("type", ether_type),
	},
};

static void __init payload_init(void)
{
	datatype_register(&icmp_type_type);
	datatype_register(&tcp_flag_type);
	datatype_register(&dccp_pkttype_type);
	datatype_register(&arpop_type);
	datatype_register(&ethertype_type);
	datatype_register(&icmp6_type_type);
}
