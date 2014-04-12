/*
 * Payload expression and related functions.
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
#include <gmputil.h>
#include <utils.h>

static void payload_expr_print(const struct expr *expr)
{
	const struct proto_desc *desc;
	const struct proto_hdr_template *tmpl;

	desc = expr->payload.desc;
	tmpl = expr->payload.tmpl;
	if (desc != NULL && tmpl != NULL)
		printf("%s %s", desc->name, tmpl->token);
	else
		printf("payload @%s,%u,%u",
		       proto_base_tokens[expr->payload.base],
		       expr->payload.offset, expr->len);
}

static bool payload_expr_cmp(const struct expr *e1, const struct expr *e2)
{
	return e1->payload.desc   == e2->payload.desc &&
	       e1->payload.tmpl   == e2->payload.tmpl &&
	       e1->payload.base   == e2->payload.base &&
	       e1->payload.offset == e2->payload.offset;
}

static void payload_expr_clone(struct expr *new, const struct expr *expr)
{
	new->payload.desc   = expr->payload.desc;
	new->payload.tmpl   = expr->payload.tmpl;
	new->payload.base   = expr->payload.base;
	new->payload.offset = expr->payload.offset;
}

/**
 * payload_expr_pctx_update - update protocol context based on payload match
 *
 * @ctx:	protocol context
 * @expr:	relational payload expression
 *
 * Update protocol context for relational payload expressions.
 */
static void payload_expr_pctx_update(struct proto_ctx *ctx,
				     const struct expr *expr)
{
	const struct expr *left = expr->left, *right = expr->right;
	const struct proto_desc *base, *desc;

	if (!(left->flags & EXPR_F_PROTOCOL))
		return;

	assert(expr->op == OP_EQ);
	base = ctx->protocol[left->payload.base].desc;
	desc = proto_find_upper(base, mpz_get_uint32(right->value));

	proto_ctx_update(ctx, left->payload.base + 1, &expr->location, desc);
}

static const struct expr_ops payload_expr_ops = {
	.type		= EXPR_PAYLOAD,
	.name		= "payload",
	.print		= payload_expr_print,
	.cmp		= payload_expr_cmp,
	.clone		= payload_expr_clone,
	.pctx_update	= payload_expr_pctx_update,
};

struct expr *payload_expr_alloc(const struct location *loc,
				const struct proto_desc *desc,
				unsigned int type)
{
	const struct proto_hdr_template *tmpl;
	enum proto_bases base;
	struct expr *expr;
	unsigned int flags = 0;

	if (desc != NULL) {
		tmpl = &desc->templates[type];
		base = desc->base;
		if (type == desc->protocol_key)
			flags = EXPR_F_PROTOCOL;
	} else {
		tmpl = &proto_unknown_template;
		base = PROTO_BASE_INVALID;
	}

	expr = expr_alloc(loc, &payload_expr_ops, tmpl->dtype,
			  tmpl->dtype->byteorder, tmpl->len);
	expr->flags |= flags;

	expr->payload.desc   = desc;
	expr->payload.tmpl   = tmpl;
	expr->payload.base   = base;
	expr->payload.offset = tmpl->offset;

	return expr;
}

void payload_init_raw(struct expr *expr, enum proto_bases base,
		      unsigned int offset, unsigned int len)
{
	expr->payload.base	= base;
	expr->payload.offset	= offset;
	expr->len		= len;
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
	const struct hook_proto_desc *h = &hook_proto_desc[ctx->pctx.family];
	const struct proto_desc *desc;
	const struct proto_hdr_template *tmpl;
	struct expr *dep, *left, *right;
	int protocol;
	uint16_t type;

	if (expr->payload.base < h->base) {
		if (expr->payload.base < h->base - 1)
			return expr_error(ctx->msgs, expr,
					  "payload base is invalid for this "
					  "family");

		if (proto_dev_type(expr->payload.desc, &type) < 0)
			return expr_error(ctx->msgs, expr,
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
	/* Special case for mixed IPv4/IPv6 tables: use meta L4 proto */
	if (desc == NULL &&
	    ctx->pctx.family == NFPROTO_INET &&
	    expr->payload.base == PROTO_BASE_TRANSPORT_HDR)
		desc = &proto_inet_service;

	if (desc == NULL)
		return expr_error(ctx->msgs, expr,
				  "ambiguous payload specification: "
				  "no %s protocol specified",
				  proto_base_names[expr->payload.base - 1]);

	protocol = proto_find_num(desc, expr->payload.desc);
	if (protocol < 0)
		return expr_error(ctx->msgs, expr,
				  "conflicting protocols specified: %s vs. %s",
				  desc->name, expr->payload.desc->name);

	tmpl = &desc->templates[desc->protocol_key];
	if (tmpl->meta_key)
		left = meta_expr_alloc(&expr->location, tmpl->meta_key);
	else
		left = payload_expr_alloc(&expr->location, desc, desc->protocol_key);

	right = constant_expr_alloc(&expr->location, tmpl->dtype,
				    BYTEORDER_HOST_ENDIAN,
				    tmpl->len,
				    constant_data_ptr(protocol, tmpl->len));

	dep = relational_expr_alloc(&expr->location, OP_EQ, left, right);
	left->ops->pctx_update(&ctx->pctx, dep);
	*res = dep;
	return 0;
}

/**
 * payload_expr_complete - fill in type information of a raw payload expr
 *
 * @expr:	the payload expression
 * @ctx:	protocol context
 *
 * Complete the type of a raw payload expression based on the context. If
 * insufficient information is available the expression remains unchanged.
 */
void payload_expr_complete(struct expr *expr, const struct proto_ctx *ctx)
{
	const struct proto_desc *desc;
	const struct proto_hdr_template *tmpl;
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
 * @ctx:	protocol context
 *
 * Expand a merged adjacent payload expression into its original components
 * by splitting elements off the beginning matching a payload template.
 *
 * Note: this requires all payload templates to be specified in ascending
 * 	 offset order.
 */
void payload_expr_expand(struct list_head *list, struct expr *expr,
			 const struct proto_ctx *ctx)
{
	const struct proto_desc *desc;
	const struct proto_hdr_template *tmpl;
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
