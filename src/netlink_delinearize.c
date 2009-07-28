/*
 * Copyright (c) 2008 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Development of this code funded by Astaro AG (http://www.astaro.com/)
 */

#include <limits.h>
#include <linux/netfilter/nf_tables.h>
#include <netlink.h>
#include <rule.h>
#include <statement.h>
#include <expression.h>
#include <gmputil.h>
#include <utils.h>
#include <erec.h>

struct netlink_parse_ctx {
	struct list_head	*msgs;
	struct table		*table;
	struct rule		*rule;
	struct expr		*registers[NFT_REG_MAX + 1];
};

static void __fmtstring(3, 4) netlink_error(struct netlink_parse_ctx *ctx,
					    const struct location *loc,
					    const char *fmt, ...)
{
	struct error_record *erec;
	va_list ap;

	va_start(ap, fmt);
	erec = erec_vcreate(EREC_ERROR, loc, fmt, ap);
	va_end(ap);
	erec_queue(erec, ctx->msgs);
}

static void netlink_set_register(struct netlink_parse_ctx *ctx,
				 enum nft_registers reg,
				 struct expr *expr)
{
	if (reg > NFT_REG_MAX) {
		netlink_error(ctx, &expr->location,
			      "Invalid destination register %u", reg);
		expr_free(expr);
		return;
	}

	ctx->registers[reg] = expr;
}

static struct expr *netlink_get_register(struct netlink_parse_ctx *ctx,
					 const struct location *loc,
					 enum nft_registers reg)
{
	struct expr *expr;

	if (reg == NFT_REG_VERDICT || reg > NFT_REG_MAX) {
		netlink_error(ctx, loc, "Invalid source register %u", reg);
		return NULL;
	}

	expr = ctx->registers[reg];
	ctx->registers[reg] = NULL;
	return expr;
}

static void netlink_parse_immediate(struct netlink_parse_ctx *ctx,
				    const struct location *loc,
				    const struct nfnl_nft_expr *nle)
{
	const struct nfnl_nft_data *data = nfnl_nft_immediate_get_data(nle);
	enum nft_registers dreg = nfnl_nft_immediate_get_dreg(nle);
	struct stmt *stmt;
	struct expr *expr;

	expr = netlink_alloc_data(loc, data, dreg);
	if (dreg == NFT_REG_VERDICT) {
		stmt = verdict_stmt_alloc(loc, expr);
		list_add_tail(&stmt->list, &ctx->rule->stmts);
	} else
		netlink_set_register(ctx, dreg, expr);
}

static enum ops netlink_parse_cmp_op(const struct nfnl_nft_expr *nle)
{
	switch (nfnl_nft_cmp_get_op(nle)) {
	case NFT_CMP_EQ:
		return OP_EQ;
	case NFT_CMP_NEQ:
		return OP_NEQ;
	case NFT_CMP_LT:
		return OP_LT;
	case NFT_CMP_LTE:
		return OP_LTE;
	case NFT_CMP_GT:
		return OP_GT;
	case NFT_CMP_GTE:
		return OP_GTE;
	default:
		return OP_INVALID;
	}
}

static void netlink_parse_cmp(struct netlink_parse_ctx *ctx,
			      const struct location *loc,
			      const struct nfnl_nft_expr *nle)
{
	const struct nfnl_nft_data *data = nfnl_nft_cmp_get_data(nle);
	struct expr *expr, *left, *right;
	struct stmt *stmt;
	enum ops op;

	left = netlink_get_register(ctx, loc, nfnl_nft_cmp_get_sreg(nle));
	if (left == NULL)
		return netlink_error(ctx, loc,
				     "Relational expression has no left "
				     "hand side");

	op = netlink_parse_cmp_op(nle);
	right = netlink_alloc_value(loc, data);

	// FIXME
	if (left->len && left->dtype && left->dtype->type != TYPE_STRING &&
	    left->len != right->len)
		return netlink_error(ctx, loc,
				     "Relational expression size mismatch");

	expr = relational_expr_alloc(loc, op, left, right);
	stmt = expr_stmt_alloc(loc, expr);
	list_add_tail(&stmt->list, &ctx->rule->stmts);
}

static void netlink_parse_lookup(struct netlink_parse_ctx *ctx,
				 const struct location *loc,
				 const struct nfnl_nft_expr *nle)
{
	struct stmt *stmt;
	struct expr *expr, *left, *right;
	struct set *set;
	enum nft_registers dreg;

	left = netlink_get_register(ctx, loc, nfnl_nft_lookup_get_sreg(nle));
	if (left == NULL)
		return netlink_error(ctx, loc,
				     "Lookup expression has no left hand side");

	set = set_lookup(ctx->table, nfnl_nft_lookup_get_set(nle));
	if (set == NULL)
		return netlink_error(ctx, loc,
				     "Unknown set '%s' in lookup expression",
				     nfnl_nft_lookup_get_set(nle));

	right = set_ref_expr_alloc(loc, set);

	if (nfnl_nft_lookup_test_dreg(nle)) {
		dreg = nfnl_nft_lookup_get_dreg(nle);
		expr = map_expr_alloc(loc, left, right);
		if (dreg != NFT_REG_VERDICT)
			return netlink_set_register(ctx, dreg, expr);
	} else {
		expr = relational_expr_alloc(loc, OP_LOOKUP, left, right);
	}

	stmt = expr_stmt_alloc(loc, expr);
	list_add_tail(&stmt->list, &ctx->rule->stmts);
}

static void netlink_parse_bitwise(struct netlink_parse_ctx *ctx,
				  const struct location *loc,
				  const struct nfnl_nft_expr *nle)
{
	struct expr *expr, *left, *mask, *xor, *or;
	mpz_t m, x, o;

	left = netlink_get_register(ctx, loc, nfnl_nft_bitwise_get_sreg(nle));
	if (left == NULL)
		return netlink_error(ctx, loc,
				     "Bitwise expression has no left "
				     "hand side");

	expr = left;

	mask = netlink_alloc_value(loc, nfnl_nft_bitwise_get_mask(nle));
	mpz_init_set(m, mask->value);

	xor  = netlink_alloc_value(loc, nfnl_nft_bitwise_get_xor(nle));
	mpz_init_set(x, xor->value);

	mpz_init_set_ui(o, 0);
	if (mpz_scan0(m, 0) != mask->len || mpz_cmp_ui(x, 0)) {
		/* o = (m & x) ^ x */
		mpz_and(o, m, x);
		mpz_xor(o, o, x);
		/* x &= m */
		mpz_and(x, x, m);
		/* m |= o */
		mpz_ior(m, m, o);
	}

	if (mpz_scan0(m, 0) != left->len) {
		mpz_set(mask->value, m);
		expr = binop_expr_alloc(loc, OP_AND, expr, mask);
		expr->len = left->len;
	} else
		expr_free(mask);

	if (mpz_cmp_ui(x, 0)) {
		mpz_set(xor->value, x);
		expr = binop_expr_alloc(loc, OP_XOR, expr, xor);
		expr->len = left->len;
	} else
		expr_free(xor);

	if (mpz_cmp_ui(o, 0)) {
		or = netlink_alloc_value(loc, nfnl_nft_bitwise_get_xor(nle));
		mpz_set(or->value, o);
		expr = binop_expr_alloc(loc, OP_OR, expr, or);
		expr->len = left->len;
	}

	mpz_clear(m);
	mpz_clear(x);
	mpz_clear(o);

	netlink_set_register(ctx, nfnl_nft_bitwise_get_dreg(nle), expr);
}

static void netlink_parse_byteorder(struct netlink_parse_ctx *ctx,
				    const struct location *loc,
				    const struct nfnl_nft_expr *nle)
{
	struct expr *expr, *arg;
	enum ops op;

	arg = netlink_get_register(ctx, loc, nfnl_nft_byteorder_get_sreg(nle));
	if (arg == NULL)
		return netlink_error(ctx, loc,
				     "Byteorder expression has no left "
				     "hand side");

	switch (nfnl_nft_byteorder_get_op(nle)) {
	case NFT_BYTEORDER_NTOH:
		op = OP_NTOH;
		break;
	case NFT_BYTEORDER_HTON:
		op = OP_HTON;
		break;
	default:
		BUG();
	}

	expr = unary_expr_alloc(loc, op, arg);
	expr->len = arg->len;
	netlink_set_register(ctx, nfnl_nft_byteorder_get_dreg(nle), expr);
}

static void netlink_parse_payload(struct netlink_parse_ctx *ctx,
				  const struct location *loc,
				  const struct nfnl_nft_expr *nle)
{
	struct expr *expr;

	expr = payload_expr_alloc(loc, NULL, 0);
	payload_init_raw(expr, nfnl_nft_payload_get_base(nle) + 1,
			 nfnl_nft_payload_get_offset(nle) * BITS_PER_BYTE,
			 nfnl_nft_payload_get_len(nle) * BITS_PER_BYTE);

	netlink_set_register(ctx, nfnl_nft_payload_get_dreg(nle), expr);
}

static void netlink_parse_exthdr(struct netlink_parse_ctx *ctx,
				 const struct location *loc,
				 const struct nfnl_nft_expr *nle)
{
	struct expr *expr;

	expr = exthdr_expr_alloc(loc, NULL, 0);
	exthdr_init_raw(expr, nfnl_nft_exthdr_get_type(nle),
			nfnl_nft_exthdr_get_offset(nle) * BITS_PER_BYTE,
			nfnl_nft_exthdr_get_len(nle) * BITS_PER_BYTE);

	netlink_set_register(ctx, nfnl_nft_exthdr_get_dreg(nle), expr);
}

static void netlink_parse_meta(struct netlink_parse_ctx *ctx,
			       const struct location *loc,
			       const struct nfnl_nft_expr *nle)
{
	struct expr *expr;

	expr = meta_expr_alloc(loc, nfnl_nft_meta_get_key(nle));
	netlink_set_register(ctx, nfnl_nft_meta_get_dreg(nle), expr);
}

static void netlink_parse_ct(struct netlink_parse_ctx *ctx,
			     const struct location *loc,
			     const struct nfnl_nft_expr *nle)
{
	struct expr *expr;

	expr = ct_expr_alloc(loc, nfnl_nft_ct_get_key(nle));
	netlink_set_register(ctx, nfnl_nft_ct_get_dreg(nle), expr);
}

static void netlink_parse_counter(struct netlink_parse_ctx *ctx,
				  const struct location *loc,
				  const struct nfnl_nft_expr *nle)
{
	struct stmt *stmt;

	stmt = counter_stmt_alloc(loc);
	stmt->counter.packets = nfnl_nft_counter_get_packets(nle);
	stmt->counter.bytes   = nfnl_nft_counter_get_bytes(nle);
	list_add_tail(&stmt->list, &ctx->rule->stmts);
}

static void netlink_parse_log(struct netlink_parse_ctx *ctx,
			      const struct location *loc,
			      const struct nfnl_nft_expr *nle)
{
	struct stmt *stmt;
	const char *prefix;

	stmt = log_stmt_alloc(loc);
	prefix = nfnl_nft_log_get_prefix(nle);
	if (prefix != NULL)
		stmt->log.prefix = xstrdup(prefix);
	stmt->log.group	     = nfnl_nft_log_get_group(nle);
	stmt->log.snaplen    = nfnl_nft_log_get_snaplen(nle);
	stmt->log.qthreshold = nfnl_nft_log_get_qthreshold(nle);
	list_add_tail(&stmt->list, &ctx->rule->stmts);
}

static void netlink_parse_limit(struct netlink_parse_ctx *ctx,
				const struct location *loc,
				const struct nfnl_nft_expr *nle)
{
	struct stmt *stmt;

	stmt = limit_stmt_alloc(loc);
	stmt->limit.rate  = nfnl_nft_limit_get_rate(nle);
	stmt->limit.depth = nfnl_nft_limit_get_depth(nle);
	list_add_tail(&stmt->list, &ctx->rule->stmts);
}

static void netlink_parse_reject(struct netlink_parse_ctx *ctx,
				 const struct location *loc,
				 const struct nfnl_nft_expr *expr)
{
	struct stmt *stmt;

	stmt = reject_stmt_alloc(loc);
	list_add_tail(&stmt->list, &ctx->rule->stmts);
}

static void netlink_parse_nat(struct netlink_parse_ctx *ctx,
			      const struct location *loc,
			      const struct nfnl_nft_expr *nle)
{
	struct stmt *stmt;
	struct expr *addr, *proto;
	enum nft_registers reg1, reg2;

	stmt = nat_stmt_alloc(loc);
	stmt->nat.type = nfnl_nft_nat_get_type(nle);

	reg1 = nfnl_nft_nat_get_sreg_addr_min(nle);
	if (reg1) {
		addr = netlink_get_register(ctx, loc, reg1);
		if (addr == NULL)
			return netlink_error(ctx, loc,
					     "NAT statement has no address "
					     "expression");

		expr_set_type(addr, &ipaddr_type, BYTEORDER_BIG_ENDIAN);
		stmt->nat.addr = addr;
	}

	reg2 = nfnl_nft_nat_get_sreg_addr_max(nle);
	if (reg2 && reg2 != reg1) {
		addr = netlink_get_register(ctx, loc, reg2);
		if (addr == NULL)
			return netlink_error(ctx, loc,
					     "NAT statement has no address "
					     "expression");

		expr_set_type(addr, &ipaddr_type, BYTEORDER_BIG_ENDIAN);
		if (stmt->nat.addr != NULL)
			addr = range_expr_alloc(loc, stmt->nat.addr, addr);
		stmt->nat.addr = addr;
	}

	reg1 = nfnl_nft_nat_get_sreg_proto_min(nle);
	if (reg1) {
		proto = netlink_get_register(ctx, loc, reg1);
		if (proto == NULL)
			return netlink_error(ctx, loc,
					     "NAT statement has no proto "
					     "expression");

		expr_set_type(proto, &inet_service_type, BYTEORDER_BIG_ENDIAN);
		stmt->nat.proto = proto;
	}

	reg2 = nfnl_nft_nat_get_sreg_proto_max(nle);
	if (reg2 && reg2 != reg1) {
		proto = netlink_get_register(ctx, loc, reg1);
		if (proto == NULL)
			return netlink_error(ctx, loc,
					     "NAT statement has no proto "
					     "expression");

		expr_set_type(proto, &inet_service_type, BYTEORDER_BIG_ENDIAN);
		stmt->nat.proto = proto;
		if (stmt->nat.proto != NULL)
			proto = range_expr_alloc(loc, stmt->nat.proto, proto);
		stmt->nat.proto = proto;
	}

	list_add_tail(&stmt->list, &ctx->rule->stmts);
}

static const struct {
	const char	*name;
	void		(*parse)(struct netlink_parse_ctx *ctx,
				 const struct location *loc,
				 const struct nfnl_nft_expr *nle);
} netlink_parsers[] = {
	{ .name = "immediate",	.parse = netlink_parse_immediate },
	{ .name = "cmp",	.parse = netlink_parse_cmp },
	{ .name = "lookup",	.parse = netlink_parse_lookup },
	{ .name = "bitwise",	.parse = netlink_parse_bitwise },
	{ .name = "byteorder",	.parse = netlink_parse_byteorder },
	{ .name = "payload",	.parse = netlink_parse_payload },
	{ .name = "exthdr",	.parse = netlink_parse_exthdr },
	{ .name = "meta",	.parse = netlink_parse_meta },
	{ .name = "ct",		.parse = netlink_parse_ct },
	{ .name = "counter",	.parse = netlink_parse_counter },
	{ .name = "log",	.parse = netlink_parse_log },
	{ .name = "limit",	.parse = netlink_parse_limit },
	{ .name = "reject",	.parse = netlink_parse_reject },
	{ .name = "nat",	.parse = netlink_parse_nat },
};

static const struct input_descriptor indesc_netlink = {
	.name = "netlink",
	.type  = INDESC_NETLINK,
};

static void netlink_parse_expr(struct nl_object *obj, void *arg)
{
	const struct nfnl_nft_expr *nle = (struct nfnl_nft_expr *)obj;
	const char *type = nfnl_nft_expr_get_type(nle);
	struct netlink_parse_ctx *ctx = arg;
	struct location loc;
	unsigned int i;

	memset(&loc, 0, sizeof(loc));
	loc.indesc = &indesc_netlink;
	loc.nl_obj = obj;

	for (i = 0; i < array_size(netlink_parsers); i++) {
		if (strcmp(type, netlink_parsers[i].name))
			continue;
		return netlink_parsers[i].parse(ctx, &loc, nle);
	}

	netlink_error(ctx, &loc, "unknown expression type '%s'", type);
}

struct rule_pp_ctx {
	struct payload_ctx	pctx;
};

static void payload_match_postprocess(struct payload_ctx *ctx,
				      struct stmt *stmt, struct expr *expr)
{
	struct expr *left = expr->left, *right = expr->right, *tmp;
	struct list_head list = LIST_HEAD_INIT(list);
	struct stmt *nstmt;
	struct expr *nexpr;

	switch (expr->op) {
	case OP_EQ:
	case OP_NEQ:
		payload_expr_expand(&list, left, ctx);
		list_for_each_entry(left, &list, list) {
			tmp = constant_expr_splice(right, left->len);
			expr_set_type(tmp, left->dtype, left->byteorder);
			nexpr = relational_expr_alloc(&expr->location, expr->op,
						      left, tmp);
			payload_ctx_update(ctx, nexpr);

			nstmt = expr_stmt_alloc(&stmt->location, nexpr);
			list_add_tail(&nstmt->list, &stmt->list);
		}
		list_del(&stmt->list);
		stmt_free(stmt);
		break;
	default:
		payload_expr_complete(left, ctx);
		expr_set_type(expr->right, expr->left->dtype,
			      expr->left->byteorder);
		break;
	}
}

static void meta_match_postprocess(struct payload_ctx *ctx,
				   const struct expr *expr)
{
	switch (expr->op) {
	case OP_EQ:
		payload_ctx_update_meta(ctx, expr);
		break;
	default:
		break;
	}
}

static void expr_postprocess(struct rule_pp_ctx *ctx,
			     struct stmt *stmt, struct expr **exprp)
{
	struct expr *expr = *exprp, *i;

	//pr_debug("%s len %u\n", expr->ops->name, expr->len);

	switch (expr->ops->type) {
	case EXPR_MAP:
		expr_postprocess(ctx, stmt, &expr->expr);
		expr_postprocess(ctx, stmt, &expr->mappings);
		break;
	case EXPR_MAPPING:
		expr_postprocess(ctx, stmt, &expr->left);
		expr_postprocess(ctx, stmt, &expr->right);
		break;
	case EXPR_SET:
		list_for_each_entry(i, &expr->expressions, list)
			expr_postprocess(ctx, stmt, &i);
		break;
	case EXPR_UNARY:
		expr_postprocess(ctx, stmt, &expr->arg);
		expr_set_type(expr->arg, expr->arg->dtype, !expr->arg->byteorder);

		*exprp = expr_get(expr->arg);
		expr_free(expr);
		break;
	case EXPR_BINOP:
		expr_postprocess(ctx, stmt, &expr->left);
		expr_postprocess(ctx, stmt, &expr->right);
		expr_set_type(expr->right, expr->left->dtype,
			      expr->left->byteorder);
		expr_set_type(expr, expr->left->dtype,
			      expr->left->byteorder);
		break;
	case EXPR_RELATIONAL:
		switch (expr->left->ops->type) {
		case EXPR_PAYLOAD:
			payload_match_postprocess(&ctx->pctx, stmt, expr);
			return;
		case EXPR_META:
			meta_match_postprocess(&ctx->pctx, expr);
			break;
		default:
			expr_postprocess(ctx, stmt, &expr->left);
			break;
		}

		expr_set_type(expr->right, expr->left->dtype, expr->left->byteorder);
		expr_postprocess(ctx, stmt, &expr->right);

		if (expr->left->ops->type == EXPR_BINOP &&
		    expr->left->op == OP_AND &&
		    expr->op == OP_NEQ &&
		    expr->right->dtype->basetype->type == TYPE_BITMASK) {
			unsigned int n;

			expr_free(expr->right);
			expr->right = list_expr_alloc(&expr->left->left->location);
			n = 0;
			while ((n = mpz_scan1(expr->left->right->value, n)) != ULONG_MAX) {
				i = constant_expr_alloc(&expr->left->right->location,
							expr->left->left->dtype,
							expr->left->right->byteorder,
							expr->left->right->len, NULL);
				mpz_set_ui(i->value, 1);
				mpz_lshift_ui(i->value, n);
				compound_expr_add(expr->right, i);
				n++;
			}
			expr->left = expr->left->left;
			expr->op = OP_FLAGCMP;
		}
		break;
	case EXPR_PAYLOAD:
		payload_expr_complete(expr, &ctx->pctx);
		break;
	case EXPR_VALUE:
		// FIXME
		if (expr->byteorder == BYTEORDER_HOST_ENDIAN)
			mpz_switch_byteorder(expr->value, expr->len / BITS_PER_BYTE);

		// Quite a hack :)
		if (expr->dtype->type == TYPE_STRING) {
			unsigned int len = expr->len;
			mpz_t tmp;
			mpz_init(tmp);
			while (len >= BITS_PER_BYTE) {
				mpz_bitmask(tmp, BITS_PER_BYTE);
				mpz_lshift_ui(tmp, len - BITS_PER_BYTE);
				mpz_and(tmp, tmp, expr->value);
				if (mpz_cmp_ui(tmp, 0))
					break;
				len -= BITS_PER_BYTE;
			}
			mpz_clear(tmp);
			expr->len = len;
		}
		break;
	case EXPR_SET_REF:
	case EXPR_EXTHDR:
	case EXPR_META:
	case EXPR_CT:
	case EXPR_VERDICT:
		break;
	default:
		printf("%s\n", expr->ops->name);
		BUG();
	}
}

static void rule_parse_postprocess(struct netlink_parse_ctx *ctx, struct rule *rule)
{
	struct rule_pp_ctx rctx;
	struct stmt *stmt, *next;

	payload_ctx_init(&rctx.pctx, rule->handle.family);

	list_for_each_entry_safe(stmt, next, &rule->stmts, list) {
		switch (stmt->ops->type) {
		case STMT_EXPRESSION:
			expr_postprocess(&rctx, stmt, &stmt->expr);
			break;
		case STMT_NAT:
			if (stmt->nat.addr != NULL)
				expr_postprocess(&rctx, stmt, &stmt->nat.addr);
			if (stmt->nat.proto != NULL)
				expr_postprocess(&rctx, stmt, &stmt->nat.proto);
			break;
		default:
			break;
		}
	}
}

struct rule *netlink_delinearize_rule(struct netlink_ctx *ctx,
				      const struct nl_object *obj)
{
	const struct nfnl_nft_rule *nlr = (const struct nfnl_nft_rule *)obj;
	struct netlink_parse_ctx _ctx, *pctx = &_ctx;
	struct handle h;

	memset(&_ctx, 0, sizeof(_ctx));
	_ctx.msgs = ctx->msgs;

	memset(&h, 0, sizeof(h));
	h.family = nfnl_nft_rule_get_family(nlr);
	h.table  = xstrdup(nfnl_nft_rule_get_table(nlr));
	h.chain  = xstrdup(nfnl_nft_rule_get_chain(nlr));
	h.handle = nfnl_nft_rule_get_handle(nlr);

	pctx->rule = rule_alloc(&internal_location, &h);
	pctx->table = table_lookup(&h);
	assert(pctx->table != NULL);
	nfnl_nft_rule_foreach_expr(nlr, netlink_parse_expr, pctx);

	rule_parse_postprocess(pctx, pctx->rule);
	return pctx->rule;
}
