/*
 * Copyright (c) 2008 Patrick McHardy <kaber@trash.net>
 * Copyright (c) 2013 Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Development of this code funded by Astaro AG (http://www.astaro.com/)
 */

#include <linux/netfilter/nf_tables.h>

#include <string.h>
#include <rule.h>
#include <statement.h>
#include <expression.h>
#include <netlink.h>
#include <gmputil.h>
#include <utils.h>

struct netlink_linearize_ctx {
	struct nft_rule		*nlr;
	unsigned int		reg_low;
};

static enum nft_registers get_register(struct netlink_linearize_ctx *ctx)
{
	if (ctx->reg_low > NFT_REG_MAX)
		BUG("register reg_low %u invalid\n", ctx->reg_low);
	return ctx->reg_low++;
}

static void release_register(struct netlink_linearize_ctx *ctx)
{
	ctx->reg_low--;
}

static void netlink_gen_expr(struct netlink_linearize_ctx *ctx,
			     const struct expr *expr,
			     enum nft_registers dreg);

static void netlink_gen_concat(struct netlink_linearize_ctx *ctx,
			       const struct expr *expr,
			       enum nft_registers dreg)
{
	const struct expr *i;

	list_for_each_entry(i, &expr->expressions, list)
		netlink_gen_expr(ctx, i, dreg);
}

static void netlink_gen_payload(struct netlink_linearize_ctx *ctx,
				const struct expr *expr,
				enum nft_registers dreg)
{
	struct nft_rule_expr *nle;

	nle = alloc_nft_expr("payload");
	nft_rule_expr_set_u32(nle, NFT_EXPR_PAYLOAD_DREG, dreg);
	nft_rule_expr_set_u32(nle, NFT_EXPR_PAYLOAD_BASE,
			      expr->payload.base - 1);
	nft_rule_expr_set_u32(nle, NFT_EXPR_PAYLOAD_OFFSET,
			      expr->payload.offset / BITS_PER_BYTE);
	nft_rule_expr_set_u32(nle, NFT_EXPR_PAYLOAD_LEN,
			      expr->len / BITS_PER_BYTE);
	nft_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_exthdr(struct netlink_linearize_ctx *ctx,
			       const struct expr *expr,
			       enum nft_registers dreg)
{
	struct nft_rule_expr *nle;

	nle = alloc_nft_expr("exthdr");
	nft_rule_expr_set_u32(nle, NFT_EXPR_EXTHDR_DREG, dreg);
	nft_rule_expr_set_u8(nle, NFT_EXPR_EXTHDR_TYPE,
			     expr->exthdr.desc->type);
	nft_rule_expr_set_u32(nle, NFT_EXPR_EXTHDR_OFFSET,
			      expr->exthdr.tmpl->offset / BITS_PER_BYTE);
	nft_rule_expr_set_u32(nle, NFT_EXPR_EXTHDR_LEN,
			      expr->len / BITS_PER_BYTE);
	nft_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_meta(struct netlink_linearize_ctx *ctx,
			     const struct expr *expr,
			     enum nft_registers dreg)
{
	struct nft_rule_expr *nle;

	nle = alloc_nft_expr("meta");
	nft_rule_expr_set_u32(nle, NFT_EXPR_META_DREG, dreg);
	nft_rule_expr_set_u32(nle, NFT_EXPR_META_KEY, expr->meta.key);
	nft_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_ct(struct netlink_linearize_ctx *ctx,
			   const struct expr *expr,
			   enum nft_registers dreg)
{
	struct nft_rule_expr *nle;

	nle = alloc_nft_expr("ct");
	nft_rule_expr_set_u32(nle, NFT_EXPR_CT_DREG, dreg);
	nft_rule_expr_set_u32(nle, NFT_EXPR_CT_KEY, expr->ct.key);
	nft_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_map(struct netlink_linearize_ctx *ctx,
			    const struct expr *expr,
			    enum nft_registers dreg)
{
	struct nft_rule_expr *nle;
	enum nft_registers sreg;

	assert(expr->mappings->ops->type == EXPR_SET_REF);

	if (dreg == NFT_REG_VERDICT)
		sreg = get_register(ctx);
	else
		sreg = dreg;

	netlink_gen_expr(ctx, expr->map, sreg);

	nle = alloc_nft_expr("lookup");
	nft_rule_expr_set_u32(nle, NFT_EXPR_LOOKUP_SREG, sreg);
	nft_rule_expr_set_u32(nle, NFT_EXPR_LOOKUP_DREG, dreg);
	nft_rule_expr_set_str(nle, NFT_EXPR_LOOKUP_SET,
			      expr->mappings->set->handle.set);

	if (dreg == NFT_REG_VERDICT)
		release_register(ctx);

	nft_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_lookup(struct netlink_linearize_ctx *ctx,
			       const struct expr *expr,
			       enum nft_registers dreg)
{
	struct nft_rule_expr *nle;
	enum nft_registers sreg;

	assert(expr->right->ops->type == EXPR_SET_REF);
	assert(dreg == NFT_REG_VERDICT);

	sreg = get_register(ctx);
	netlink_gen_expr(ctx, expr->left, sreg);

	nle = alloc_nft_expr("lookup");
	nft_rule_expr_set_u32(nle, NFT_EXPR_LOOKUP_SREG, sreg);
	nft_rule_expr_set_str(nle, NFT_EXPR_LOOKUP_SET,
			      expr->right->set->handle.set);

	release_register(ctx);
	nft_rule_add_expr(ctx->nlr, nle);
}

static enum nft_cmp_ops netlink_gen_cmp_op(enum ops op)
{
	switch (op) {
	case OP_EQ:
		return NFT_CMP_EQ;
	case OP_NEQ:
		return NFT_CMP_NEQ;
	case OP_LT:
		return NFT_CMP_LT;
	case OP_GT:
		return NFT_CMP_GT;
	case OP_LTE:
		return NFT_CMP_LTE;
	case OP_GTE:
		return NFT_CMP_GTE;
	default:
		BUG("invalid comparison operation %u\n", op);
	}
}

static void netlink_gen_cmp(struct netlink_linearize_ctx *ctx,
			    const struct expr *expr,
			    enum nft_registers dreg)
{
	struct nft_rule_expr *nle;
	enum nft_registers sreg;
	struct nft_data_linearize nld, zero = {};
	struct expr *right;

	assert(dreg == NFT_REG_VERDICT);

	sreg = get_register(ctx);
	netlink_gen_expr(ctx, expr->left, sreg);

	if (expr->right->ops->type == EXPR_PREFIX) {
		right = expr->right->prefix;

		netlink_gen_data(expr->right, &nld);
		zero.len = nld.len;

		nle = alloc_nft_expr("bitwise");
		nft_rule_expr_set_u32(nle, NFT_EXPR_BITWISE_SREG, sreg);
		nft_rule_expr_set_u32(nle, NFT_EXPR_BITWISE_DREG, sreg);
		nft_rule_expr_set_u32(nle, NFT_EXPR_BITWISE_LEN, nld.len);
		nft_rule_expr_set(nle, NFT_EXPR_BITWISE_MASK, &nld.value, nld.len);
		nft_rule_expr_set(nle, NFT_EXPR_BITWISE_XOR, &zero.value, zero.len);
		nft_rule_add_expr(ctx->nlr, nle);
	} else {
		right = expr->right;
	}

	nle = alloc_nft_expr("cmp");
	nft_rule_expr_set_u32(nle, NFT_EXPR_CMP_SREG, sreg);
	nft_rule_expr_set_u32(nle, NFT_EXPR_CMP_OP,
			      netlink_gen_cmp_op(expr->op));
	netlink_gen_data(right, &nld);
	nft_rule_expr_set(nle, NFT_EXPR_CMP_DATA, nld.value, nld.len);
	release_register(ctx);

	nft_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_range(struct netlink_linearize_ctx *ctx,
			      const struct expr *expr,
			      enum nft_registers dreg)
{
	struct expr *range = expr->right;
	struct nft_rule_expr *nle;
	enum nft_registers sreg;
	struct nft_data_linearize nld;

	assert(dreg == NFT_REG_VERDICT);

	sreg = get_register(ctx);
	netlink_gen_expr(ctx, expr->left, sreg);

	nle = alloc_nft_expr("cmp");
	nft_rule_expr_set_u32(nle, NFT_EXPR_CMP_SREG, sreg);
	nft_rule_expr_set_u32(nle, NFT_EXPR_CMP_OP,
			      netlink_gen_cmp_op(OP_GTE));
	netlink_gen_data(range->left, &nld);
	nft_rule_expr_set(nle, NFT_EXPR_CMP_DATA, nld.value, nld.len);
	nft_rule_add_expr(ctx->nlr, nle);

	nle = alloc_nft_expr("cmp");
	nft_rule_expr_set_u32(nle, NFT_EXPR_CMP_SREG, sreg);
	nft_rule_expr_set_u32(nle, NFT_EXPR_CMP_OP,
			      netlink_gen_cmp_op(OP_LTE));
	netlink_gen_data(range->right, &nld);
	nft_rule_expr_set(nle, NFT_EXPR_CMP_DATA, nld.value, nld.len);
	nft_rule_add_expr(ctx->nlr, nle);

	release_register(ctx);
}

static void netlink_gen_flagcmp(struct netlink_linearize_ctx *ctx,
				const struct expr *expr,
				enum nft_registers dreg)
{
	struct nft_rule_expr *nle;
	struct nft_data_linearize nld, nld2;
	enum nft_registers sreg;
	unsigned int len;
	mpz_t zero;

	assert(dreg == NFT_REG_VERDICT);

	sreg = get_register(ctx);
	netlink_gen_expr(ctx, expr->left, sreg);
	len = div_round_up(expr->left->len, BITS_PER_BYTE);

	mpz_init_set_ui(zero, 0);

	nle = alloc_nft_expr("bitwise");
	netlink_gen_raw_data(zero, expr->right->byteorder, len, &nld);
	nft_rule_expr_set_u32(nle, NFT_EXPR_BITWISE_SREG, sreg);
	nft_rule_expr_set_u32(nle, NFT_EXPR_BITWISE_DREG, sreg);
	nft_rule_expr_set_u32(nle, NFT_EXPR_BITWISE_LEN, len);
	netlink_gen_data(expr->right, &nld2);
	nft_rule_expr_set(nle, NFT_EXPR_BITWISE_MASK, &nld2.value, nld2.len);
	nft_rule_expr_set(nle, NFT_EXPR_BITWISE_XOR, &nld.value, nld.len);
	nft_rule_add_expr(ctx->nlr, nle);

	nle = alloc_nft_expr("cmp");
	netlink_gen_raw_data(zero, expr->right->byteorder, len, &nld);
	nft_rule_expr_set_u32(nle, NFT_EXPR_CMP_SREG, sreg);
	nft_rule_expr_set_u32(nle, NFT_EXPR_CMP_OP, NFT_CMP_NEQ);
	netlink_gen_data(expr->right, &nld);
	nft_rule_expr_set(nle, NFT_EXPR_CMP_DATA, nld.value, nld.len);
	nft_rule_add_expr(ctx->nlr, nle);

	mpz_clear(zero);
	release_register(ctx);
}

static void netlink_gen_relational(struct netlink_linearize_ctx *ctx,
				   const struct expr *expr,
				   enum nft_registers dreg)
{
	switch (expr->op) {
	case OP_EQ:
	case OP_NEQ:
	case OP_LT:
	case OP_GT:
	case OP_LTE:
	case OP_GTE:
		return netlink_gen_cmp(ctx, expr, dreg);
	case OP_RANGE:
		return netlink_gen_range(ctx, expr, dreg);
	case OP_FLAGCMP:
		return netlink_gen_flagcmp(ctx, expr, dreg);
	case OP_LOOKUP:
		return netlink_gen_lookup(ctx, expr, dreg);
	default:
		BUG("invalid relational operation %u\n", expr->op);
	}
}

static void combine_binop(mpz_t mask, mpz_t xor, const mpz_t m, const mpz_t x)
{
	/* xor = x ^ (xor & m) */
	mpz_and(xor, xor, m);
	mpz_xor(xor, x, xor);
	/* mask &= m */
	mpz_and(mask, mask, m);
}

static void netlink_gen_binop(struct netlink_linearize_ctx *ctx,
			      const struct expr *expr,
			      enum nft_registers dreg)
{
	struct nft_rule_expr *nle;
	struct nft_data_linearize nld;
	struct expr *left, *i;
	struct expr *binops[16];
	mpz_t mask, xor, val, tmp;
	unsigned int len;
	int n = 0;

	mpz_init(mask);
	mpz_init(xor);
	mpz_init(val);
	mpz_init(tmp);

	binops[n++] = left = (void *)expr;
	while (left->ops->type == EXPR_BINOP && left->left != NULL)
		binops[n++] = left = left->left;
	n--;

	netlink_gen_expr(ctx, binops[n--], dreg);

	mpz_bitmask(mask, expr->len);
	mpz_set_ui(xor, 0);
	for (; n >= 0; n--) {
		i = binops[n];
		mpz_set(val, i->right->value);

		switch (i->op) {
		case OP_AND:
			mpz_set_ui(tmp, 0);
			combine_binop(mask, xor, val, tmp);
			break;
		case OP_OR:
			mpz_com(tmp, val);
			combine_binop(mask, xor, tmp, val);
			break;
		case OP_XOR:
			mpz_bitmask(tmp, expr->len);
			combine_binop(mask, xor, tmp, val);
			break;
		default:
			BUG("invalid binary operation %u\n", i->op);
		}
	}

	len = div_round_up(expr->len, BITS_PER_BYTE);

	nle = alloc_nft_expr("bitwise");
	nft_rule_expr_set_u32(nle, NFT_EXPR_BITWISE_SREG, dreg);
	nft_rule_expr_set_u32(nle, NFT_EXPR_BITWISE_DREG, dreg);
	nft_rule_expr_set_u32(nle, NFT_EXPR_BITWISE_LEN, len);

	netlink_gen_raw_data(mask, expr->byteorder, len, &nld);
	nft_rule_expr_set(nle, NFT_EXPR_BITWISE_MASK, nld.value, nld.len);
	netlink_gen_raw_data(xor, expr->byteorder, len, &nld);
	nft_rule_expr_set(nle, NFT_EXPR_BITWISE_XOR, nld.value, nld.len);

	mpz_clear(tmp);
	mpz_clear(val);
	mpz_clear(xor);
	mpz_clear(mask);

	nft_rule_add_expr(ctx->nlr, nle);
}

static enum nft_byteorder_ops netlink_gen_unary_op(enum ops op)
{
	switch (op) {
	case OP_HTON:
		return NFT_BYTEORDER_HTON;
	case OP_NTOH:
		return NFT_BYTEORDER_HTON;
	default:
		BUG("invalid unary operation %u\n", op);
	}
}

static void netlink_gen_unary(struct netlink_linearize_ctx *ctx,
			      const struct expr *expr,
			      enum nft_registers dreg)
{
	struct nft_rule_expr *nle;

	netlink_gen_expr(ctx, expr->arg, dreg);

	nle = alloc_nft_expr("byteorder");
	nft_rule_expr_set_u32(nle, NFT_EXPR_BYTEORDER_SREG, dreg);
	nft_rule_expr_set_u32(nle, NFT_EXPR_BYTEORDER_DREG, dreg);
	nft_rule_expr_set_u32(nle, NFT_EXPR_BYTEORDER_LEN,
			      expr->len / BITS_PER_BYTE);
	nft_rule_expr_set_u32(nle, NFT_EXPR_BYTEORDER_SIZE,
			      expr->arg->len % 32 ? 2 : 4);
	nft_rule_expr_set_u32(nle, NFT_EXPR_BYTEORDER_OP,
			      netlink_gen_unary_op(expr->op));
	nft_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_immediate(struct netlink_linearize_ctx *ctx,
				  const struct expr *expr,
				  enum nft_registers dreg)
{
	struct nft_rule_expr *nle;
	struct nft_data_linearize nld;

	nle = alloc_nft_expr("immediate");
	nft_rule_expr_set_u32(nle, NFT_EXPR_IMM_DREG, dreg);
	netlink_gen_data(expr, &nld);
	switch (expr->ops->type) {
	case EXPR_VALUE:
		nft_rule_expr_set(nle, NFT_EXPR_IMM_DATA, nld.value, nld.len);
		break;
	case EXPR_VERDICT:
		if ((expr->chain != NULL) &&
		    !nft_rule_expr_is_set(nle, NFT_EXPR_IMM_CHAIN)) {
			nft_rule_expr_set_str(nle, NFT_EXPR_IMM_CHAIN,
					      nld.chain);
		}
		nft_rule_expr_set_u32(nle, NFT_EXPR_IMM_VERDICT, nld.verdict);
		break;
	default:
		break;
	}
	nft_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_expr(struct netlink_linearize_ctx *ctx,
			     const struct expr *expr,
			     enum nft_registers dreg)
{
	switch (expr->ops->type) {
	case EXPR_VERDICT:
	case EXPR_VALUE:
		return netlink_gen_immediate(ctx, expr, dreg);
	case EXPR_UNARY:
		return netlink_gen_unary(ctx, expr, dreg);
	case EXPR_BINOP:
		return netlink_gen_binop(ctx, expr, dreg);
	case EXPR_RELATIONAL:
		return netlink_gen_relational(ctx, expr, dreg);
	case EXPR_CONCAT:
		return netlink_gen_concat(ctx, expr, dreg);
	case EXPR_MAP:
		return netlink_gen_map(ctx, expr, dreg);
	case EXPR_PAYLOAD:
		return netlink_gen_payload(ctx, expr, dreg);
	case EXPR_EXTHDR:
		return netlink_gen_exthdr(ctx, expr, dreg);
	case EXPR_META:
		return netlink_gen_meta(ctx, expr, dreg);
	case EXPR_CT:
		return netlink_gen_ct(ctx, expr, dreg);
	default:
		BUG("unknown expression type %s\n", expr->ops->name);
	}
}

static void netlink_gen_verdict_stmt(struct netlink_linearize_ctx *ctx,
				     const struct stmt *stmt)
{
	return netlink_gen_expr(ctx, stmt->expr, NFT_REG_VERDICT);
}

static void netlink_gen_counter_stmt(struct netlink_linearize_ctx *ctx,
				     const struct stmt *stmt)
{
	struct nft_rule_expr *nle;

	nle = alloc_nft_expr("counter");
	if (stmt->counter.packets) {
		nft_rule_expr_set_u64(nle, NFT_EXPR_CTR_PACKETS,
				      stmt->counter.packets);
	}
	if (stmt->counter.bytes) {
		nft_rule_expr_set_u64(nle, NFT_EXPR_CTR_BYTES,
				      stmt->counter.packets);
	}
	nft_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_meta_stmt(struct netlink_linearize_ctx *ctx,
				  const struct stmt *stmt)
{
	struct nft_rule_expr *nle;
	enum nft_registers sreg;

	sreg = get_register(ctx);
	netlink_gen_expr(ctx, stmt->meta.expr, sreg);
	release_register(ctx);

	nle = alloc_nft_expr("meta");
	nft_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_log_stmt(struct netlink_linearize_ctx *ctx,
				 const struct stmt *stmt)
{
	struct nft_rule_expr *nle;

	nle = alloc_nft_expr("log");
	if (stmt->log.prefix != NULL) {
		nft_rule_expr_set_str(nle, NFT_EXPR_LOG_PREFIX,
				      stmt->log.prefix);
	}
	if (stmt->log.group) {
		nft_rule_expr_set_u16(nle, NFT_EXPR_LOG_GROUP,
				      stmt->log.group);
	}
	if (stmt->log.snaplen) {
		nft_rule_expr_set_u32(nle, NFT_EXPR_LOG_SNAPLEN,
				      stmt->log.snaplen);
	}
	if (stmt->log.qthreshold) {
		nft_rule_expr_set_u16(nle, NFT_EXPR_LOG_QTHRESHOLD,
				      stmt->log.qthreshold);
	}
	nft_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_limit_stmt(struct netlink_linearize_ctx *ctx,
				   const struct stmt *stmt)
{
	struct nft_rule_expr *nle;

	nle = alloc_nft_expr("limit");
	nft_rule_expr_set_u64(nle, NFT_EXPR_LIMIT_RATE, stmt->limit.rate);
	nft_rule_expr_set_u64(nle, NFT_EXPR_LIMIT_UNIT, stmt->limit.unit);
	nft_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_reject_stmt(struct netlink_linearize_ctx *ctx,
				    const struct stmt *stmt)
{
	struct nft_rule_expr *nle;

	nle = alloc_nft_expr("reject");
	nft_rule_expr_set_u32(nle, NFT_EXPR_REJECT_TYPE, stmt->reject.type);
	nft_rule_expr_set_u8(nle, NFT_EXPR_REJECT_CODE, 0);
	nft_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_nat_stmt(struct netlink_linearize_ctx *ctx,
				 const struct stmt *stmt)
{
	struct nft_rule_expr *nle;
	enum nft_registers amin_reg, amax_reg;
	enum nft_registers pmin_reg, pmax_reg;
	int registers = 0;
	int family;

	nle = alloc_nft_expr("nat");
	nft_rule_expr_set_u32(nle, NFT_EXPR_NAT_TYPE, stmt->nat.type);

	family = nft_rule_attr_get_u32(ctx->nlr, NFT_RULE_ATTR_FAMILY);
	nft_rule_expr_set_u32(nle, NFT_EXPR_NAT_FAMILY, family);

	if (stmt->nat.addr) {
		amin_reg = get_register(ctx);
		registers++;

		if (stmt->nat.addr->ops->type == EXPR_RANGE) {
			amax_reg = get_register(ctx);
			registers++;

			netlink_gen_expr(ctx, stmt->nat.addr->left, amin_reg);
			netlink_gen_expr(ctx, stmt->nat.addr->right, amax_reg);
			nft_rule_expr_set_u32(nle, NFT_EXPR_NAT_REG_ADDR_MIN,
					      amin_reg);
			nft_rule_expr_set_u32(nle, NFT_EXPR_NAT_REG_ADDR_MAX,
					      amax_reg);
		} else {
			netlink_gen_expr(ctx, stmt->nat.addr, amin_reg);
			nft_rule_expr_set_u32(nle, NFT_EXPR_NAT_REG_ADDR_MIN,
					      amin_reg);
		}

	}

	if (stmt->nat.proto) {
		pmin_reg = get_register(ctx);
		registers++;

		if (stmt->nat.proto->ops->type == EXPR_RANGE) {
			pmax_reg = get_register(ctx);
			registers++;

			netlink_gen_expr(ctx, stmt->nat.proto->left, pmin_reg);
			netlink_gen_expr(ctx, stmt->nat.proto->right, pmax_reg);
			nft_rule_expr_set_u32(nle, NFT_EXPR_NAT_REG_PROTO_MIN,
					      pmin_reg);
			nft_rule_expr_set_u32(nle, NFT_EXPR_NAT_REG_PROTO_MAX,
					      pmax_reg);
		} else {
			netlink_gen_expr(ctx, stmt->nat.proto, pmin_reg);
			nft_rule_expr_set_u32(nle, NFT_EXPR_NAT_REG_PROTO_MIN,
					      pmin_reg);
		}
	}

	while (registers > 0) {
		release_register(ctx);
		registers--;
	}

	nft_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_stmt(struct netlink_linearize_ctx *ctx,
			     const struct stmt *stmt)
{
	switch (stmt->ops->type) {
	case STMT_EXPRESSION:
		return netlink_gen_expr(ctx, stmt->expr, NFT_REG_VERDICT);
	case STMT_VERDICT:
		return netlink_gen_verdict_stmt(ctx, stmt);
	case STMT_COUNTER:
		return netlink_gen_counter_stmt(ctx, stmt);
	case STMT_META:
		return netlink_gen_meta_stmt(ctx, stmt);
	case STMT_LOG:
		return netlink_gen_log_stmt(ctx, stmt);
	case STMT_LIMIT:
		return netlink_gen_limit_stmt(ctx, stmt);
	case STMT_REJECT:
		return netlink_gen_reject_stmt(ctx, stmt);
	case STMT_NAT:
		return netlink_gen_nat_stmt(ctx, stmt);
	default:
		BUG("unknown statement type %s\n", stmt->ops->name);
	}
}

int netlink_linearize_rule(struct netlink_ctx *ctx, struct nft_rule *nlr,
			   const struct rule *rule)
{
	struct netlink_linearize_ctx lctx;
	const struct stmt *stmt;

	memset(&lctx, 0, sizeof(lctx));
	lctx.reg_low = NFT_REG_1;
	lctx.nlr = nlr;

	list_for_each_entry(stmt, &rule->stmts, list)
		netlink_gen_stmt(&lctx, stmt);

	netlink_dump_rule(nlr);
	return 0;
}
