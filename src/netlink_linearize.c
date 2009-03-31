/*
 * Copyright (c) 2008 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Development of this code funded by Astaro AG (http://www.astaro.com/)
 */

#include <linux/netfilter/nf_tables.h>

#include <rule.h>
#include <statement.h>
#include <expression.h>
#include <netlink.h>
#include <gmputil.h>
#include <utils.h>

struct netlink_linearize_ctx {
	struct nfnl_nft_rule	*nlr;
	unsigned int		reg_low;
};

static enum nft_registers get_register(struct netlink_linearize_ctx *ctx)
{
	if (ctx->reg_low > NFT_REG_MAX)
		BUG();
	return ctx->reg_low++;
}

static void release_register(struct netlink_linearize_ctx *ctx)
{
	ctx->reg_low--;
}

static struct nfnl_nft_data *netlink_gen_mpz_data(const mpz_t value,
						  enum byteorder byteorder,
						  unsigned int len)
{
	unsigned char data[len];

	mpz_export_data(data, value, byteorder, len);
	return alloc_nft_data(data, len);
}

static struct nfnl_nft_data *netlink_gen_constant_data(const struct expr *expr)
{
	assert(expr->ops->type == EXPR_VALUE);
	return netlink_gen_mpz_data(expr->value, expr->byteorder,
				    div_round_up(expr->len, BITS_PER_BYTE));
}

static struct nfnl_nft_data *netlink_gen_concat_data(const struct expr *expr)
{
	struct nfnl_nft_data *data;
	const struct expr *i;
	void *buf;
	unsigned int len, offset;

	len = 0;
	list_for_each_entry(i, &expr->expressions, list)
		len += i->len;

	buf = xmalloc(len / BITS_PER_BYTE);

	offset = 0;
	list_for_each_entry(i, &expr->expressions, list) {
		assert(i->ops->type == EXPR_VALUE);
		mpz_export_data(buf + offset, i->value, i->byteorder,
				i->len / BITS_PER_BYTE);
		offset += i->len / BITS_PER_BYTE;
	}

	data = alloc_nft_data(buf, len / BITS_PER_BYTE);
	xfree(buf);
	return data;
}

static struct nfnl_nft_data *netlink_gen_verdict(const struct expr *expr)
{
	struct nfnl_nft_data *verdict;

	verdict = nfnl_nft_verdict_alloc();
	nfnl_nft_verdict_set_verdict(verdict, expr->verdict);

	switch (expr->verdict) {
	case NFT_JUMP:
	case NFT_GOTO:
		nfnl_nft_verdict_set_chain(verdict, expr->chain);
	}

	return verdict;
}

static struct nfnl_nft_data *netlink_gen_data(const struct expr *expr)
{
	switch (expr->ops->type) {
	case EXPR_VALUE:
		return netlink_gen_constant_data(expr);
	case EXPR_CONCAT:
		return netlink_gen_concat_data(expr);
	case EXPR_VERDICT:
		return netlink_gen_verdict(expr);
	default:
		BUG();
	}
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
	struct nfnl_nft_expr *nle;

	nle = alloc_nft_expr(nfnl_nft_payload_init);
	nfnl_nft_payload_set_dreg(nle, dreg);
	nfnl_nft_payload_set_base(nle, expr->payload.base - 1);
	nfnl_nft_payload_set_offset(nle, expr->payload.offset / BITS_PER_BYTE);
	nfnl_nft_payload_set_len(nle, expr->len / BITS_PER_BYTE);
	nfnl_nft_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_exthdr(struct netlink_linearize_ctx *ctx,
			       const struct expr *expr,
			       enum nft_registers dreg)
{
	struct nfnl_nft_expr *nle;

	nle = alloc_nft_expr(nfnl_nft_exthdr_init);
	nfnl_nft_exthdr_set_dreg(nle, dreg);
	nfnl_nft_exthdr_set_type(nle, expr->exthdr.desc->type);
	nfnl_nft_exthdr_set_offset(nle, expr->exthdr.tmpl->offset / BITS_PER_BYTE);
	nfnl_nft_exthdr_set_len(nle, expr->len / BITS_PER_BYTE);
	nfnl_nft_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_meta(struct netlink_linearize_ctx *ctx,
			     const struct expr *expr,
			     enum nft_registers dreg)
{
	struct nfnl_nft_expr *nle;

	nle = alloc_nft_expr(nfnl_nft_meta_init);
	nfnl_nft_meta_set_dreg(nle, dreg);
	nfnl_nft_meta_set_key(nle, expr->meta.key);
	nfnl_nft_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_ct(struct netlink_linearize_ctx *ctx,
			   const struct expr *expr,
			   enum nft_registers dreg)
{
	struct nfnl_nft_expr *nle;

	nle = alloc_nft_expr(nfnl_nft_ct_init);
	nfnl_nft_ct_set_dreg(nle, dreg);
	nfnl_nft_ct_set_key(nle, expr->ct.key);
	nfnl_nft_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_map(struct netlink_linearize_ctx *ctx,
			    const struct expr *expr,
			    enum nft_registers dreg)
{
	struct nfnl_nft_expr *nle;
	struct nfnl_nft_data *data;
	struct nfnl_nft_data *mapping;
	const struct expr *i;
	enum nft_set_elem_flags flags;
	enum nft_registers sreg;
	unsigned int klen, dlen;

	assert(expr->mappings->ops->type == EXPR_SET);

	klen = expr->expr->len / BITS_PER_BYTE;
	dlen = expr->mappings->len / BITS_PER_BYTE;
	if (dreg == NFT_REG_VERDICT)
		sreg = get_register(ctx);
	else
		sreg = dreg;

	netlink_gen_expr(ctx, expr->expr, sreg);

	nle = alloc_nft_expr(nfnl_nft_set_init);
	nfnl_nft_set_set_flags(nle, NFT_SET_MAP);
	nfnl_nft_set_set_sreg(nle, sreg);
	nfnl_nft_set_set_klen(nle, klen);
	nfnl_nft_set_set_dreg(nle, dreg);
	nfnl_nft_set_set_dlen(nle, dlen);

	if (expr->mappings->flags & SET_F_INTERVAL) {
		set_to_intervals(expr->mappings);
		nfnl_nft_set_set_flags(nle, NFT_SET_INTERVAL);
	}

	list_for_each_entry(i, &expr->mappings->expressions, list) {
		flags = 0;

		switch (i->ops->type) {
		case EXPR_MAPPING:
			data	= netlink_gen_data(i->left);
			mapping	= netlink_gen_data(i->right);
			break;
		case EXPR_VALUE:
			assert(i->flags & EXPR_F_INTERVAL_END);
			data    = netlink_gen_data(i);
			mapping = NULL;
			flags   = NFT_SE_INTERVAL_END;
			break;
		default:
			BUG();
		}

		nfnl_nft_set_add_mapping(nle, data, mapping, flags);
	}

	if (dreg == NFT_REG_VERDICT)
		release_register(ctx);

	nfnl_nft_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_lookup(struct netlink_linearize_ctx *ctx,
			       const struct expr *expr,
			       enum nft_registers dreg)
{
	struct nfnl_nft_expr *nle;
	const struct expr *i;
	enum nft_set_elem_flags flags;
	enum nft_registers sreg;

	assert(expr->right->ops->type == EXPR_SET);
	assert(dreg == NFT_REG_VERDICT);

	sreg = get_register(ctx);
	netlink_gen_expr(ctx, expr->left, sreg);

	nle = alloc_nft_expr(nfnl_nft_set_init);
	nfnl_nft_set_set_sreg(nle, sreg);
	nfnl_nft_set_set_klen(nle, expr->left->len / BITS_PER_BYTE);

	if (expr->right->flags & SET_F_INTERVAL) {
		set_to_intervals(expr->right);
		nfnl_nft_set_set_flags(nle, NFT_SET_INTERVAL);
	}

	list_for_each_entry(i, &expr->right->expressions, list) {
		assert(i->ops->type == EXPR_VALUE);

		flags = 0;
		if (i->flags & EXPR_F_INTERVAL_END)
			flags = NFT_SE_INTERVAL_END;

		nfnl_nft_set_add_elem(nle, netlink_gen_data(i), flags);
	}

	release_register(ctx);
	nfnl_nft_rule_add_expr(ctx->nlr, nle);
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
		BUG();
	}
}

static void netlink_gen_cmp(struct netlink_linearize_ctx *ctx,
			    const struct expr *expr,
			    enum nft_registers dreg)
{
	struct nfnl_nft_expr *nle;
	enum nft_registers sreg;

	assert(dreg == NFT_REG_VERDICT);

	sreg = get_register(ctx);
	netlink_gen_expr(ctx, expr->left, sreg);

	nle = alloc_nft_expr(nfnl_nft_cmp_init);
	nfnl_nft_cmp_set_sreg(nle, sreg);
	nfnl_nft_cmp_set_op(nle, netlink_gen_cmp_op(expr->op));
	nfnl_nft_cmp_set_data(nle, netlink_gen_data(expr->right));
	release_register(ctx);

	nfnl_nft_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_range(struct netlink_linearize_ctx *ctx,
			      const struct expr *expr,
			      enum nft_registers dreg)
{
	struct expr *range = expr->right;
	struct nfnl_nft_expr *nle;
	enum nft_registers sreg;

	assert(dreg == NFT_REG_VERDICT);

	sreg = get_register(ctx);
	netlink_gen_expr(ctx, expr->left, sreg);

	nle = alloc_nft_expr(nfnl_nft_cmp_init);
	nfnl_nft_cmp_set_sreg(nle, sreg);
	nfnl_nft_cmp_set_op(nle, netlink_gen_cmp_op(OP_GTE));
	nfnl_nft_cmp_set_data(nle, netlink_gen_data(range->left));
	nfnl_nft_rule_add_expr(ctx->nlr, nle);

	nle = alloc_nft_expr(nfnl_nft_cmp_init);
	nfnl_nft_cmp_set_sreg(nle, sreg);
	nfnl_nft_cmp_set_op(nle, netlink_gen_cmp_op(OP_LTE));
	nfnl_nft_cmp_set_data(nle, netlink_gen_data(range->right));
	nfnl_nft_rule_add_expr(ctx->nlr, nle);

	release_register(ctx);
}

static void netlink_gen_flagcmp(struct netlink_linearize_ctx *ctx,
				const struct expr *expr,
				enum nft_registers dreg)
{
	struct nfnl_nft_expr *nle;
	struct nfnl_nft_data *nld;
	enum nft_registers sreg;
	unsigned int len;
	mpz_t zero;

	assert(dreg == NFT_REG_VERDICT);

	sreg = get_register(ctx);
	netlink_gen_expr(ctx, expr->left, sreg);
	len = div_round_up(expr->left->len, BITS_PER_BYTE);

	mpz_init_set_ui(zero, 0);

	nle = alloc_nft_expr(nfnl_nft_bitwise_init);
	nld = netlink_gen_mpz_data(zero, expr->right->byteorder, len);
	nfnl_nft_bitwise_set_sreg(nle, sreg);
	nfnl_nft_bitwise_set_dreg(nle, sreg);
	nfnl_nft_bitwise_set_len(nle, len);
	nfnl_nft_bitwise_set_mask(nle, netlink_gen_data(expr->right));
	nfnl_nft_bitwise_set_xor(nle, nld);
	nfnl_nft_rule_add_expr(ctx->nlr, nle);

	nle = alloc_nft_expr(nfnl_nft_cmp_init);
	nld = netlink_gen_mpz_data(zero, expr->right->byteorder, len);
	nfnl_nft_cmp_set_sreg(nle, sreg);
	nfnl_nft_cmp_set_op(nle, NFT_CMP_NEQ);
	nfnl_nft_cmp_set_data(nle, nld);
	nfnl_nft_rule_add_expr(ctx->nlr, nle);

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
		BUG();
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
	struct nfnl_nft_expr *nle;
	struct nfnl_nft_data *nld;
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
			BUG();
		}
	}

	len = div_round_up(expr->len, BITS_PER_BYTE);

	nle = alloc_nft_expr(nfnl_nft_bitwise_init);
	nfnl_nft_bitwise_set_sreg(nle, dreg);
	nfnl_nft_bitwise_set_dreg(nle, dreg);
	nfnl_nft_bitwise_set_len(nle, len);

	nld = netlink_gen_mpz_data(mask, expr->byteorder, len);
	nfnl_nft_bitwise_set_mask(nle, nld);

	nld = netlink_gen_mpz_data(xor, expr->byteorder, len);
	nfnl_nft_bitwise_set_xor(nle, nld);

	mpz_clear(tmp);
	mpz_clear(val);
	mpz_clear(xor);
	mpz_clear(mask);

	nfnl_nft_rule_add_expr(ctx->nlr, nle);
}

static enum nft_byteorder_ops netlink_gen_unary_op(enum ops op)
{
	switch (op) {
	case OP_HTON:
		return NFT_BYTEORDER_HTON;
	case OP_NTOH:
		return NFT_BYTEORDER_HTON;
	default:
		BUG();
	}
}

static void netlink_gen_unary(struct netlink_linearize_ctx *ctx,
			      const struct expr *expr,
			      enum nft_registers dreg)
{
	struct nfnl_nft_expr *nle;

	netlink_gen_expr(ctx, expr->arg, dreg);

	nle = alloc_nft_expr(nfnl_nft_byteorder_init);
	nfnl_nft_byteorder_set_sreg(nle, dreg);
	nfnl_nft_byteorder_set_dreg(nle, dreg);
	nfnl_nft_byteorder_set_len(nle, expr->len / BITS_PER_BYTE);
	nfnl_nft_byteorder_set_size(nle, expr->arg->len % 32 ? 2 : 4);
	nfnl_nft_byteorder_set_op(nle, netlink_gen_unary_op(expr->op));
	nfnl_nft_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_immediate(struct netlink_linearize_ctx *ctx,
				  const struct expr *expr,
				  enum nft_registers dreg)
{
	struct nfnl_nft_expr *nle;

	nle = alloc_nft_expr(nfnl_nft_immediate_init);
	nfnl_nft_immediate_set_dreg(nle, dreg);
	nfnl_nft_immediate_set_data(nle, netlink_gen_data(expr));
	nfnl_nft_rule_add_expr(ctx->nlr, nle);
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
		BUG();
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
	struct nfnl_nft_expr *nle;

	nle = alloc_nft_expr(nfnl_nft_counter_init);
	nfnl_nft_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_meta_stmt(struct netlink_linearize_ctx *ctx,
				  const struct stmt *stmt)
{
	struct nfnl_nft_expr *nle;
	enum nft_registers sreg;

	sreg = get_register(ctx);
	netlink_gen_expr(ctx, stmt->meta.expr, sreg);
	release_register(ctx);

	nle = alloc_nft_expr(nfnl_nft_meta_init);
	nfnl_nft_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_log_stmt(struct netlink_linearize_ctx *ctx,
				 const struct stmt *stmt)
{
	struct nfnl_nft_expr *nle;

	nle = alloc_nft_expr(nfnl_nft_log_init);
	if (stmt->log.prefix != NULL)
		nfnl_nft_log_set_prefix(nle, stmt->log.prefix);
	if (stmt->log.group)
		nfnl_nft_log_set_group(nle, stmt->log.group);
	if (stmt->log.snaplen)
		nfnl_nft_log_set_snaplen(nle, stmt->log.snaplen);
	if (stmt->log.qthreshold)
		nfnl_nft_log_set_qthreshold(nle, stmt->log.qthreshold);
	nfnl_nft_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_limit_stmt(struct netlink_linearize_ctx *ctx,
				   const struct stmt *stmt)
{
	struct nfnl_nft_expr *nle;

	nle = alloc_nft_expr(nfnl_nft_limit_init);
	nfnl_nft_limit_set_rate(nle, stmt->limit.rate);
	nfnl_nft_limit_set_depth(nle, stmt->limit.depth);
	nfnl_nft_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_reject_stmt(struct netlink_linearize_ctx *ctx,
				    const struct stmt *stmt)
{
	struct nfnl_nft_expr *nle;

	nle = alloc_nft_expr(NULL);
	nfnl_nft_rule_add_expr(ctx->nlr, nle);
}

static void netlink_gen_nat_stmt(struct netlink_linearize_ctx *ctx,
				 const struct stmt *stmt)
{
	struct nfnl_nft_expr *nle;
	enum nft_registers amin_reg, amax_reg;
	enum nft_registers pmin_reg, pmax_reg;

	nle = alloc_nft_expr(nfnl_nft_nat_init);
	nfnl_nft_nat_set_type(nle, stmt->nat.type);

	if (stmt->nat.addr) {
		switch (stmt->nat.addr->ops->type) {
		default:
			amin_reg = amax_reg = get_register(ctx);
			netlink_gen_expr(ctx, stmt->nat.addr, amin_reg);
			nfnl_nft_nat_set_sreg_addr_min(nle, amin_reg);
			release_register(ctx);
			break;
		case EXPR_RANGE:
			amin_reg = get_register(ctx);
			amax_reg = get_register(ctx);
			netlink_gen_expr(ctx, stmt->nat.addr->left, amin_reg);
			netlink_gen_expr(ctx, stmt->nat.addr->right, amax_reg);
			nfnl_nft_nat_set_sreg_addr_min(nle, amin_reg);
			nfnl_nft_nat_set_sreg_addr_max(nle, amax_reg);
			release_register(ctx);
			release_register(ctx);
			break;
		}

	}

	if (stmt->nat.proto) {
		switch (stmt->nat.proto->ops->type) {
		default:
			pmin_reg = pmax_reg = get_register(ctx);
			netlink_gen_expr(ctx, stmt->nat.proto, pmin_reg);
			nfnl_nft_nat_set_sreg_proto_min(nle, pmin_reg);
			release_register(ctx);
			break;
		case EXPR_RANGE:
			pmin_reg = get_register(ctx);
			pmax_reg = get_register(ctx);
			netlink_gen_expr(ctx, stmt->nat.proto->left, pmin_reg);
			netlink_gen_expr(ctx, stmt->nat.proto->right, pmax_reg);
			nfnl_nft_nat_set_sreg_proto_min(nle, pmin_reg);
			nfnl_nft_nat_set_sreg_proto_max(nle, pmax_reg);
			release_register(ctx);
			release_register(ctx);
			break;
		}
	}

	nfnl_nft_rule_add_expr(ctx->nlr, nle);
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
		BUG();
	}
}

int netlink_linearize_rule(struct netlink_ctx *ctx, struct nfnl_nft_rule *nlr,
			   const struct rule *rule)
{
	struct netlink_linearize_ctx lctx;
	const struct stmt *stmt;

	memset(&lctx, 0, sizeof(lctx));
	lctx.reg_low = NFT_REG_1;
	lctx.nlr = nlr;

	list_for_each_entry(stmt, &rule->stmts, list)
		netlink_gen_stmt(&lctx, stmt);

#ifdef DEBUG
	netlink_dump_object((struct nl_object *)nlr);
#endif
	return 0;
}
