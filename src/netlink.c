/*
 * Copyright (c) 2008 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Development of this code funded by Astaro AG (http://www.astaro.com/)
 */

#include <netlink/netfilter/nfnl.h>
#include <netlink/netfilter/netfilter.h>
#include <netlink/netfilter/nft_table.h>
#include <netlink/netfilter/nft_chain.h>
#include <netlink/netfilter/nft_rule.h>
#include <netlink/netfilter/nft_expr.h>
#include <netlink/netfilter/nft_data.h>
#include <linux/netfilter/nf_tables.h>

#include <nftables.h>
#include <netlink.h>
#include <expression.h>
#include <gmputil.h>
#include <utils.h>
#include <erec.h>

#define TRACE	0

static struct nl_sock *nf_sock;

static void __init netlink_open_sock(void)
{
	// FIXME: should be done dynamically by nft_set and based on set members
	nlmsg_set_default_size(65536);
	nf_sock = nl_socket_alloc();
	nfnl_connect(nf_sock);
}

static void __exit netlink_close_sock(void)
{
	nl_socket_free(nf_sock);
}

static void netlink_set_callback(nl_recvmsg_msg_cb_t func, void *arg)
{
	nl_socket_modify_cb(nf_sock, NL_CB_VALID, NL_CB_CUSTOM, func, arg);
}

void netlink_dump_object(struct nl_object *obj)
{
	struct nl_dump_params params = {
		.dp_fd		= stdout,
		.dp_type	= NL_DUMP_DETAILS,
	};
	nl_object_dump(obj, &params);
}

static int netlink_io_error(struct netlink_ctx *ctx, const struct location *loc,
			    const char *fmt, ...)
{
	struct error_record *erec;
	va_list ap;

	if (loc == NULL)
		loc = &internal_location;

	va_start(ap, fmt);
	erec = erec_vcreate(EREC_ERROR, loc, fmt, ap);
	va_end(ap);
	erec_queue(erec, ctx->msgs);
	return -1;
}

struct nfnl_nft_table *alloc_nft_table(const struct handle *h)
{
	struct nfnl_nft_table *nlt;

	nlt = nfnl_nft_table_alloc();
	if (nlt == NULL)
		memory_allocation_error();
	nfnl_nft_table_set_family(nlt, h->family);
	nfnl_nft_table_set_name(nlt, h->table, strlen(h->table) + 1);
	return nlt;
}

struct nfnl_nft_chain *alloc_nft_chain(const struct handle *h)
{
	struct nfnl_nft_chain *nlc;

	nlc = nfnl_nft_chain_alloc();
	if (nlc == NULL)
		memory_allocation_error();
	nfnl_nft_chain_set_family(nlc, h->family);
	nfnl_nft_chain_set_table(nlc, h->table, strlen(h->table) + 1);
	if (h->chain != NULL)
		nfnl_nft_chain_set_name(nlc, h->chain, strlen(h->chain) + 1);
	return nlc;
}

struct nfnl_nft_rule *alloc_nft_rule(const struct handle *h)
{
	struct nfnl_nft_rule *nlr;

	nlr = nfnl_nft_rule_alloc();
	if (nlr == NULL)
		memory_allocation_error();
	nfnl_nft_rule_set_family(nlr, h->family);
	nfnl_nft_rule_set_table(nlr, h->table, strlen(h->table) + 1);
	if (h->chain != NULL)
		nfnl_nft_rule_set_chain(nlr, h->chain, strlen(h->chain) + 1);
	if (h->handle)
		nfnl_nft_rule_set_handle(nlr, h->handle);
	return nlr;
}

struct nfnl_nft_expr *alloc_nft_expr(int (*init)(struct nfnl_nft_expr *))
{
	struct nfnl_nft_expr *nle;

	nle = nfnl_nft_expr_alloc();
	if (nle == NULL || init(nle) != 0)
		memory_allocation_error();
	return nle;
}

struct nfnl_nft_data *alloc_nft_data(const void *data, unsigned int len)
{
	struct nfnl_nft_data *nld;

	assert(len > 0);
	nld = nfnl_nft_data_alloc(data, len);
	if (nld == NULL)
		memory_allocation_error();
	return nld;
}

struct nfnl_nft_data *netlink_gen_raw_data(const mpz_t value,
					   enum byteorder byteorder,
					   unsigned int len)
{
	unsigned char data[len];

	mpz_export_data(data, value, byteorder, len);
	return alloc_nft_data(data, len);
}

static struct nfnl_nft_data *netlink_gen_concat_data(const struct expr *expr)
{
	const struct expr *i;
	unsigned int len, offset;

	len = 0;
	list_for_each_entry(i, &expr->expressions, list)
		len += i->len;

	if (1) {
		unsigned char data[len / BITS_PER_BYTE];

		offset = 0;
		list_for_each_entry(i, &expr->expressions, list) {
			assert(i->ops->type == EXPR_VALUE);
			mpz_export_data(data + offset, i->value, i->byteorder,
					i->len / BITS_PER_BYTE);
			offset += i->len / BITS_PER_BYTE;
		}
	
		return alloc_nft_data(data, len / BITS_PER_BYTE);
	}
}

static struct nfnl_nft_data *netlink_gen_constant_data(const struct expr *expr)
{
	assert(expr->ops->type == EXPR_VALUE);
	return netlink_gen_raw_data(expr->value, expr->byteorder,
				    div_round_up(expr->len, BITS_PER_BYTE));
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
		break;
	}

	return verdict;
}

struct nfnl_nft_data *netlink_gen_data(const struct expr *expr)
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

struct expr *netlink_alloc_value(const struct location *loc,
				 const struct nfnl_nft_data *nld)
{
	return constant_expr_alloc(loc, &invalid_type, BYTEORDER_INVALID,
				   nfnl_nft_data_get_size(nld) * BITS_PER_BYTE,
				   nfnl_nft_data_get(nld));
}

static struct expr *netlink_alloc_verdict(const struct location *loc,
					  const struct nfnl_nft_data *nld)
{
	unsigned int code;
	char *chain;

	code = nfnl_nft_verdict_get_verdict(nld);
	switch (code) {
	case NFT_JUMP:
	case NFT_GOTO:
		chain = xstrdup(nfnl_nft_verdict_get_chain(nld));
		break;
	default:
		chain = NULL;
		break;
	}

	return verdict_expr_alloc(loc, code, chain);
}

struct expr *netlink_alloc_data(const struct location *loc,
				const struct nfnl_nft_data *nld,
				enum nft_registers dreg)
{
	switch (dreg) {
	case NFT_REG_VERDICT:
		return netlink_alloc_verdict(loc, nld);
	default:
		return netlink_alloc_value(loc, nld);
	}
}

int netlink_add_rule(struct netlink_ctx *ctx, const struct handle *h,
		     const struct rule *rule)
{
	struct nfnl_nft_rule *nlr;
	int err;

	nlr = alloc_nft_rule(&rule->handle);
	err = netlink_linearize_rule(ctx, nlr, rule);
	if (err == 0) {
		err = nfnl_nft_rule_add(nf_sock, nlr, NLM_F_EXCL | NLM_F_APPEND);
		if (err < 0)
			netlink_io_error(ctx, &rule->location,
					 "Could not add rule: %s", nl_geterror(err));
	}
	nfnl_nft_rule_put(nlr);
	return err;
}

int netlink_delete_rule(struct netlink_ctx *ctx, const struct handle *h)
{
	struct nfnl_nft_rule *nlr;
	int err;

	nlr = alloc_nft_rule(h);
	err = nfnl_nft_rule_delete(nf_sock, nlr, 0);
	nfnl_nft_rule_put(nlr);

	if (err < 0)
		netlink_io_error(ctx, NULL, "Could not delete rule: %s",
				 nl_geterror(err));
	return err;
}

static void list_rule_cb(struct nl_object *obj, void *arg)
{
	const struct nfnl_nft_rule *nlr = (struct nfnl_nft_rule *)obj;
	struct netlink_ctx *ctx = arg;
	struct rule *rule;
#if TRACE
	printf("\n"); netlink_dump_object(obj); printf("\n");
#endif
	if (!nfnl_nft_rule_test_family(nlr) ||
	    !nfnl_nft_rule_test_table(nlr) ||
	    !nfnl_nft_rule_test_chain(nlr) ||
	    !nfnl_nft_rule_test_handle(nlr)) {
		netlink_io_error(ctx, NULL, "Incomplete rule received");
		return;
	}

	rule = netlink_delinearize_rule(ctx, obj);
	list_add_tail(&rule->list, &ctx->list);
}

static int netlink_list_rules(struct netlink_ctx *ctx, const struct handle *h)
{
	struct nl_cache *rule_cache;
	struct nfnl_nft_rule *nlr;
	int err;

	err = nfnl_nft_rule_alloc_cache(nf_sock, &rule_cache);
	if (err < 0)
		return netlink_io_error(ctx, NULL,
					"Could not receive rules from kernel: %s",
					nl_geterror(err));

	nlr = alloc_nft_rule(h);
	nl_cache_foreach_filter(rule_cache, OBJ_CAST(nlr), list_rule_cb, ctx);
	nfnl_nft_rule_put(nlr);
	nl_cache_free(rule_cache);
	return 0;
}

static int netlink_get_rule_cb(struct nl_msg *msg, void *arg)
{
	return nl_msg_parse(msg, list_rule_cb, arg);
}

int netlink_get_rule(struct netlink_ctx *ctx, const struct handle *h)
{
	struct nfnl_nft_rule *nlr;
	int err;

	nlr = alloc_nft_rule(h);
	nfnl_nft_rule_query(nf_sock, nlr, 0);
	netlink_set_callback(netlink_get_rule_cb, ctx);
	err = nl_recvmsgs_default(nf_sock);
	nfnl_nft_rule_put(nlr);

	if (err < 0)
		return netlink_io_error(ctx, NULL,
					"Could not receive rule from kernel: %s",
					nl_geterror(err));
	return err;
}

static void flush_rule_cb(struct nl_object *obj, void *arg)
{
	struct netlink_ctx *ctx = arg;
	int err;

	netlink_dump_object(obj);
	err = nfnl_nft_rule_delete(nf_sock, (struct nfnl_nft_rule *)obj, 0);
	if (err < 0)
		netlink_io_error(ctx, NULL, "Could not delete rule: %s",
				 nl_geterror(err));
}

static int netlink_flush_rules(struct netlink_ctx *ctx, const struct handle *h)
{
	struct nl_cache *rule_cache;
	struct nfnl_nft_rule *nlr;
	int err;

	err = nfnl_nft_rule_alloc_cache(nf_sock, &rule_cache);
	if (err < 0)
		return netlink_io_error(ctx, NULL,
					"Could not receive rules from kernel: %s",
					nl_geterror(err));

	nlr = alloc_nft_rule(h);
	nl_cache_foreach_filter(rule_cache, OBJ_CAST(nlr), flush_rule_cb, ctx);
	nfnl_nft_rule_put(nlr);
	nl_cache_free(rule_cache);
	return 0;
}

int netlink_add_chain(struct netlink_ctx *ctx, const struct handle *h,
		      const struct chain *chain)
{
	struct nfnl_nft_chain *nlc;
	int err;

	nlc = alloc_nft_chain(h);
	if (chain != NULL && (chain->hooknum || chain->priority)) {
		nfnl_nft_chain_set_hooknum(nlc, chain->hooknum);
		nfnl_nft_chain_set_priority(nlc, chain->priority);
	}
	err = nfnl_nft_chain_add(nf_sock, nlc, NLM_F_EXCL);
	nfnl_nft_chain_put(nlc);

	if (err < 0)
		netlink_io_error(ctx, NULL, "Could not add chain: %s",
				 nl_geterror(err));
	return err;
}

int netlink_delete_chain(struct netlink_ctx *ctx, const struct handle *h)
{
	struct nfnl_nft_chain *nlc;
	int err;

	nlc = alloc_nft_chain(h);
	err = nfnl_nft_chain_delete(nf_sock, nlc, 0);
	nfnl_nft_chain_put(nlc);

	if (err < 0)
		netlink_io_error(ctx, NULL, "Could not delete chain: %s",
				 nl_geterror(err));
	return err;
}

static void list_chain_cb(struct nl_object *obj, void *arg)
{
	struct nfnl_nft_chain *nlc = (struct nfnl_nft_chain *)obj;
	struct netlink_ctx *ctx = arg;
	struct chain *chain;
#if TRACE
	netlink_dump_object(obj);;
#endif
	if (!nfnl_nft_chain_test_family(nlc) ||
	    !nfnl_nft_chain_test_table(nlc) ||
	    !nfnl_nft_chain_test_name(nlc)) {
		netlink_io_error(ctx, NULL, "Incomplete chain received");
		return;
	}

	chain = chain_alloc(nfnl_nft_chain_get_name(nlc));
	chain->handle.family = nfnl_nft_chain_get_family(nlc);
	chain->handle.table  = xstrdup(nfnl_nft_chain_get_table(nlc));
	chain->hooknum       = nfnl_nft_chain_get_hooknum(nlc);
	chain->priority      = nfnl_nft_chain_get_priority(nlc);
	list_add_tail(&chain->list, &ctx->list);
}

int netlink_list_chains(struct netlink_ctx *ctx, const struct handle *h)
{
	struct nl_cache *chain_cache;
	struct nfnl_nft_chain *nlc;
	int err;

	err = nfnl_nft_chain_alloc_cache(nf_sock, &chain_cache);
	if (err < 0)
		return netlink_io_error(ctx, NULL,
					"Could not receive chains from kernel: %s",
					nl_geterror(err));

	nlc = alloc_nft_chain(h);
	nl_cache_foreach_filter(chain_cache, OBJ_CAST(nlc), list_chain_cb, ctx);
	nfnl_nft_chain_put(nlc);
	nl_cache_free(chain_cache);
	return 0;
}

static int netlink_get_chain_cb(struct nl_msg *msg, void *arg)
{
	return nl_msg_parse(msg, list_chain_cb, arg);
}

int netlink_get_chain(struct netlink_ctx *ctx, const struct handle *h)
{
	struct nfnl_nft_chain *nlc;
	int err;

	nlc = alloc_nft_chain(h);
	nfnl_nft_chain_query(nf_sock, nlc, 0);
	netlink_set_callback(netlink_get_chain_cb, ctx);
	err = nl_recvmsgs_default(nf_sock);
	nfnl_nft_chain_put(nlc);

	if (err < 0)
		return netlink_io_error(ctx, NULL,
					"Could not receive chain from kernel: %s",
					nl_geterror(err));
	return err;
}

int netlink_list_chain(struct netlink_ctx *ctx, const struct handle *h)
{
	return netlink_list_rules(ctx, h);
}

int netlink_flush_chain(struct netlink_ctx *ctx, const struct handle *h)
{
	return netlink_flush_rules(ctx, h);
}

int netlink_add_table(struct netlink_ctx *ctx, const struct handle *h,
		      const struct table *table)
{
	struct nfnl_nft_table *nlt;
	int err;

	nlt = alloc_nft_table(h);
	err = nfnl_nft_table_add(nf_sock, nlt, NLM_F_EXCL);
	nfnl_nft_table_put(nlt);

	if (err < 0)
		netlink_io_error(ctx, NULL, "Could not add table: %s",
				 nl_geterror(err));
	return err;
}

int netlink_delete_table(struct netlink_ctx *ctx, const struct handle *h)
{
	struct nfnl_nft_table *nlt;
	int err;

	nlt = alloc_nft_table(h);
	err = nfnl_nft_table_delete(nf_sock, nlt, 0);
	nfnl_nft_table_put(nlt);

	if (err < 0)
		netlink_io_error(ctx, NULL, "Could not delete table: %s",
				 nl_geterror(err));
	return err;
}

static void list_table_cb(struct nl_object *obj, void *arg)
{
	struct nfnl_nft_table *nlt = (struct nfnl_nft_table *)obj;
	struct netlink_ctx *ctx = arg;
	struct table *table;
#if TRACE
	netlink_dump_object(obj);
#endif
	if (!nfnl_nft_table_test_family(nlt) ||
	    !nfnl_nft_table_test_name(nlt)) {
		netlink_io_error(ctx, NULL, "Incomplete table received");
		return;
	}

	table = table_alloc();
	table->handle.family = nfnl_nft_table_get_family(nlt);
	table->handle.table  = xstrdup(nfnl_nft_table_get_name(nlt));
	list_add_tail(&table->list, &ctx->list);
}

int netlink_list_tables(struct netlink_ctx *ctx, const struct handle *h)
{
	struct nl_cache *table_cache;
	struct nfnl_nft_table *nlt;
	int err;

	err = nfnl_nft_table_alloc_cache(nf_sock, &table_cache);
	if (err < 0)
		return netlink_io_error(ctx, NULL,
					"Could not receive tables from kernel: %s",
					nl_geterror(err));

	nlt = alloc_nft_table(h);
	nl_cache_foreach_filter(table_cache, OBJ_CAST(nlt), list_table_cb, ctx);
	nfnl_nft_table_put(nlt);
	nl_cache_free(table_cache);
	return 0;
}

static int netlink_get_table_cb(struct nl_msg *msg, void *arg)
{
	return nl_msg_parse(msg, list_table_cb, arg);
}

int netlink_get_table(struct netlink_ctx *ctx, const struct handle *h)
{
	struct nfnl_nft_table *nlt;
	int err;

	nlt = alloc_nft_table(h);
	nfnl_nft_table_query(nf_sock, nlt, 0);
	netlink_set_callback(netlink_get_table_cb, ctx);
	err = nl_recvmsgs_default(nf_sock);
	nfnl_nft_table_put(nlt);

	if (err < 0)
		return netlink_io_error(ctx, NULL,
					"Could not receive table from kernel: %s",
					nl_geterror(err));
	return err;
}


int netlink_list_table(struct netlink_ctx *ctx, const struct handle *h)
{
	return netlink_list_rules(ctx, h);
}

int netlink_flush_table(struct netlink_ctx *ctx, const struct handle *h)
{
	return netlink_flush_rules(ctx, h);
}
