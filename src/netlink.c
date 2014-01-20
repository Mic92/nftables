/*
 * Copyright (c) 2008-2012 Patrick McHardy <kaber@trash.net>
 * Copyright (c) 2013 Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Development of this code funded by Astaro AG (http://www.astaro.com/)
 */

#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <libmnl/libmnl.h>

#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/expr.h>
#include <libnftnl/set.h>
#include <linux/netfilter/nf_tables.h>

#include <nftables.h>
#include <netlink.h>
#include <mnl.h>
#include <expression.h>
#include <gmputil.h>
#include <utils.h>
#include <erec.h>

static struct mnl_socket *nf_sock;

static void __init netlink_open_sock(void)
{
	nf_sock = mnl_socket_open(NETLINK_NETFILTER);
	if (nf_sock == NULL)
		memory_allocation_error();

	fcntl(mnl_socket_get_fd(nf_sock), F_SETFL, O_NONBLOCK);
	mnl_batch_init();
}

static void __exit netlink_close_sock(void)
{
	mnl_socket_close(nf_sock);
}

int netlink_io_error(struct netlink_ctx *ctx, const struct location *loc,
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

struct nft_table *alloc_nft_table(const struct handle *h)
{
	struct nft_table *nlt;

	nlt = nft_table_alloc();
	if (nlt == NULL)
		memory_allocation_error();

	nft_table_attr_set_u32(nlt, NFT_TABLE_ATTR_FAMILY, h->family);
	if (h->table != NULL)
		nft_table_attr_set(nlt, NFT_TABLE_ATTR_NAME, h->table);
	return nlt;
}

struct nft_chain *alloc_nft_chain(const struct handle *h)
{
	struct nft_chain *nlc;

	nlc = nft_chain_alloc();
	if (nlc == NULL)
		memory_allocation_error();

	nft_chain_attr_set_u32(nlc, NFT_CHAIN_ATTR_FAMILY, h->family);
	nft_chain_attr_set_str(nlc, NFT_CHAIN_ATTR_TABLE, h->table);
	if (h->handle != 0)
		nft_chain_attr_set_u64(nlc, NFT_CHAIN_ATTR_HANDLE, h->handle);
	if (h->chain != NULL)
		nft_chain_attr_set_str(nlc, NFT_CHAIN_ATTR_NAME, h->chain);
	return nlc;
}

struct nft_rule *alloc_nft_rule(const struct handle *h)
{
	struct nft_rule *nlr;

	nlr = nft_rule_alloc();
	if (nlr == NULL)
		memory_allocation_error();

	nft_rule_attr_set_u32(nlr, NFT_RULE_ATTR_FAMILY, h->family);
	nft_rule_attr_set_str(nlr, NFT_RULE_ATTR_TABLE, h->table);
	if (h->chain != NULL)
		nft_rule_attr_set_str(nlr, NFT_RULE_ATTR_CHAIN, h->chain);
	if (h->handle)
		nft_rule_attr_set_u64(nlr, NFT_RULE_ATTR_HANDLE, h->handle);
	if (h->position)
		nft_rule_attr_set_u64(nlr, NFT_RULE_ATTR_POSITION, h->position);
	return nlr;
}

struct nft_rule_expr *alloc_nft_expr(const char *name)
{
	struct nft_rule_expr *nle;

	nle = nft_rule_expr_alloc(name);
	if (nle == NULL)
		memory_allocation_error();
	return nle;
}

struct nft_set *alloc_nft_set(const struct handle *h)
{
	struct nft_set *nls;

	nls = nft_set_alloc();
	if (nls == NULL)
		memory_allocation_error();

	nft_set_attr_set_u32(nls, NFT_SET_ATTR_FAMILY, h->family);
	nft_set_attr_set_str(nls, NFT_SET_ATTR_TABLE, h->table);
	if (h->set != NULL)
		nft_set_attr_set_str(nls, NFT_SET_ATTR_NAME, h->set);

	return nls;
}

static struct nft_set_elem *alloc_nft_setelem(const struct expr *expr)
{
	struct nft_set_elem *nlse;
	struct nft_data_linearize nld;

	nlse = nft_set_elem_alloc();
	if (nlse == NULL)
		memory_allocation_error();

	if (expr->ops->type == EXPR_VALUE ||
	    expr->flags & EXPR_F_INTERVAL_END) {
		netlink_gen_data(expr, &nld);
		nft_set_elem_attr_set(nlse, NFT_SET_ELEM_ATTR_KEY,
				      &nld.value, nld.len);
	} else {
		assert(expr->ops->type == EXPR_MAPPING);
		netlink_gen_data(expr->left, &nld);
		nft_set_elem_attr_set(nlse, NFT_SET_ELEM_ATTR_KEY,
				      &nld.value, nld.len);
		netlink_gen_data(expr->right, &nld);
		switch (expr->right->ops->type) {
		case EXPR_VERDICT:
			nft_set_elem_attr_set_u32(nlse, NFT_SET_ELEM_ATTR_VERDICT,
						  expr->right->verdict);
			if (expr->chain != NULL) {
				nft_set_elem_attr_set(nlse, NFT_SET_ELEM_ATTR_CHAIN,
						nld.chain, strlen(nld.chain));
			}
			break;
		case EXPR_VALUE:
			nft_set_elem_attr_set(nlse, NFT_SET_ELEM_ATTR_DATA,
					      nld.value, nld.len);
			break;
		default:
			BUG("unexpected set element expression\n");
			break;
		}
	}

	if (expr->flags & EXPR_F_INTERVAL_END) {
		nft_set_elem_attr_set_u32(nlse, NFT_SET_ELEM_ATTR_FLAGS,
					  NFT_SET_ELEM_INTERVAL_END);
	}

	return nlse;
}

void netlink_gen_raw_data(const mpz_t value, enum byteorder byteorder,
			  unsigned int len, struct nft_data_linearize *data)
{
	assert(len > 0);
	mpz_export_data(data->value, value, byteorder, len);
	data->len = len;
}

static void netlink_gen_concat_data(const struct expr *expr,
				    struct nft_data_linearize *nld)
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

		memcpy(nld->value, data, len / BITS_PER_BYTE);
		nld->len = len;
	}
}

static void netlink_gen_constant_data(const struct expr *expr,
				      struct nft_data_linearize *data)
{
	assert(expr->ops->type == EXPR_VALUE);
	netlink_gen_raw_data(expr->value, expr->byteorder,
			     div_round_up(expr->len, BITS_PER_BYTE), data);
}

static void netlink_gen_verdict(const struct expr *expr,
				struct nft_data_linearize *data)
{
	data->verdict = expr->verdict;

	switch (expr->verdict) {
	case NFT_JUMP:
	case NFT_GOTO:
		strncpy(data->chain, expr->chain, NFT_CHAIN_MAXNAMELEN);
		data->chain[NFT_CHAIN_MAXNAMELEN-1] = '\0';
		break;
	}
}

static void netlink_gen_prefix(const struct expr *expr,
			       struct nft_data_linearize *data)
{
	uint32_t idx;
	int32_t i, cidr;
	uint32_t mask;

	assert(expr->ops->type == EXPR_PREFIX);

	data->len = div_round_up(expr->prefix->len, BITS_PER_BYTE);
	cidr = expr->prefix_len;

	for (i = 0; (uint32_t)i / BITS_PER_BYTE < data->len; i += 32) {
		if (cidr - i >= 32)
			mask = 0xffffffff;
		else if (cidr - i > 0)
			mask = (1 << (cidr - i)) - 1;
		else
			mask = 0;

		idx = i / 32;
		data->value[idx] = mask;
	}
}

void netlink_gen_data(const struct expr *expr, struct nft_data_linearize *data)
{
	switch (expr->ops->type) {
	case EXPR_VALUE:
		return netlink_gen_constant_data(expr, data);
	case EXPR_CONCAT:
		return netlink_gen_concat_data(expr, data);
	case EXPR_VERDICT:
		return netlink_gen_verdict(expr, data);
	case EXPR_PREFIX:
		return netlink_gen_prefix(expr, data);
	default:
		BUG("invalid data expression type %s\n", expr->ops->name);
	}
}

struct expr *netlink_alloc_value(const struct location *loc,
				 const struct nft_data_delinearize *nld)
{
	return constant_expr_alloc(loc, &invalid_type, BYTEORDER_INVALID,
				   nld->len * BITS_PER_BYTE, nld->value);
}

static struct expr *netlink_alloc_verdict(const struct location *loc,
					  const struct nft_data_delinearize *nld)
{
	char *chain;

	switch (nld->verdict) {
	case NFT_JUMP:
	case NFT_GOTO:
		chain = xstrdup(nld->chain);
		break;
	default:
		chain = NULL;
		break;
	}

	return verdict_expr_alloc(loc, nld->verdict, chain);
}

struct expr *netlink_alloc_data(const struct location *loc,
				const struct nft_data_delinearize *nld,
				enum nft_registers dreg)
{
	switch (dreg) {
	case NFT_REG_VERDICT:
		return netlink_alloc_verdict(loc, nld);
	default:
		return netlink_alloc_value(loc, nld);
	}
}

int netlink_add_rule_batch(struct netlink_ctx *ctx,
			   const struct handle *h,
		           const struct rule *rule, uint32_t flags)
{
	struct nft_rule *nlr;
	int err;

	nlr = alloc_nft_rule(&rule->handle);
	err = netlink_linearize_rule(ctx, nlr, rule);
	if (err == 0) {
		err = mnl_nft_rule_batch_add(nlr, flags | NLM_F_EXCL,
					     ctx->seqnum);
		if (err < 0)
			netlink_io_error(ctx, &rule->location,
					 "Could not add rule to batch: %s",
					 strerror(errno));
	}
	nft_rule_free(nlr);
	return err;
}

int netlink_add_rule_list(struct netlink_ctx *ctx, const struct handle *h,
			  struct list_head *rule_list)
{
	struct rule *rule;

	list_for_each_entry(rule, rule_list, list) {
		if (netlink_add_rule_batch(ctx, &rule->handle, rule,
					   NLM_F_APPEND) < 0)
			return -1;
	}
	return 0;
}

int netlink_del_rule_batch(struct netlink_ctx *ctx, const struct handle *h,
			   const struct location *loc)
{
	struct nft_rule *nlr;
	int err;

	nlr = alloc_nft_rule(h);
	err = mnl_nft_rule_batch_del(nlr, 0, ctx->seqnum);
	nft_rule_free(nlr);

	if (err < 0)
		netlink_io_error(ctx, loc, "Could not delete rule to batch: %s",
				 strerror(errno));

	return err;
}

void netlink_dump_rule(struct nft_rule *nlr)
{
#ifdef DEBUG
	char buf[4096];

	if (!(debug_level & DEBUG_NETLINK))
		return;

	nft_rule_snprintf(buf, sizeof(buf), nlr, 0, 0);
	fprintf(stdout, "%s\n", buf);
#endif
}

void netlink_dump_expr(struct nft_rule_expr *nle)
{
#ifdef DEBUG
	char buf[4096];

	if (!(debug_level & DEBUG_NETLINK))
		return;

	nft_rule_expr_snprintf(buf, sizeof(buf), nle, 0, 0);
	fprintf(stdout, "%s\n", buf);
#endif
}

static int list_rule_cb(struct nft_rule *nlr, void *arg)
{
	struct netlink_ctx *ctx = arg;
	const struct handle *h = ctx->data;
	struct rule *rule;

	if ((h->family != nft_rule_attr_get_u32(nlr, NFT_RULE_ATTR_FAMILY)) ||
	    strcmp(nft_rule_attr_get_str(nlr, NFT_RULE_ATTR_TABLE), h->table) != 0 ||
	    (h->chain &&
	     strcmp(nft_rule_attr_get_str(nlr, NFT_RULE_ATTR_CHAIN), h->chain) != 0))
		return 0;

	netlink_dump_rule(nlr);
	rule = netlink_delinearize_rule(ctx, nlr);
	list_add_tail(&rule->list, &ctx->list);

	return 0;
}

static int netlink_list_rules(struct netlink_ctx *ctx, const struct handle *h,
			      const struct location *loc)
{
	struct nft_rule_list *rule_cache;

	rule_cache = mnl_nft_rule_dump(nf_sock, h->family);
	if (rule_cache == NULL)
		return netlink_io_error(ctx, loc,
					"Could not receive rules from kernel: %s",
					strerror(errno));

	ctx->data = h;
	nft_rule_list_foreach(rule_cache, list_rule_cb, ctx);
	nft_rule_list_free(rule_cache);
	return 0;
}

static int netlink_flush_rules(struct netlink_ctx *ctx, const struct handle *h,
			       const struct location *loc)
{
	return netlink_del_rule_batch(ctx, h, loc);
}

void netlink_dump_chain(struct nft_chain *nlc)
{
#ifdef DEBUG
	char buf[4096];

	if (!(debug_level & DEBUG_NETLINK))
		return;

	nft_chain_snprintf(buf, sizeof(buf), nlc, 0, 0);
	fprintf(stdout, "%s\n", buf);
#endif
}

int netlink_add_chain(struct netlink_ctx *ctx, const struct handle *h,
		      const struct location *loc, const struct chain *chain)
{
	struct nft_chain *nlc;
	int err;

	nlc = alloc_nft_chain(h);
	if (chain != NULL && chain->flags & CHAIN_F_BASECHAIN) {
		nft_chain_attr_set_u32(nlc, NFT_CHAIN_ATTR_HOOKNUM,
				       chain->hooknum);
		nft_chain_attr_set_u32(nlc, NFT_CHAIN_ATTR_PRIO,
				       chain->priority);
		nft_chain_attr_set_str(nlc, NFT_CHAIN_ATTR_TYPE,
				       chain->type);
	}
	netlink_dump_chain(nlc);
	err = mnl_nft_chain_add(nf_sock, nlc, NLM_F_EXCL);
	nft_chain_free(nlc);

	if (err < 0)
		netlink_io_error(ctx, loc, "Could not add chain: %s",
				 strerror(errno));
	return err;
}

int netlink_rename_chain(struct netlink_ctx *ctx, const struct handle *h,
			 const struct location *loc, const char *name)
{
	struct nft_chain *nlc;
	int err;

	nlc = alloc_nft_chain(h);
	nft_chain_attr_set_str(nlc, NFT_CHAIN_ATTR_NAME, name);
	netlink_dump_chain(nlc);
	err = mnl_nft_chain_add(nf_sock, nlc, 0);
	nft_chain_free(nlc);

	if (err < 0)
		netlink_io_error(ctx, loc, "Could not rename chain: %s",
				 strerror(errno));
	return err;
}

int netlink_delete_chain(struct netlink_ctx *ctx, const struct handle *h,
			 const struct location *loc)
{
	struct nft_chain *nlc;
	int err;

	nlc = alloc_nft_chain(h);
	netlink_dump_chain(nlc);
	err = mnl_nft_chain_delete(nf_sock, nlc, 0);
	nft_chain_free(nlc);

	if (err < 0)
		netlink_io_error(ctx, loc, "Could not delete chain: %s",
				 strerror(errno));
	return err;
}

static int list_chain_cb(struct nft_chain *nlc, void *arg)
{
	struct netlink_ctx *ctx = arg;
	const struct handle *h = ctx->data;
	struct chain *chain;

	if ((h->family != nft_chain_attr_get_u32(nlc, NFT_CHAIN_ATTR_FAMILY)) ||
	    strcmp(nft_chain_attr_get_str(nlc, NFT_CHAIN_ATTR_TABLE), h->table) != 0)
		return 0;

	if (h->chain &&
	    strcmp(nft_chain_attr_get_str(nlc, NFT_CHAIN_ATTR_NAME), h->chain) != 0)
		return 0;

	chain = chain_alloc(nft_chain_attr_get_str(nlc, NFT_CHAIN_ATTR_NAME));
	chain->handle.family =
		nft_chain_attr_get_u32(nlc, NFT_CHAIN_ATTR_FAMILY);
	chain->handle.table  =
		xstrdup(nft_chain_attr_get_str(nlc, NFT_CHAIN_ATTR_NAME));
	chain->handle.handle =
		nft_chain_attr_get_u64(nlc, NFT_CHAIN_ATTR_HANDLE);

	if (nft_chain_attr_is_set(nlc, NFT_CHAIN_ATTR_HOOKNUM) &&
	    nft_chain_attr_is_set(nlc, NFT_CHAIN_ATTR_PRIO) &&
	    nft_chain_attr_is_set(nlc, NFT_CHAIN_ATTR_TYPE)) {
		chain->hooknum       =
			nft_chain_attr_get_u32(nlc, NFT_CHAIN_ATTR_HOOKNUM);
		chain->priority      =
			nft_chain_attr_get_u32(nlc, NFT_CHAIN_ATTR_PRIO);
		chain->type          =
			xstrdup(nft_chain_attr_get_str(nlc, NFT_CHAIN_ATTR_TYPE));
		chain->flags        |= CHAIN_F_BASECHAIN;
	}
	list_add_tail(&chain->list, &ctx->list);

	return 0;
}

int netlink_list_chains(struct netlink_ctx *ctx, const struct handle *h,
			const struct location *loc)
{
	struct nft_chain_list *chain_cache;
	struct chain *chain;

	chain_cache = mnl_nft_chain_dump(nf_sock, h->family);
	if (chain_cache == NULL)
		return netlink_io_error(ctx, loc,
					"Could not receive chains from kernel: %s",
					strerror(errno));

	ctx->data = h;
	nft_chain_list_foreach(chain_cache, list_chain_cb, ctx);
	nft_chain_list_free(chain_cache);

	/* Caller wants all existing chains */
	if (h->chain == NULL)
		return 0;

	/* Check if this chain exists, otherwise return an error */
	list_for_each_entry(chain, &ctx->list, list) {
		if (strcmp(chain->handle.chain, h->chain) == 0)
			return 0;
	}

	return netlink_io_error(ctx, NULL,
				"Could not find chain `%s' in table `%s': %s",
				h->chain, h->table,
				strerror(ENOENT));
}

int netlink_get_chain(struct netlink_ctx *ctx, const struct handle *h,
		      const struct location *loc)
{
	struct nft_chain *nlc;
	struct chain *chain;
	int err;

	nlc = alloc_nft_chain(h);
	err = mnl_nft_chain_get(nf_sock, nlc, 0);

	chain = chain_alloc(nft_chain_attr_get_str(nlc, NFT_CHAIN_ATTR_NAME));
	chain->handle.family = nft_chain_attr_get_u32(nlc, NFT_CHAIN_ATTR_FAMILY);
	chain->handle.table  = xstrdup(nft_chain_attr_get_str(nlc, NFT_CHAIN_ATTR_TABLE));
	chain->handle.handle = nft_chain_attr_get_u64(nlc, NFT_CHAIN_ATTR_HANDLE);
	if (nft_chain_attr_is_set(nlc, NFT_CHAIN_ATTR_TYPE) &&
	    nft_chain_attr_is_set(nlc, NFT_CHAIN_ATTR_HOOKNUM) &&
	    nft_chain_attr_is_set(nlc, NFT_CHAIN_ATTR_PRIO)) {
		chain->hooknum       = nft_chain_attr_get_u32(nlc, NFT_CHAIN_ATTR_HOOKNUM);
		chain->priority      = nft_chain_attr_get_u32(nlc, NFT_CHAIN_ATTR_PRIO);
		chain->type          = xstrdup(nft_chain_attr_get_str(nlc, NFT_CHAIN_ATTR_TYPE));
	}
	list_add_tail(&chain->list, &ctx->list);

	nft_chain_free(nlc);

	if (err < 0)
		return netlink_io_error(ctx, loc,
					"Could not receive chain from kernel: %s",
					strerror(errno));
	return err;
}

int netlink_list_chain(struct netlink_ctx *ctx, const struct handle *h,
		       const struct location *loc)
{
	return netlink_list_rules(ctx, h, loc);
}

int netlink_flush_chain(struct netlink_ctx *ctx, const struct handle *h,
			const struct location *loc)
{
	return netlink_del_rule_batch(ctx, h, loc);
}

int netlink_add_table(struct netlink_ctx *ctx, const struct handle *h,
		      const struct location *loc, const struct table *table)
{
	struct nft_table *nlt;
	int err;

	nlt = alloc_nft_table(h);
	err = mnl_nft_table_add(nf_sock, nlt, NLM_F_EXCL);
	nft_table_free(nlt);

	if (err < 0)
		netlink_io_error(ctx, loc, "Could not add table: %s",
				 strerror(errno));
	return err;
}

int netlink_delete_table(struct netlink_ctx *ctx, const struct handle *h,
			 const struct location *loc)
{
	struct nft_table *nlt;
	int err;

	nlt = alloc_nft_table(h);
	err = mnl_nft_table_delete(nf_sock, nlt, 0);
	nft_table_free(nlt);

	if (err < 0)
		netlink_io_error(ctx, loc, "Could not delete table: %s",
				 strerror(errno));
	return err;
}

void netlink_dump_table(struct nft_table *nlt)
{
#ifdef DEBUG
	char buf[4096];

	if (!(debug_level & DEBUG_NETLINK))
		return;

	nft_table_snprintf(buf, sizeof(buf), nlt, 0, 0);
	fprintf(stdout, "%s\n", buf);
#endif
}

static int list_table_cb(struct nft_table *nlt, void *arg)
{
	struct netlink_ctx *ctx = arg;
	struct table *table;

	netlink_dump_table(nlt);
	table = table_alloc();
	table->handle.family =
		nft_table_attr_get_u32(nlt, NFT_TABLE_ATTR_FAMILY);
	table->handle.table  =
		xstrdup(nft_table_attr_get_str(nlt, NFT_TABLE_ATTR_NAME));
	list_add_tail(&table->list, &ctx->list);

	return 0;
}

int netlink_list_tables(struct netlink_ctx *ctx, const struct handle *h,
			const struct location *loc)
{
	struct nft_table_list *table_cache;
	struct nft_table *nlt;

	table_cache = mnl_nft_table_dump(nf_sock, h->family);
	if (table_cache == NULL)
		return netlink_io_error(ctx, loc,
					"Could not receive tables from kernel: %s",
					strerror(errno));

	nlt = alloc_nft_table(h);
	nft_table_list_foreach(table_cache, list_table_cb, ctx);
	nft_table_free(nlt);
	nft_table_list_free(table_cache);
	return 0;
}

int netlink_get_table(struct netlink_ctx *ctx, const struct handle *h,
		      const struct location *loc)
{
	struct nft_table *nlt;
	int err;

	nlt = alloc_nft_table(h);
	err = mnl_nft_table_get(nf_sock, nlt, 0);
	nft_table_free(nlt);

	if (err < 0)
		return netlink_io_error(ctx, loc,
					"Could not receive table from kernel: %s",
					strerror(errno));
	return err;
}


int netlink_list_table(struct netlink_ctx *ctx, const struct handle *h,
		       const struct location *loc)
{
	return netlink_list_rules(ctx, h, loc);
}

int netlink_flush_table(struct netlink_ctx *ctx, const struct handle *h,
			const struct location *loc)
{
	return netlink_flush_rules(ctx, h, loc);
}

static enum nft_data_types dtype_map_to_kernel(const struct datatype *dtype)
{
	switch (dtype->type) {
	case TYPE_VERDICT:
		return NFT_DATA_VERDICT;
	default:
		return dtype->type;
	}
}

static const struct datatype *dtype_map_from_kernel(enum nft_data_types type)
{
	switch (type) {
	case NFT_DATA_VERDICT:
		return &verdict_type;
	default:
		return datatype_lookup(type);
	}
}

void netlink_dump_set(struct nft_set *nls)
{
#ifdef DEBUG
	char buf[4096];

	if (!(debug_level & DEBUG_NETLINK))
		return;

	nft_set_snprintf(buf, sizeof(buf), nls, 0, 0);
	fprintf(stdout, "%s\n", buf);
#endif
}

int netlink_add_set(struct netlink_ctx *ctx, const struct handle *h,
		    struct set *set)
{
	struct nft_set *nls;
	int err;

	nls = alloc_nft_set(h);
	nft_set_attr_set_u32(nls, NFT_SET_ATTR_FLAGS, set->flags);
	nft_set_attr_set_u32(nls, NFT_SET_ATTR_KEY_TYPE,
			     dtype_map_to_kernel(set->keytype));
	nft_set_attr_set_u32(nls, NFT_SET_ATTR_KEY_LEN,
			     set->keylen / BITS_PER_BYTE);
	if (set->flags & NFT_SET_MAP) {
		nft_set_attr_set_u32(nls, NFT_SET_ATTR_DATA_TYPE,
				     dtype_map_to_kernel(set->datatype));
		nft_set_attr_set_u32(nls, NFT_SET_ATTR_DATA_LEN,
				     set->datalen / BITS_PER_BYTE);
	}
	netlink_dump_set(nls);

	err = mnl_nft_set_add(nf_sock, nls, NLM_F_EXCL | NLM_F_ECHO);
	if (err < 0)
		netlink_io_error(ctx, NULL, "Could not add set: %s",
				 strerror(errno));

	set->handle.set =
		xstrdup(nft_set_attr_get_str(nls, NFT_SET_ATTR_NAME));
	nft_set_free(nls);

	return err;
}

int netlink_delete_set(struct netlink_ctx *ctx, const struct handle *h,
		       const struct location *loc)
{
	struct nft_set *nls;
	int err;

	nls = alloc_nft_set(h);
	err = mnl_nft_set_delete(nf_sock, nls, 0);
	nft_set_free(nls);

	if (err < 0)
		netlink_io_error(ctx, loc, "Could not delete set: %s",
				 strerror(errno));
	return err;
}

static int list_set_cb(struct nft_set *nls, void *arg)
{
	struct netlink_ctx *ctx = arg;
	const struct datatype *keytype, *datatype;
	uint32_t flags, key, data;
	struct set *set;

	netlink_dump_set(nls);
	key = nft_set_attr_get_u32(nls, NFT_SET_ATTR_KEY_TYPE);
	keytype = dtype_map_from_kernel(key);
	if (keytype == NULL) {
		netlink_io_error(ctx, NULL, "Unknown data type in set key %u",
				 key);
		return -1;
	}

	flags = nft_set_attr_get_u32(nls, NFT_SET_ATTR_FLAGS);
	if (flags & NFT_SET_MAP) {
		data = nft_set_attr_get_u32(nls, NFT_SET_ATTR_DATA_TYPE);
		datatype = dtype_map_from_kernel(data);
		if (datatype == NULL) {
			netlink_io_error(ctx, NULL, "Unknown data type in set key %u",
					 data);
			return -1;
		}
	} else
		datatype = NULL;

	set = set_alloc(&internal_location);
	set->handle.family = nft_set_attr_get_u32(nls, NFT_SET_ATTR_FAMILY);
	set->handle.table  =
		xstrdup(nft_set_attr_get_str(nls, NFT_SET_ATTR_TABLE));
	set->handle.set    =
		xstrdup(nft_set_attr_get_str(nls, NFT_SET_ATTR_NAME));
	set->keytype       = keytype;
	set->keylen        =
		nft_set_attr_get_u32(nls, NFT_SET_ATTR_KEY_LEN) * BITS_PER_BYTE;
	set->flags         = flags;
	set->datatype      = datatype;
	if (nft_set_attr_is_set(nls, NFT_SET_ATTR_DATA_LEN)) {
		set->datalen =
			nft_set_attr_get_u32(nls, NFT_SET_ATTR_DATA_LEN) * BITS_PER_BYTE;
	}
	list_add_tail(&set->list, &ctx->list);

	return 0;
}

int netlink_list_sets(struct netlink_ctx *ctx, const struct handle *h,
		      const struct location *loc)
{
	struct nft_set_list *set_cache;

	set_cache = mnl_nft_set_dump(nf_sock, h->family, h->table);
	if (set_cache == NULL)
		return netlink_io_error(ctx, loc,
					"Could not receive sets from kernel: %s",
					strerror(errno));

	nft_set_list_foreach(set_cache, list_set_cb, ctx);
	nft_set_list_free(set_cache);
	return 0;
}

int netlink_get_set(struct netlink_ctx *ctx, const struct handle *h,
		    const struct location *loc)
{
	struct nft_set *nls;
	struct set *set;
	int err;

	nls = alloc_nft_set(h);
	netlink_dump_set(nls);
	err = mnl_nft_set_get(nf_sock, nls);
	if (err < 0)
		return netlink_io_error(ctx, loc,
					"Could not receive set from kernel: %s",
					strerror(errno));

	set = set_alloc(&internal_location);
	set->handle.family = nft_set_attr_get_u32(nls, NFT_SET_ATTR_FAMILY);
	set->handle.table  =
		xstrdup(nft_set_attr_get_str(nls, NFT_SET_ATTR_TABLE));
	set->handle.set    =
		xstrdup(nft_set_attr_get_str(nls, NFT_SET_ATTR_NAME));
	set->keytype       =
		 dtype_map_from_kernel(nft_set_attr_get_u32(nls, NFT_SET_ATTR_KEY_TYPE));
	set->keylen        =
		nft_set_attr_get_u32(nls, NFT_SET_ATTR_KEY_LEN) * BITS_PER_BYTE;
	set->flags         = nft_set_attr_get_u32(nls, NFT_SET_ATTR_FLAGS);
	set->datatype      =
		dtype_map_from_kernel(nft_set_attr_get_u32(nls, NFT_SET_ATTR_DATA_TYPE));
	if (nft_set_attr_is_set(nls, NFT_SET_ATTR_DATA_LEN)) {
		set->datalen =
			nft_set_attr_get_u32(nls, NFT_SET_ATTR_DATA_LEN) * BITS_PER_BYTE;
	}
	list_add_tail(&set->list, &ctx->list);
	nft_set_free(nls);

	return err;
}

static void alloc_setelem_cache(const struct expr *set, struct nft_set *nls)
{
	struct nft_set_elem *nlse;
	const struct expr *expr;

	list_for_each_entry(expr, &set->expressions, list) {
		nlse = alloc_nft_setelem(expr);
		nft_set_elem_add(nls, nlse);
	}
}

int netlink_add_setelems(struct netlink_ctx *ctx, const struct handle *h,
			 const struct expr *expr)
{
	struct nft_set *nls;
	int err;

	nls = alloc_nft_set(h);
	alloc_setelem_cache(expr, nls);
	netlink_dump_set(nls);

	err = mnl_nft_setelem_add(nf_sock, nls, 0);
	nft_set_free(nls);
	if (err < 0)
		netlink_io_error(ctx, &expr->location,
				 "Could not add set elements: %s",
				 strerror(errno));
	return err;
}

int netlink_delete_setelems(struct netlink_ctx *ctx, const struct handle *h,
			    const struct expr *expr)
{
	struct nft_set *nls;
	int err;

	nls = alloc_nft_set(h);
	alloc_setelem_cache(expr, nls);
	netlink_dump_set(nls);

	err = mnl_nft_setelem_delete(nf_sock, nls, 0);
	nft_set_free(nls);
	if (err < 0)
		netlink_io_error(ctx, &expr->location,
				 "Could not delete set elements: %s",
				 strerror(errno));
	return err;
}

static int list_setelem_cb(struct nft_set_elem *nlse, void *arg)
{
	struct nft_data_delinearize nld;
	struct netlink_ctx *ctx = arg;
	struct set *set = ctx->set;
	struct expr *expr, *data;
	uint32_t flags = 0;

	nld.value =
		nft_set_elem_attr_get(nlse, NFT_SET_ELEM_ATTR_KEY, &nld.len);
	if (nft_set_elem_attr_is_set(nlse, NFT_SET_ELEM_ATTR_FLAGS))
		flags = nft_set_elem_attr_get_u32(nlse, NFT_SET_ELEM_ATTR_FLAGS);

	expr = netlink_alloc_value(&internal_location, &nld);
	expr->dtype	= set->keytype;
	expr->byteorder	= set->keytype->byteorder;
	if (expr->byteorder == BYTEORDER_HOST_ENDIAN)
		mpz_switch_byteorder(expr->value, expr->len / BITS_PER_BYTE);

	if (flags & NFT_SET_ELEM_INTERVAL_END) {
		expr->flags |= EXPR_F_INTERVAL_END;
	} else {
		if (nft_set_elem_attr_is_set(nlse, NFT_SET_ELEM_ATTR_DATA)) {
			nld.value = nft_set_elem_attr_get(nlse, NFT_SET_ELEM_ATTR_DATA,
							  &nld.len);
		} else if (nft_set_elem_attr_is_set(nlse, NFT_SET_ELEM_ATTR_CHAIN)) {
			nld.chain = nft_set_elem_attr_get_str(nlse, NFT_SET_ELEM_ATTR_CHAIN);
			nld.verdict = nft_set_elem_attr_get_u32(nlse, NFT_SET_ELEM_ATTR_VERDICT);
		} else if (nft_set_elem_attr_is_set(nlse, NFT_SET_ELEM_ATTR_VERDICT)) {
			nld.verdict = nft_set_elem_attr_get_u32(nlse, NFT_SET_ELEM_ATTR_VERDICT);
		} else
			goto out;

		data = netlink_alloc_data(&internal_location, &nld,
					  set->datatype->type == TYPE_VERDICT ?
					  NFT_REG_VERDICT : NFT_REG_1);
		data->dtype = set->datatype;
		data->byteorder = set->datatype->byteorder;
		if (data->byteorder == BYTEORDER_HOST_ENDIAN)
			mpz_switch_byteorder(data->value, data->len / BITS_PER_BYTE);

		expr = mapping_expr_alloc(&internal_location, expr, data);
	}
out:
	compound_expr_add(set->init, expr);
	return 0;
}

extern void interval_map_decompose(struct expr *set);

int netlink_get_setelems(struct netlink_ctx *ctx, const struct handle *h,
			 const struct location *loc, struct set *set)
{
	struct nft_set *nls;
	int err;

	nls = alloc_nft_set(h);
	netlink_dump_set(nls);

	err = mnl_nft_setelem_get(nf_sock, nls);
	if (err < 0)
		goto out;

	ctx->set = set;
	set->init = set_expr_alloc(loc);
	nft_set_elem_foreach(nls, list_setelem_cb, ctx);
	nft_set_free(nls);
	ctx->set = NULL;

	if (set->flags & NFT_SET_INTERVAL)
		interval_map_decompose(set->init);
out:
	if (err < 0)
		netlink_io_error(ctx, loc, "Could not receive set elements: %s",
				 strerror(errno));
	return err;
}

int netlink_batch_send(struct list_head *err_list)
{
	return mnl_batch_talk(nf_sock, err_list);
}
