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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>

#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/expr.h>
#include <libnftnl/set.h>
#include <libnftnl/common.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter.h>

#include <nftables.h>
#include <netlink.h>
#include <mnl.h>
#include <expression.h>
#include <gmputil.h>
#include <utils.h>
#include <erec.h>

static struct mnl_socket *nf_sock;
static struct mnl_socket *nf_mon_sock;

const struct input_descriptor indesc_netlink = {
	.name	= "netlink",
	.type	= INDESC_NETLINK,
};

const struct location netlink_location = {
	.indesc	= &indesc_netlink,
};

static struct mnl_socket *nfsock_open(void)
{
	struct mnl_socket *s = mnl_socket_open(NETLINK_NETFILTER);
	if (s == NULL)
		netlink_open_error();

	return s;
}

static void __init netlink_open_sock(void)
{
	nf_sock = nfsock_open();
	fcntl(mnl_socket_get_fd(nf_sock), F_SETFL, O_NONBLOCK);
}

static void __exit netlink_close_sock(void)
{
	if (nf_sock)
		mnl_socket_close(nf_sock);
	if (nf_mon_sock)
		mnl_socket_close(nf_mon_sock);
}

void netlink_restart(void)
{
	netlink_close_sock();
	netlink_open_sock();
}

void netlink_genid_get(void)
{
	mnl_genid_get(nf_sock);
}

static void netlink_open_mon_sock(void)
{
	nf_mon_sock = nfsock_open();
}

void __noreturn __netlink_abi_error(const char *file, int line,
				    const char *reason)
{
	fprintf(stderr, "E: Contact urgently your Linux kernel vendor. "
		"Netlink ABI is broken: %s:%d %s\n", file, line, reason);
	exit(NFT_EXIT_FAILURE);
}

int netlink_io_error(struct netlink_ctx *ctx, const struct location *loc,
		     const char *fmt, ...)
{
	struct error_record *erec;
	va_list ap;

	if (loc == NULL)
		loc = &netlink_location;

	va_start(ap, fmt);
	erec = erec_vcreate(EREC_ERROR, loc, fmt, ap);
	va_end(ap);
	erec_queue(erec, ctx->msgs);
	return -1;
}

void __noreturn netlink_open_error(void)
{
	fprintf(stderr, "E: Unable to open Netlink socket: %s\n",
		strerror(errno));
	exit(NFT_EXIT_NONL);
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
	if (h->comment) {
		nft_rule_attr_set_data(nlr, NFT_RULE_ATTR_USERDATA,
				       h->comment, strlen(h->comment) + 1);
	}
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
	if (h->set_id)
		nft_set_attr_set_u32(nls, NFT_SET_ATTR_ID, h->set_id);

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
		nld->len = len / BITS_PER_BYTE;
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

void netlink_gen_data(const struct expr *expr, struct nft_data_linearize *data)
{
	switch (expr->ops->type) {
	case EXPR_VALUE:
		return netlink_gen_constant_data(expr, data);
	case EXPR_CONCAT:
		return netlink_gen_concat_data(expr, data);
	case EXPR_VERDICT:
		return netlink_gen_verdict(expr, data);
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
	netlink_linearize_rule(ctx, nlr, rule);
	err = mnl_nft_rule_batch_add(nlr, flags | NLM_F_EXCL, ctx->seqnum);
	nft_rule_free(nlr);
	if (err < 0) {
		netlink_io_error(ctx, &rule->location,
				 "Could not add rule to batch: %s",
				 strerror(errno));
	}
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
	if (rule_cache == NULL) {
		if (errno == EINTR)
			return -1;

		return netlink_io_error(ctx, loc,
					"Could not receive rules from kernel: %s",
					strerror(errno));
	}

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

static int netlink_add_chain_compat(struct netlink_ctx *ctx,
				    const struct handle *h,
				    const struct location *loc,
				    const struct chain *chain, bool excl)
{
	struct nft_chain *nlc;
	int err;

	nlc = alloc_nft_chain(h);
	if (chain != NULL && chain->flags & CHAIN_F_BASECHAIN) {
		nft_chain_attr_set_u32(nlc, NFT_CHAIN_ATTR_HOOKNUM,
				       chain->hooknum);
		nft_chain_attr_set_s32(nlc, NFT_CHAIN_ATTR_PRIO,
				       chain->priority);
		nft_chain_attr_set_str(nlc, NFT_CHAIN_ATTR_TYPE,
				       chain->type);
	}
	netlink_dump_chain(nlc);
	err = mnl_nft_chain_add(nf_sock, nlc, excl ? NLM_F_EXCL : 0);
	nft_chain_free(nlc);

	if (err < 0)
		netlink_io_error(ctx, loc, "Could not add chain: %s",
				 strerror(errno));
	return err;
}

static int netlink_add_chain_batch(struct netlink_ctx *ctx,
				   const struct handle *h,
				   const struct location *loc,
				   const struct chain *chain, bool excl)
{
	struct nft_chain *nlc;
	int err;

	nlc = alloc_nft_chain(h);
	if (chain != NULL && chain->flags & CHAIN_F_BASECHAIN) {
		nft_chain_attr_set_u32(nlc, NFT_CHAIN_ATTR_HOOKNUM,
				       chain->hooknum);
		nft_chain_attr_set_s32(nlc, NFT_CHAIN_ATTR_PRIO,
				       chain->priority);
		nft_chain_attr_set_str(nlc, NFT_CHAIN_ATTR_TYPE,
				       chain->type);
	}
	netlink_dump_chain(nlc);
	err = mnl_nft_chain_batch_add(nlc, excl ? NLM_F_EXCL : 0,
				      ctx->seqnum);
	nft_chain_free(nlc);

	if (err < 0) {
		netlink_io_error(ctx, loc, "Could not add chain: %s",
				 strerror(errno));
	}
	return err;
}

int netlink_add_chain(struct netlink_ctx *ctx, const struct handle *h,
		      const struct location *loc, const struct chain *chain,
		      bool excl)
{
	int ret;

	if (ctx->batch_supported)
		ret = netlink_add_chain_batch(ctx, h, loc, chain, excl);
	else
		ret = netlink_add_chain_compat(ctx, h, loc, chain, excl);

	return ret;
}

static int netlink_rename_chain_compat(struct netlink_ctx *ctx,
				       const struct handle *h,
				       const struct location *loc,
				       const char *name)
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

static int netlink_rename_chain_batch(struct netlink_ctx *ctx,
				      const struct handle *h,
				      const struct location *loc,
				      const char *name)
{
	struct nft_chain *nlc;
	int err;

	nlc = alloc_nft_chain(h);
	nft_chain_attr_set_str(nlc, NFT_CHAIN_ATTR_NAME, name);
	netlink_dump_chain(nlc);
	err = mnl_nft_chain_batch_add(nlc, 0, ctx->seqnum);
	nft_chain_free(nlc);

	if (err < 0) {
		netlink_io_error(ctx, loc, "Could not rename chain: %s",
				 strerror(errno));
	}
	return err;
}

int netlink_rename_chain(struct netlink_ctx *ctx, const struct handle *h,
			 const struct location *loc, const char *name)
{
	int ret;

	if (ctx->batch_supported)
		ret = netlink_rename_chain_batch(ctx, h, loc, name);
	else
		ret = netlink_rename_chain_compat(ctx, h, loc, name);

	return ret;
}

static int netlink_del_chain_compat(struct netlink_ctx *ctx,
				    const struct handle *h,
				    const struct location *loc)
{
	struct nft_chain *nlc;
	int err;

	nlc = alloc_nft_chain(h);
	netlink_dump_chain(nlc);
	err = mnl_nft_chain_delete(nf_sock, nlc, 0);
	nft_chain_free(nlc);

	if (err < 0) {
		netlink_io_error(ctx, loc, "Could not delete chain: %s",
				 strerror(errno));
	}
	return err;
}

static int netlink_del_chain_batch(struct netlink_ctx *ctx,
				   const struct handle *h,
				   const struct location *loc)
{
	struct nft_chain *nlc;
	int err;

	nlc = alloc_nft_chain(h);
	netlink_dump_chain(nlc);
	err = mnl_nft_chain_batch_del(nlc, 0, ctx->seqnum);
	nft_chain_free(nlc);

	if (err < 0) {
		netlink_io_error(ctx, loc, "Could not delete chain: %s",
				 strerror(errno));
	}
	return err;
}

int netlink_delete_chain(struct netlink_ctx *ctx, const struct handle *h,
			 const struct location *loc)
{
	int ret;

	if (ctx->batch_supported)
		ret = netlink_del_chain_batch(ctx, h, loc);
	else
		ret = netlink_del_chain_compat(ctx, h, loc);

	return ret;
}

static struct chain *netlink_delinearize_chain(struct netlink_ctx *ctx,
					       struct nft_chain *nlc)
{
	struct chain *chain;

	chain = chain_alloc(nft_chain_attr_get_str(nlc, NFT_CHAIN_ATTR_NAME));
	chain->handle.family =
		nft_chain_attr_get_u32(nlc, NFT_CHAIN_ATTR_FAMILY);
	chain->handle.table  =
		xstrdup(nft_chain_attr_get_str(nlc, NFT_CHAIN_ATTR_TABLE));
	chain->handle.handle =
		nft_chain_attr_get_u64(nlc, NFT_CHAIN_ATTR_HANDLE);

	if (nft_chain_attr_is_set(nlc, NFT_CHAIN_ATTR_HOOKNUM) &&
	    nft_chain_attr_is_set(nlc, NFT_CHAIN_ATTR_PRIO) &&
	    nft_chain_attr_is_set(nlc, NFT_CHAIN_ATTR_TYPE)) {
		chain->hooknum       =
			nft_chain_attr_get_u32(nlc, NFT_CHAIN_ATTR_HOOKNUM);
		chain->priority      =
			nft_chain_attr_get_s32(nlc, NFT_CHAIN_ATTR_PRIO);
		chain->type          =
			xstrdup(nft_chain_attr_get_str(nlc, NFT_CHAIN_ATTR_TYPE));
		chain->flags        |= CHAIN_F_BASECHAIN;
	}

	return chain;
}

static int list_chain_cb(struct nft_chain *nlc, void *arg)
{
	struct netlink_ctx *ctx = arg;
	const struct handle *h = ctx->data;
	const char *table = nft_chain_attr_get_str(nlc, NFT_CHAIN_ATTR_TABLE);
	const char *name = nft_chain_attr_get_str(nlc, NFT_CHAIN_ATTR_NAME);
	struct chain *chain;

	if ((h->family != nft_chain_attr_get_u32(nlc, NFT_CHAIN_ATTR_FAMILY)) ||
	    strcmp(table, h->table) != 0)
		return 0;

	if (h->chain && strcmp(name, h->chain) != 0)
		return 0;

	chain = netlink_delinearize_chain(ctx, nlc);
	list_add_tail(&chain->list, &ctx->list);

	return 0;
}

int netlink_list_chains(struct netlink_ctx *ctx, const struct handle *h,
			const struct location *loc)
{
	struct nft_chain_list *chain_cache;
	struct chain *chain;

	chain_cache = mnl_nft_chain_dump(nf_sock, h->family);
	if (chain_cache == NULL) {
		if (errno == EINTR)
			return -1;

		return netlink_io_error(ctx, loc,
					"Could not receive chains from kernel: %s",
					strerror(errno));
	}

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
	if (err < 0) {
		nft_chain_free(nlc);
		return netlink_io_error(ctx, loc,
					"Could not receive chain from kernel: %s",
					strerror(errno));
	}

	chain = netlink_delinearize_chain(ctx, nlc);
	list_add_tail(&chain->list, &ctx->list);
	nft_chain_free(nlc);

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

static int netlink_add_table_compat(struct netlink_ctx *ctx,
				    const struct handle *h,
				    const struct location *loc,
				    const struct table *table, bool excl)
{
	struct nft_table *nlt;
	int err;

	nlt = alloc_nft_table(h);
	err = mnl_nft_table_add(nf_sock, nlt, excl ? NLM_F_EXCL : 0);
	nft_table_free(nlt);

	if (err < 0)
		netlink_io_error(ctx, loc, "Could not add table: %s",
				 strerror(errno));
	return err;
}

static int netlink_add_table_batch(struct netlink_ctx *ctx,
				   const struct handle *h,
				   const struct location *loc,
				   const struct table *table, bool excl)
{
	struct nft_table *nlt;
	int err;

	nlt = alloc_nft_table(h);
	err = mnl_nft_table_batch_add(nlt, excl ? NLM_F_EXCL : 0,
				      ctx->seqnum);
	nft_table_free(nlt);

	if (err < 0) {
		netlink_io_error(ctx, loc, "Could not add table: %s",
				 strerror(errno));
	}
	return err;
}

int netlink_add_table(struct netlink_ctx *ctx, const struct handle *h,
		      const struct location *loc,
		      const struct table *table, bool excl)
{
	int ret;

	if (ctx->batch_supported)
		ret = netlink_add_table_batch(ctx, h, loc, table, excl);
	else
		ret = netlink_add_table_compat(ctx, h, loc, table, excl);

	return ret;
}

static int netlink_del_table_compat(struct netlink_ctx *ctx,
				    const struct handle *h,
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

static int netlink_del_table_batch(struct netlink_ctx *ctx,
				   const struct handle *h,
				   const struct location *loc)
{
	struct nft_table *nlt;
	int err;

	nlt = alloc_nft_table(h);
	err = mnl_nft_table_batch_del(nlt, 0, ctx->seqnum);
	nft_table_free(nlt);

	if (err < 0) {
		netlink_io_error(ctx, loc, "Could not delete table: %s",
				 strerror(errno));
	}
	return err;
}

int netlink_delete_table(struct netlink_ctx *ctx, const struct handle *h,
			 const struct location *loc)
{
	int ret;

	if (ctx->batch_supported)
		ret = netlink_del_table_batch(ctx, h, loc);
	else
		ret = netlink_del_table_compat(ctx, h, loc);

	return ret;
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

static struct table *netlink_delinearize_table(struct netlink_ctx *ctx,
					       struct nft_table *nlt)
{
	struct table *table;

	netlink_dump_table(nlt);
	table = table_alloc();
	table->handle.family =
		nft_table_attr_get_u32(nlt, NFT_TABLE_ATTR_FAMILY);
	table->handle.table  =
		xstrdup(nft_table_attr_get_str(nlt, NFT_TABLE_ATTR_NAME));

	return table;
}

static int list_table_cb(struct nft_table *nlt, void *arg)
{
	struct netlink_ctx *ctx = arg;
	struct table *table;

	table = netlink_delinearize_table(ctx, nlt);
	list_add_tail(&table->list, &ctx->list);

	return 0;
}

int netlink_list_tables(struct netlink_ctx *ctx, const struct handle *h,
			const struct location *loc)
{
	struct nft_table_list *table_cache;

	table_cache = mnl_nft_table_dump(nf_sock, h->family);
	if (table_cache == NULL) {
		if (errno == EINTR)
			return -1;

		return netlink_io_error(ctx, loc,
					"Could not receive tables from kernel: %s",
					strerror(errno));
	}

	nft_table_list_foreach(table_cache, list_table_cb, ctx);
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

static struct set *netlink_delinearize_set(struct netlink_ctx *ctx,
					   struct nft_set *nls)
{
	struct set *set;
	const struct datatype *keytype, *datatype;
	uint32_t flags, key, data, data_len;

	key = nft_set_attr_get_u32(nls, NFT_SET_ATTR_KEY_TYPE);
	keytype = dtype_map_from_kernel(key);
	if (keytype == NULL) {
		netlink_io_error(ctx, NULL, "Unknown data type in set key %u",
				 key);
		return NULL;
	}

	flags = nft_set_attr_get_u32(nls, NFT_SET_ATTR_FLAGS);
	if (flags & NFT_SET_MAP) {
		data = nft_set_attr_get_u32(nls, NFT_SET_ATTR_DATA_TYPE);
		datatype = dtype_map_from_kernel(data);
		if (datatype == NULL) {
			netlink_io_error(ctx, NULL,
					 "Unknown data type in set key %u",
					 data);
			return NULL;
		}
	} else
		datatype = NULL;

	set = set_alloc(&netlink_location);
	set->handle.family = nft_set_attr_get_u32(nls, NFT_SET_ATTR_FAMILY);
	set->handle.table  =
		xstrdup(nft_set_attr_get_str(nls, NFT_SET_ATTR_TABLE));
	set->handle.set    =
		xstrdup(nft_set_attr_get_str(nls, NFT_SET_ATTR_NAME));

	set->keytype = keytype;
	set->keylen        =
		nft_set_attr_get_u32(nls, NFT_SET_ATTR_KEY_LEN) * BITS_PER_BYTE;

	set->flags         = nft_set_attr_get_u32(nls, NFT_SET_ATTR_FLAGS);

	set->datatype = datatype;
	if (nft_set_attr_is_set(nls, NFT_SET_ATTR_DATA_LEN)) {
		data_len = nft_set_attr_get_u32(nls, NFT_SET_ATTR_DATA_LEN);
		set->datalen = data_len * BITS_PER_BYTE;
	}

	if (nft_set_attr_is_set(nls, NFT_SET_ATTR_POLICY))
		set->policy = nft_set_attr_get_u32(nls, NFT_SET_ATTR_POLICY);

	if (nft_set_attr_is_set(nls, NFT_SET_ATTR_DESC_SIZE))
		set->desc.size = nft_set_attr_get_u32(nls,
						      NFT_SET_ATTR_DESC_SIZE);

	return set;
}

static int netlink_add_set_compat(struct netlink_ctx *ctx,
				  const struct handle *h, struct set *set)
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
		netlink_io_error(ctx, &set->location, "Could not add set: %s",
				 strerror(errno));

	set->handle.set =
		xstrdup(nft_set_attr_get_str(nls, NFT_SET_ATTR_NAME));
	nft_set_free(nls);

	return err;
}

/* internal ID to uniquely identify a set in the batch */
static uint32_t set_id;

static int netlink_add_set_batch(struct netlink_ctx *ctx,
				 const struct handle *h, struct set *set)
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
	set->handle.set_id = ++set_id;
	nft_set_attr_set_u32(nls, NFT_SET_ATTR_ID, set->handle.set_id);

	if (!(set->flags & (SET_F_CONSTANT))) {
		if (set->policy != NFT_SET_POL_PERFORMANCE) {
			nft_set_attr_set_u32(nls, NFT_SET_ATTR_POLICY,
					     set->policy);
		}

		if (set->desc.size != 0) {
			nft_set_attr_set_u32(nls, NFT_SET_ATTR_DESC_SIZE,
					     set->desc.size);
		}
	}

	netlink_dump_set(nls);

	err = mnl_nft_set_batch_add(nls, NLM_F_EXCL, ctx->seqnum);
	if (err < 0) {
		netlink_io_error(ctx, &set->location, "Could not add set: %s",
				 strerror(errno));
	}
	nft_set_free(nls);

	return err;
}

int netlink_add_set(struct netlink_ctx *ctx, const struct handle *h,
		    struct set *set)
{
	int ret;

	if (ctx->batch_supported)
		ret = netlink_add_set_batch(ctx, h, set);
	else
		ret = netlink_add_set_compat(ctx, h, set);

	return ret;
}

static int netlink_del_set_compat(struct netlink_ctx *ctx,
				  const struct handle *h,
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

static int netlink_del_set_batch(struct netlink_ctx *ctx,
				 const struct handle *h,
				 const struct location *loc)
{
	struct nft_set *nls;
	int err;

	nls = alloc_nft_set(h);
	err = mnl_nft_set_batch_del(nls, 0, ctx->seqnum);
	nft_set_free(nls);

	if (err < 0)
		netlink_io_error(ctx, loc, "Could not delete set: %s",
				 strerror(errno));
	return err;
}

int netlink_delete_set(struct netlink_ctx *ctx, const struct handle *h,
		       const struct location *loc)
{
	int ret;

	if (ctx->batch_supported)
		ret = netlink_del_set_batch(ctx, h, loc);
	else
		ret = netlink_del_set_compat(ctx, h, loc);

	return ret;
}

static int list_set_cb(struct nft_set *nls, void *arg)
{
	struct netlink_ctx *ctx = arg;
	struct set *set;

	netlink_dump_set(nls);
	set = netlink_delinearize_set(ctx, nls);
	if (set == NULL)
		return -1;
	list_add_tail(&set->list, &ctx->list);
	return 0;
}

int netlink_list_sets(struct netlink_ctx *ctx, const struct handle *h,
		      const struct location *loc)
{
	struct nft_set_list *set_cache;
	int err;

	set_cache = mnl_nft_set_dump(nf_sock, h->family, h->table);
	if (set_cache == NULL) {
		if (errno == EINTR)
			return -1;

		return netlink_io_error(ctx, loc,
					"Could not receive sets from kernel: %s",
					strerror(errno));
	}

	err = nft_set_list_foreach(set_cache, list_set_cb, ctx);
	nft_set_list_free(set_cache);
	return err;
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
	if (err < 0) {
		nft_set_free(nls);
		return netlink_io_error(ctx, loc,
					"Could not receive set from kernel: %s",
					strerror(errno));
	}

	set = netlink_delinearize_set(ctx, nls);
	nft_set_free(nls);
	if (set == NULL)
		return -1;
	list_add_tail(&set->list, &ctx->list);

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

static int netlink_add_setelems_batch(struct netlink_ctx *ctx,
				      const struct handle *h,
				      const struct expr *expr)
{
	struct nft_set *nls;
	int err;

	nls = alloc_nft_set(h);
	alloc_setelem_cache(expr, nls);
	netlink_dump_set(nls);

	err = mnl_nft_setelem_batch_add(nls, 0, ctx->seqnum);
	nft_set_free(nls);
	if (err < 0)
		netlink_io_error(ctx, &expr->location,
				 "Could not add set elements: %s",
				 strerror(errno));
	return err;
}

static int netlink_add_setelems_compat(struct netlink_ctx *ctx,
				       const struct handle *h,
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

int netlink_add_setelems(struct netlink_ctx *ctx, const struct handle *h,
			 const struct expr *expr)
{
	int ret;

	if (ctx->batch_supported)
		ret = netlink_add_setelems_batch(ctx, h, expr);
	else
		ret = netlink_add_setelems_compat(ctx, h, expr);

	return ret;
}

static int netlink_del_setelems_batch(struct netlink_ctx *ctx,
				      const struct handle *h,
				      const struct expr *expr)
{
	struct nft_set *nls;
	int err;

	nls = alloc_nft_set(h);
	alloc_setelem_cache(expr, nls);
	netlink_dump_set(nls);

	err = mnl_nft_setelem_batch_del(nls, 0, ctx->seqnum);
	nft_set_free(nls);
	if (err < 0)
		netlink_io_error(ctx, &expr->location,
				 "Could not delete set elements: %s",
				 strerror(errno));
	return err;
}

static int netlink_del_setelems_compat(struct netlink_ctx *ctx,
				       const struct handle *h,
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

static int netlink_delinearize_setelem(struct nft_set_elem *nlse,
				       struct set *set)
{
	struct nft_data_delinearize nld;
	struct expr *expr, *data;
	uint32_t flags = 0;

	nld.value =
		nft_set_elem_attr_get(nlse, NFT_SET_ELEM_ATTR_KEY, &nld.len);
	if (nft_set_elem_attr_is_set(nlse, NFT_SET_ELEM_ATTR_FLAGS))
		flags = nft_set_elem_attr_get_u32(nlse, NFT_SET_ELEM_ATTR_FLAGS);

	expr = netlink_alloc_value(&netlink_location, &nld);
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

		data = netlink_alloc_data(&netlink_location, &nld,
					  set->datatype->type == TYPE_VERDICT ?
					  NFT_REG_VERDICT : NFT_REG_1);
		data->dtype = set->datatype;
		data->byteorder = set->datatype->byteorder;
		if (data->byteorder == BYTEORDER_HOST_ENDIAN)
			mpz_switch_byteorder(data->value, data->len / BITS_PER_BYTE);

		expr = mapping_expr_alloc(&netlink_location, expr, data);
	}
out:
	compound_expr_add(set->init, expr);
	return 0;
}

int netlink_delete_setelems(struct netlink_ctx *ctx, const struct handle *h,
			    const struct expr *expr)
{
	int ret;

	if (ctx->batch_supported)
		ret = netlink_del_setelems_batch(ctx, h, expr);
	else
		ret = netlink_del_setelems_compat(ctx, h, expr);

	return ret;
}

static int list_setelem_cb(struct nft_set_elem *nlse, void *arg)
{
	struct netlink_ctx *ctx = arg;
	return netlink_delinearize_setelem(nlse, ctx->set);
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
	if (err < 0) {
		nft_set_free(nls);
		if (errno == EINTR)
			return -1;

		goto out;
	}

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

int netlink_flush_ruleset(struct netlink_ctx *ctx, const struct handle *h,
			  const struct location *loc)
{
	int err;
	struct nft_table *nlt;

	if (!ctx->batch_supported) {
		netlink_io_error(ctx, loc, "Operation not supported.");
		return -1;
	}

	nlt = alloc_nft_table(h);
	err = mnl_nft_table_batch_del(nlt, 0, ctx->seqnum);
	nft_table_free(nlt);

	if (err < 0)
		netlink_io_error(ctx, loc, "Could not flush the ruleset: %s",
				 strerror(errno));

	return err;
}

struct nft_ruleset *netlink_dump_ruleset(struct netlink_ctx *ctx,
					 const struct handle *h,
					 const struct location *loc)
{
	struct nft_ruleset *rs;

	rs = mnl_nft_ruleset_dump(nf_sock, h->family);
	if (rs == NULL) {
		if (errno == EINTR)
			return NULL;

		netlink_io_error(ctx, loc, "Could not receive ruleset: %s",
				 strerror(errno));
	}

	return rs;
}

static struct nft_table *netlink_table_alloc(const struct nlmsghdr *nlh)
{
	struct nft_table *nlt = nft_table_alloc();
	if (nlt == NULL)
		memory_allocation_error();

	if (nft_table_nlmsg_parse(nlh, nlt) < 0)
		netlink_abi_error();

	return nlt;
}

static struct nft_chain *netlink_chain_alloc(const struct nlmsghdr *nlh)
{
	struct nft_chain *nlc = nft_chain_alloc();
	if (nlc == NULL)
		memory_allocation_error();

	if (nft_chain_nlmsg_parse(nlh, nlc) < 0)
		netlink_abi_error();

	return nlc;
}

static struct nft_set *netlink_set_alloc(const struct nlmsghdr *nlh)
{
	struct nft_set *nls = nft_set_alloc();
	if (nls == NULL)
		memory_allocation_error();

	if (nft_set_nlmsg_parse(nlh, nls) < 0)
		netlink_abi_error();

	return nls;
}

static struct nft_set *netlink_setelem_alloc(const struct nlmsghdr *nlh)
{
	struct nft_set *nls = nft_set_alloc();
	if (nls == NULL)
		memory_allocation_error();

	if (nft_set_elems_nlmsg_parse(nlh, nls) < 0)
		netlink_abi_error();

	return nls;
}

static struct nft_rule *netlink_rule_alloc(const struct nlmsghdr *nlh)
{
	struct nft_rule *nlr = nft_rule_alloc();
	if (nlr == NULL)
		memory_allocation_error();

	if (nft_rule_nlmsg_parse(nlh, nlr) < 0)
		netlink_abi_error();

	return nlr;
}

static uint32_t netlink_msg2nftnl_of(uint32_t msg)
{
	switch (msg) {
	case NFT_MSG_NEWTABLE:
	case NFT_MSG_NEWCHAIN:
	case NFT_MSG_NEWSET:
	case NFT_MSG_NEWSETELEM:
	case NFT_MSG_NEWRULE:
		return NFT_OF_EVENT_NEW;
	case NFT_MSG_DELTABLE:
	case NFT_MSG_DELCHAIN:
	case NFT_MSG_DELSET:
	case NFT_MSG_DELSETELEM:
	case NFT_MSG_DELRULE:
		return NFT_OF_EVENT_DEL;
	}

	return 0;
}

static void nlr_for_each_set(struct nft_rule *nlr,
			     void (*cb)(struct set *s, void *data),
			     void *data)
{
	struct set *s;
	uint32_t family;
	const char *set_name, *table;
	struct nft_rule_expr *nlre;
	struct nft_rule_expr_iter *nlrei;
	const char *name;

	nlrei = nft_rule_expr_iter_create(nlr);
	if (nlrei == NULL)
		memory_allocation_error();

	family = nft_rule_attr_get_u32(nlr, NFT_RULE_ATTR_FAMILY);
	table = nft_rule_attr_get_str(nlr, NFT_RULE_ATTR_TABLE);

	nlre = nft_rule_expr_iter_next(nlrei);
	while (nlre != NULL) {
		name = nft_rule_expr_get_str(nlre, NFT_RULE_EXPR_ATTR_NAME);
		if (strcmp(name, "lookup") != 0)
			goto next;

		set_name = nft_rule_expr_get_str(nlre, NFT_EXPR_LOOKUP_SET);
		s = set_lookup_global(family, table, set_name);
		if (s == NULL)
			goto next;

		cb(s, data);
next:
		nlre = nft_rule_expr_iter_next(nlrei);
	}
	nft_rule_expr_iter_destroy(nlrei);
}

static int netlink_events_table_cb(const struct nlmsghdr *nlh, int type,
				   struct netlink_mon_handler *monh)
{
	uint32_t family;
	struct nft_table *nlt = netlink_table_alloc(nlh);

	switch (monh->format) {
	case NFT_OUTPUT_DEFAULT:
		if (type == NFT_MSG_NEWTABLE) {
			if (nlh->nlmsg_flags & NLM_F_EXCL)
				printf("update table ");
			else
				printf("add table ");
		} else {
			printf("delete table ");
		}

		family = nft_table_attr_get_u32(nlt, NFT_TABLE_ATTR_FAMILY);

		printf("%s %s\n", family2str(family),
		       nft_table_attr_get_str(nlt, NFT_TABLE_ATTR_NAME));
		break;
	case NFT_OUTPUT_XML:
	case NFT_OUTPUT_JSON:
		nft_table_fprintf(stdout, nlt, monh->format,
				  netlink_msg2nftnl_of(type));
		fprintf(stdout, "\n");
		break;
	}

	nft_table_free(nlt);
	return MNL_CB_OK;
}

static int netlink_events_chain_cb(const struct nlmsghdr *nlh, int type,
				   struct netlink_mon_handler *monh)
{
	struct chain *c;
	uint32_t family;
	struct nft_chain *nlc = netlink_chain_alloc(nlh);

	switch (monh->format) {
	case NFT_OUTPUT_DEFAULT:
		switch (type) {
		case NFT_MSG_NEWCHAIN:
			if (nlh->nlmsg_flags & NLM_F_EXCL)
				printf("update ");
			else
				printf("add ");

			c = netlink_delinearize_chain(monh->ctx, nlc);
			chain_print_plain(c);
			chain_free(c);
			break;
		case NFT_MSG_DELCHAIN:
			family = nft_chain_attr_get_u32(nlc,
							NFT_CHAIN_ATTR_FAMILY);
			printf("delete chain %s %s %s\n", family2str(family),
			       nft_chain_attr_get_str(nlc,
						      NFT_CHAIN_ATTR_TABLE),
			       nft_chain_attr_get_str(nlc,
						      NFT_CHAIN_ATTR_NAME));
			break;
		}
		break;
	case NFT_OUTPUT_XML:
	case NFT_OUTPUT_JSON:
		nft_chain_fprintf(stdout, nlc, monh->format,
				  netlink_msg2nftnl_of(type));
		fprintf(stdout, "\n");
		break;
	}

	nft_chain_free(nlc);
	return MNL_CB_OK;
}

static int netlink_events_set_cb(const struct nlmsghdr *nlh, int type,
				 struct netlink_mon_handler *monh)
{
	struct set *set;
	uint32_t family, flags;
	struct nft_set *nls = netlink_set_alloc(nlh);

	flags = nft_set_attr_get_u32(nls, NFT_SET_ATTR_FLAGS);
	if (flags & SET_F_ANONYMOUS)
		goto out;

	switch (monh->format) {
	case NFT_OUTPUT_DEFAULT:
		switch (type) {
		case NFT_MSG_NEWSET:
			printf("add ");
			set = netlink_delinearize_set(monh->ctx, nls);
			if (set == NULL)
				return MNL_CB_ERROR;
			set_print_plain(set);
			set_free(set);
			printf("\n");
			break;
		case NFT_MSG_DELSET:
			family = nft_set_attr_get_u32(nls,
						      NFT_SET_ATTR_FAMILY);
			printf("delete set %s %s %s\n",
			       family2str(family),
			       nft_set_attr_get_str(nls, NFT_SET_ATTR_TABLE),
			       nft_set_attr_get_str(nls, NFT_SET_ATTR_NAME));
			break;
		}
		break;
	case NFT_OUTPUT_XML:
	case NFT_OUTPUT_JSON:
		nft_set_fprintf(stdout, nls, monh->format,
				netlink_msg2nftnl_of(type));
		fprintf(stdout, "\n");
		break;
	}
out:
	nft_set_free(nls);
	return MNL_CB_OK;
}

static int netlink_events_setelem_cb(const struct nlmsghdr *nlh, int type,
				     struct netlink_mon_handler *monh)
{
	struct nft_set_elem *nlse;
	struct nft_set_elems_iter *nlsei;
	struct set *dummyset;
	struct set *set;
	const char *setname, *table;
	uint32_t family;
	struct nft_set *nls = netlink_setelem_alloc(nlh);

	table = nft_set_attr_get_str(nls, NFT_SET_ATTR_TABLE);
	setname = nft_set_attr_get_str(nls, NFT_SET_ATTR_NAME);
	family = nft_set_attr_get_u32(nls, NFT_SET_ATTR_FAMILY);

	set = set_lookup_global(family, table, setname);
	if (set == NULL) {
		fprintf(stderr, "W: Received event for an unknown set.");
		goto out;
	}

	switch (monh->format) {
	case NFT_OUTPUT_DEFAULT:
		if (set->flags & SET_F_ANONYMOUS)
			goto out;

		/* we want to 'delinearize' the set_elem, but don't
		 * modify the original cached set. This path is only
		 * used by named sets, so use a dummy set.
		 */
		dummyset = set_alloc(monh->loc);
		dummyset->keytype = set->keytype;
		dummyset->datatype = set->datatype;
		dummyset->init = set_expr_alloc(monh->loc);

		nlsei = nft_set_elems_iter_create(nls);
		if (nlsei == NULL)
			memory_allocation_error();

		nlse = nft_set_elems_iter_next(nlsei);
		while (nlse != NULL) {
			if (netlink_delinearize_setelem(nlse, dummyset) < 0) {
				set_free(dummyset);
				nft_set_elems_iter_destroy(nlsei);
				goto out;
			}
			nlse = nft_set_elems_iter_next(nlsei);
		}
		nft_set_elems_iter_destroy(nlsei);

		switch (type) {
		case NFT_MSG_NEWSETELEM:
			printf("add ");
			break;
		case NFT_MSG_DELSETELEM:
			printf("delete ");
			break;
		default:
			set_free(dummyset);
			goto out;
		}
		printf("element %s %s %s ", family2str(family), table, setname);
		expr_print(dummyset->init);
		printf("\n");

		set_free(dummyset);
		break;
	case NFT_OUTPUT_XML:
	case NFT_OUTPUT_JSON:
		nft_set_fprintf(stdout, nls, monh->format,
				netlink_msg2nftnl_of(type));
		fprintf(stdout, "\n");
		break;
	}
out:
	nft_set_free(nls);
	return MNL_CB_OK;
}

static void rule_map_decompose_cb(struct set *s, void *data)
{
	if (s->flags & NFT_SET_INTERVAL)
		interval_map_decompose(s->init);
}

static int netlink_events_rule_cb(const struct nlmsghdr *nlh, int type,
				  struct netlink_mon_handler *monh)
{
	struct rule *r;
	uint32_t fam;
	const char *family;
	const char *table;
	const char *chain;
	uint64_t handle;
	struct nft_rule *nlr = netlink_rule_alloc(nlh);

	switch (monh->format) {
	case NFT_OUTPUT_DEFAULT:
		fam = nft_rule_attr_get_u32(nlr, NFT_RULE_ATTR_FAMILY);
		family = family2str(fam);
		table = nft_rule_attr_get_str(nlr, NFT_RULE_ATTR_TABLE);
		chain = nft_rule_attr_get_str(nlr, NFT_RULE_ATTR_CHAIN);
		handle = nft_rule_attr_get_u64(nlr, NFT_RULE_ATTR_HANDLE);

		switch (type) {
		case NFT_MSG_NEWRULE:
			r = netlink_delinearize_rule(monh->ctx, nlr);
			nlr_for_each_set(nlr, rule_map_decompose_cb, NULL);

			printf("add rule %s %s %s", family, table, chain);
			rule_print(r);
			printf("\n");

			rule_free(r);
			break;
		case NFT_MSG_DELRULE:
			printf("delete rule %s %s %s handle %u\n",
			       family, table, chain, (unsigned int)handle);
			break;
		}
		break;
	case NFT_OUTPUT_XML:
	case NFT_OUTPUT_JSON:
		nft_rule_fprintf(stdout, nlr, monh->format,
				 netlink_msg2nftnl_of(type));
		fprintf(stdout, "\n");
		break;
	}

	nft_rule_free(nlr);
	return MNL_CB_OK;
}

static void netlink_events_cache_addtable(struct netlink_mon_handler *monh,
					  const struct nlmsghdr *nlh)
{
	struct table *t;
	struct nft_table *nlt = netlink_table_alloc(nlh);

	t = netlink_delinearize_table(monh->ctx, nlt);
	table_add_hash(t);

	nft_table_free(nlt);
}

static void netlink_events_cache_deltable(struct netlink_mon_handler *monh,
					  const struct nlmsghdr *nlh)
{
	struct table *t;
	struct handle h;
	struct nft_table *nlt = netlink_table_alloc(nlh);

	h.family = nft_table_attr_get_u32(nlt, NFT_TABLE_ATTR_FAMILY);
	h.table = nft_table_attr_get_str(nlt, NFT_TABLE_ATTR_NAME);

	t = table_lookup(&h);
	if (t == NULL)
		goto out;

	list_del(&t->list);
	table_free(t);

out:
	nft_table_free(nlt);
}

static void netlink_events_cache_addset(struct netlink_mon_handler *monh,
					const struct nlmsghdr *nlh)
{
	struct set *s;
	LIST_HEAD(msgs);
	struct table *t;
	struct netlink_ctx set_tmpctx;
	struct nft_set *nls = netlink_set_alloc(nlh);

	memset(&set_tmpctx, 0, sizeof(set_tmpctx));
	init_list_head(&set_tmpctx.list);
	init_list_head(&msgs);
	set_tmpctx.msgs = &msgs;

	s = netlink_delinearize_set(&set_tmpctx, nls);
	if (s == NULL)
		return;
	s->init = set_expr_alloc(monh->loc);

	t = table_lookup(&s->handle);
	if (t == NULL) {
		fprintf(stderr, "W: Unable to cache set: table not found.\n");
		goto out;
	}

	set_add_hash(s, t);
out:
	nft_set_free(nls);
}

static void netlink_events_cache_addsetelem(struct netlink_mon_handler *monh,
					    const struct nlmsghdr *nlh)
{
	struct set *set;
	struct nft_set_elem *nlse;
	struct nft_set_elems_iter *nlsei;
	const char *table, *setname;
	struct nft_set *nls = netlink_setelem_alloc(nlh);

	table = nft_set_attr_get_str(nls, NFT_SET_ATTR_TABLE);
	setname = nft_set_attr_get_str(nls, NFT_SET_ATTR_NAME);

	set = set_lookup_global(nft_set_attr_get_u32(nls, NFT_SET_ATTR_FAMILY),
				table, setname);
	if (set == NULL) {
		fprintf(stderr,
			"W: Unable to cache set_elem. Set not found.\n");
		goto out;
	}

	nlsei = nft_set_elems_iter_create(nls);
	if (nlsei == NULL)
		memory_allocation_error();

	nlse = nft_set_elems_iter_next(nlsei);
	while (nlse != NULL) {
		if (netlink_delinearize_setelem(nlse, set) < 0) {
			fprintf(stderr,
				"W: Unable to cache set_elem. "
				"Delinearize failed.\n");
			nft_set_elems_iter_destroy(nlsei);
			goto out;
		}
		nlse = nft_set_elems_iter_next(nlsei);
	}
	nft_set_elems_iter_destroy(nlsei);

out:
	nft_set_free(nls);
}

static void netlink_events_cache_delset_cb(struct set *s,
					   void *data)
{
	list_del(&s->list);
	set_free(s);
}

static void netlink_events_cache_delsets(struct netlink_mon_handler *monh,
					 const struct nlmsghdr *nlh)
{
	struct nft_rule *nlr = netlink_rule_alloc(nlh);

	nlr_for_each_set(nlr, netlink_events_cache_delset_cb, NULL);
	nft_rule_free(nlr);
}

static void netlink_events_cache_update(struct netlink_mon_handler *monh,
					const struct nlmsghdr *nlh, int type)
{
	if (!monh->cache_needed)
		return;

	switch (type) {
	case NFT_MSG_NEWTABLE:
		netlink_events_cache_addtable(monh, nlh);
		break;
	case NFT_MSG_DELTABLE:
		netlink_events_cache_deltable(monh, nlh);
		break;
	case NFT_MSG_NEWSET:
		netlink_events_cache_addset(monh, nlh);
		break;
	case NFT_MSG_NEWSETELEM:
		netlink_events_cache_addsetelem(monh, nlh);
		break;
	case NFT_MSG_DELRULE:
		/* there are no notification for anon-set deletion */
		netlink_events_cache_delsets(monh, nlh);
		break;
	}
}

static int netlink_events_cb(const struct nlmsghdr *nlh, void *data)
{
	int ret = MNL_CB_OK;
	uint16_t type = NFNL_MSG_TYPE(nlh->nlmsg_type);
	struct netlink_mon_handler *monh = (struct netlink_mon_handler *)data;

	netlink_events_cache_update(monh, nlh, type);

	if (!(monh->monitor_flags & (1 << type)))
		return ret;

	switch (type) {
	case NFT_MSG_NEWTABLE:
	case NFT_MSG_DELTABLE:
		ret = netlink_events_table_cb(nlh, type, monh);
		break;
	case NFT_MSG_NEWCHAIN:
	case NFT_MSG_DELCHAIN:
		ret = netlink_events_chain_cb(nlh, type, monh);
		break;
	case NFT_MSG_NEWSET:
	case NFT_MSG_DELSET:		/* nft {add|delete} set */
		ret = netlink_events_set_cb(nlh, type, monh);
		break;
	case NFT_MSG_NEWSETELEM:
	case NFT_MSG_DELSETELEM:	/* nft {add|delete} element */
		ret = netlink_events_setelem_cb(nlh, type, monh);
		break;
	case NFT_MSG_NEWRULE:
	case NFT_MSG_DELRULE:
		ret = netlink_events_rule_cb(nlh, type, monh);
		break;
	}

	return ret;
}

int netlink_monitor(struct netlink_mon_handler *monhandler)
{
	netlink_open_mon_sock();

	if (mnl_socket_bind(nf_mon_sock, (1 << (NFNLGRP_NFTABLES-1)),
			    MNL_SOCKET_AUTOPID) < 0)
		return netlink_io_error(monhandler->ctx, monhandler->loc,
					"Could not bind to netlink socket %s",
					strerror(errno));

	return mnl_nft_event_listener(nf_mon_sock, netlink_events_cb,
				      monhandler);
}

bool netlink_batch_supported(void)
{
	return mnl_batch_supported(nf_sock);
}
