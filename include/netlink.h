#ifndef _NETLINK_H
#define _NETLINK_H

#include <netlink/netfilter/netfilter.h>
#include <netlink/netfilter/nft_table.h>
#include <netlink/netfilter/nft_chain.h>
#include <netlink/netfilter/nft_rule.h>
#include <netlink/netfilter/nft_expr.h>
#include <netlink/netfilter/nft_data.h>
#include <netlink/object.h>

#include <rule.h>

/** 
 * struct netlink_ctx
 *
 * @msgs:	message queue
 * @list:	list of parsed rules/chains/tables
 */
struct netlink_ctx {
	struct list_head	*msgs;
	struct list_head	list;
};

extern void netlink_dump_object(struct nl_object *obj);

extern struct nfnl_nft_table *alloc_nft_table(const struct handle *h);
extern struct nfnl_nft_chain *alloc_nft_chain(const struct handle *h);
extern struct nfnl_nft_rule *alloc_nft_rule(const struct handle *h);
extern struct nfnl_nft_expr *alloc_nft_expr(int (*init)(struct nfnl_nft_expr *));
extern struct nfnl_nft_data *alloc_nft_data(const void *data, unsigned int len);

extern int netlink_linearize_rule(struct netlink_ctx *ctx,
				  struct nfnl_nft_rule *nlr,
				  const struct rule *rule);
extern struct rule *netlink_delinearize_rule(struct netlink_ctx *ctx,
					     const struct nl_object *obj);

extern int netlink_add_rule(struct netlink_ctx *ctx, const struct handle *h,
			    const struct rule *rule);
extern int netlink_delete_rule(struct netlink_ctx *ctx, const struct handle *h);
extern int netlink_get_rule(struct netlink_ctx *ctx, const struct handle *h);

extern int netlink_add_chain(struct netlink_ctx *ctx, const struct handle *h,
			     const struct chain *chain);
extern int netlink_delete_chain(struct netlink_ctx *ctx, const struct handle *h);
extern int netlink_list_chains(struct netlink_ctx *ctx, const struct handle *h);
extern int netlink_get_chain(struct netlink_ctx *ctx, const struct handle *h);
extern int netlink_list_chain(struct netlink_ctx *ctx, const struct handle *h);
extern int netlink_flush_chain(struct netlink_ctx *ctx, const struct handle *h);

extern int netlink_add_table(struct netlink_ctx *ctx, const struct handle *h,
			     const struct table *table);
extern int netlink_delete_table(struct netlink_ctx *ctx, const struct handle *h);
extern int netlink_list_tables(struct netlink_ctx *ctx, const struct handle *h);
extern int netlink_get_table(struct netlink_ctx *ctx, const struct handle *h);
extern int netlink_list_table(struct netlink_ctx *ctx, const struct handle *h);
extern int netlink_flush_table(struct netlink_ctx *ctx, const struct handle *h);

#endif /* _NETLINK_H */
