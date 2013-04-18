#ifndef NFTABLES_NETLINK_H
#define NFTABLES_NETLINK_H

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
 * @set:	current set
 */
struct netlink_ctx {
	struct list_head	*msgs;
	struct list_head	list;
	struct set		*set;
};

extern void netlink_dump_object(struct nl_object *obj);

extern struct nfnl_nft_table *alloc_nft_table(const struct handle *h);
extern struct nfnl_nft_chain *alloc_nft_chain(const struct handle *h);
extern struct nfnl_nft_rule *alloc_nft_rule(const struct handle *h);
extern struct nfnl_nft_expr *alloc_nft_expr(int (*init)(struct nfnl_nft_expr *));
extern struct nfnl_nft_set *alloc_nft_set(const struct handle *h);
extern struct nfnl_nft_data *alloc_nft_data(const void *data, unsigned int len);

extern struct nfnl_nft_data *netlink_gen_data(const struct expr *expr);
extern struct nfnl_nft_data *netlink_gen_raw_data(const mpz_t value,
						  enum byteorder byteorder,
						  unsigned int len);

extern struct expr *netlink_alloc_value(const struct location *loc,
				        const struct nfnl_nft_data *nld);
extern struct expr *netlink_alloc_data(const struct location *loc,
				       const struct nfnl_nft_data *nld,
				       enum nft_registers dreg);

extern int netlink_linearize_rule(struct netlink_ctx *ctx,
				  struct nfnl_nft_rule *nlr,
				  const struct rule *rule);
extern struct rule *netlink_delinearize_rule(struct netlink_ctx *ctx,
					     const struct nl_object *obj);

extern int netlink_add_rule(struct netlink_ctx *ctx, const struct handle *h,
			    const struct rule *rule, uint32_t flags);
extern int netlink_delete_rule(struct netlink_ctx *ctx, const struct handle *h,
			       const struct location *loc);
extern int netlink_get_rule(struct netlink_ctx *ctx, const struct handle *h,
			    const struct location *loc);

extern int netlink_add_chain(struct netlink_ctx *ctx, const struct handle *h,
			     const struct location *loc,
			     const struct chain *chain);
extern int netlink_rename_chain(struct netlink_ctx *ctx, const struct handle *h,
				const struct location *loc, const char *name);
extern int netlink_delete_chain(struct netlink_ctx *ctx, const struct handle *h,
				const struct location *loc);
extern int netlink_list_chains(struct netlink_ctx *ctx, const struct handle *h,
			       const struct location *loc);
extern int netlink_get_chain(struct netlink_ctx *ctx, const struct handle *h,
			     const struct location *loc);
extern int netlink_list_chain(struct netlink_ctx *ctx, const struct handle *h,
			      const struct location *loc);
extern int netlink_flush_chain(struct netlink_ctx *ctx, const struct handle *h,
			       const struct location *loc);

extern int netlink_add_table(struct netlink_ctx *ctx, const struct handle *h,
			     const struct location *loc,
			     const struct table *table);
extern int netlink_delete_table(struct netlink_ctx *ctx, const struct handle *h,
				const struct location *loc);
extern int netlink_list_tables(struct netlink_ctx *ctx, const struct handle *h,
			       const struct location *loc);
extern int netlink_get_table(struct netlink_ctx *ctx, const struct handle *h,
			     const struct location *loc);
extern int netlink_list_table(struct netlink_ctx *ctx, const struct handle *h,
			      const struct location *loc);
extern int netlink_flush_table(struct netlink_ctx *ctx, const struct handle *h,
			       const struct location *loc);

extern int netlink_add_set(struct netlink_ctx *ctx, const struct handle *h,
			   struct set *set);
extern int netlink_delete_set(struct netlink_ctx *ctx, const struct handle *h,
			      const struct location *loc);
extern int netlink_list_sets(struct netlink_ctx *ctx, const struct handle *h,
			     const struct location *loc);
extern int netlink_get_set(struct netlink_ctx *ctx, const struct handle *h,
			   const struct location *loc);

extern int netlink_add_setelems(struct netlink_ctx *ctx, const struct handle *h,
				const struct expr *expr);
extern int netlink_delete_setelems(struct netlink_ctx *ctx, const struct handle *h,
				   const struct expr *expr);
extern int netlink_get_setelems(struct netlink_ctx *ctx, const struct handle *h,
				const struct location *loc, struct set *set);

#endif /* NFTABLES_NETLINK_H */
