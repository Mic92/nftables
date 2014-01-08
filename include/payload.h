#ifndef NFTABLES_PAYLOAD_H
#define NFTABLES_PAYLOAD_H

#include <nftables.h>
#include <proto.h>

extern struct expr *payload_expr_alloc(const struct location *loc,
				       const struct proto_desc *desc,
				       unsigned int type);
extern void payload_init_raw(struct expr *expr, enum proto_bases base,
			     unsigned int offset, unsigned int len);

struct eval_ctx;
extern int payload_gen_dependency(struct eval_ctx *ctx, const struct expr *expr,
				  struct expr **res);

extern bool payload_is_adjacent(const struct expr *e1, const struct expr *e2);
extern struct expr *payload_expr_join(const struct expr *e1,
				      const struct expr *e2);

extern void payload_expr_expand(struct list_head *list, struct expr *expr,
				const struct proto_ctx *ctx);
extern void payload_expr_complete(struct expr *expr,
				  const struct proto_ctx *ctx);

#endif /* NFTABLES_PAYLOAD_H */
