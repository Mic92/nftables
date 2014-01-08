#ifndef NFTABLES_CT_H
#define NFTABLES_CT_H

/**
 * struct ct_template
 *
 * @token:	parser token for the expression
 * @dtype:	data type of the expression
 * @len:	length of the expression
 * @byteorder:	byteorder
 */
struct ct_template {
	const char		*token;
	const struct datatype	*dtype;
	enum byteorder		byteorder;
	unsigned int		len;
};

#define CT_TEMPLATE(__token, __dtype, __byteorder, __len) {	\
	.token		= (__token),				\
	.dtype		= (__dtype),				\
	.byteorder	= (__byteorder),			\
	.len		= (__len),				\
}

extern struct expr *ct_expr_alloc(const struct location *loc,
				  enum nft_ct_keys key);
extern void ct_expr_update_type(struct proto_ctx *ctx, struct expr *expr);

#endif /* NFTABLES_CT_H */
