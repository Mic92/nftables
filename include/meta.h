#ifndef NFTABLES_META_H
#define NFTABLES_META_H

/**
 * struct meta_template - template for meta expressions and statements
 *
 * @token:	parser token for the expression
 * @dtype:	data type of the expression
 * @len:	length of the expression
 * @byteorder:	byteorder
 */
struct meta_template {
	const char		*token;
	const struct datatype	*dtype;
	enum byteorder		byteorder;
	unsigned int		len;
};

#define META_TEMPLATE(__token, __dtype, __len, __byteorder) {	\
	.token		= (__token),				\
	.dtype		= (__dtype),				\
	.len		= (__len),				\
	.byteorder	= (__byteorder),			\
}

extern struct expr *meta_expr_alloc(const struct location *loc,
				    enum nft_meta_keys key);

#endif /* NFTABLES_META_H */
