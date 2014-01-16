#ifndef NFTABLES_EXPRESSION_H
#define NFTABLES_EXPRESSION_H

#include <stdbool.h>
#include <gmp.h>
#include <linux/netfilter/nf_tables.h>

#include <nftables.h>
#include <datatype.h>
#include <utils.h>
#include <list.h>

/**
 * enum expr_types
 *
 * @EXPR_INVALID:	uninitialized type, should not happen
 * @EXPR_VERDICT:	nftables verdict expression
 * @EXPR_SYMBOL:	unparsed symbol
 * @EXPR_VALUE:		literal numeric or string expression
 * @EXPR_PREFIX:	prefixed expression
 * @EXPR_RANGE:		literal range
 * @EXPR_PAYLOAD:	payload expression
 * @EXPR_EXTHDR:	exthdr expression
 * @EXPR_META:		meta expression
 * @EXPR_CT:		conntrack expression
 * @EXPR_CONCAT:	concatenation
 * @EXPR_LIST:		list of expressions
 * @EXPR_SET:		literal set
 * @EXPR_SET_REF:	set reference
 * @EXPR_MAPPING:	a single mapping (key : value)
 * @EXPR_MAP:		map operation (expr map { EXPR_MAPPING, ... })
 * @EXPR_UNARY:		byteorder conversion, generated during evaluation
 * @EXPR_BINOP:		binary operations (bitwise, shifts)
 * @EXPR_RELATIONAL:	equality and relational expressions
 */
enum expr_types {
	EXPR_INVALID,
	EXPR_VERDICT,
	EXPR_SYMBOL,
	EXPR_VALUE,
	EXPR_PREFIX,
	EXPR_RANGE,
	EXPR_PAYLOAD,
	EXPR_EXTHDR,
	EXPR_META,
	EXPR_CT,
	EXPR_CONCAT,
	EXPR_LIST,
	EXPR_SET,
	EXPR_SET_REF,
	EXPR_MAPPING,
	EXPR_MAP,
	EXPR_UNARY,
	EXPR_BINOP,
	EXPR_RELATIONAL,
};

enum ops {
	OP_INVALID,
	OP_IMPLICIT,
	/* Unary operations */
	OP_HTON,
	OP_NTOH,
	/* Binary operations */
	OP_LSHIFT,
	OP_RSHIFT,
	OP_AND,
	OP_XOR,
	OP_OR,
	/* Relational operations */
	OP_EQ,
	OP_NEQ,
	OP_LT,
	OP_GT,
	OP_LTE,
	OP_GTE,
	/* Range comparison */
	OP_RANGE,
	/* Flag comparison */
	OP_FLAGCMP,
	/* Set lookup */
	OP_LOOKUP,
};

extern const char *expr_op_symbols[];

enum symbol_types {
	SYMBOL_VALUE,
	SYMBOL_DEFINE,
	SYMBOL_SET,
};

/**
 * struct expr_ctx - type context for symbol parsing during evaluation
 *
 * @dtype:	expected datatype
 * @len:	expected len
 */
struct expr_ctx {
	const struct datatype	*dtype;
	unsigned int		len;
};

static inline void expr_set_context(struct expr_ctx *ctx,
				    const struct datatype *dtype,
				    unsigned int len)
{
	ctx->dtype = dtype;
	ctx->len   = len;
}

/**
 * struct expr_ops
 *
 * @type:	expression type
 * @name:	expression name for diagnostics
 * @clone:	function to clone type specific data
 * @destroy:	destructor, must release inner expressions
 * @set_type:	function to promote type and byteorder of inner types
 * @print:	function to print the expression
 */
struct expr_ops {
	enum expr_types		type;
	const char		*name;
	void			(*clone)(struct expr *new, const struct expr *expr);
	void			(*destroy)(struct expr *expr);
	void			(*set_type)(const struct expr *expr,
					    const struct datatype *dtype,
					    enum byteorder byteorder);
	void			(*print)(const struct expr *expr);
};

/**
 * enum expr_flags
 *
 * @EXPR_F_CONSTANT:		constant expression
 * @EXPR_F_SINGLETON:		singleton (implies primary and constant)
 * @EXPR_F_INTERVAL_END:	set member ends an open interval
 */
enum expr_flags {
	EXPR_F_CONSTANT		= 0x1,
	EXPR_F_SINGLETON	= 0x2,
	EXPR_F_INTERVAL_END	= 0x4,
};

#include <payload.h>
#include <exthdr.h>
#include <meta.h>
#include <ct.h>

/**
 * struct expr
 *
 * @list:	list node
 * @location:	location from parser
 * @refcnt:	reference count
 * @flags:	mask of enum expr_flags
 * @dtype:	data type of expression
 * @byteorder:	byteorder of expression
 * @len:	length of expression
 * @ops:	expression ops
 * @op:		operation for unary, binary and relational expressions
 * @union:	type specific data
 */
struct expr {
	struct list_head	list;
	struct location		location;

	unsigned int		refcnt;
	unsigned int		flags;

	const struct datatype	*dtype;
	enum byteorder		byteorder;
	unsigned int		len;

	const struct expr_ops	*ops;
	enum ops		op;
	union {
		struct {
			/* EXPR_SYMBOL */
			const struct scope	*scope;
			const char		*identifier;
			enum symbol_types	symtype;
		};
		struct {
			/* EXPR_VERDICT */
			int			verdict;
			const char		*chain;
		};
		struct {
			/* EXPR_VALUE */
			mpz_t			value;
		};
		struct {
			/* EXPR_PREFIX */
			struct expr		*prefix;
			unsigned int		prefix_len;
		};
		struct {
			/* EXPR_CONCAT, EXPR_LIST, EXPR_SET */
			struct list_head	expressions;
			unsigned int		size;
			uint32_t		set_flags;
		};
		struct {
			/* EXPR_SET_REF */
			struct set		*set;
		};
		struct {
			/* EXPR_UNARY */
			struct expr		*arg;
		};
		struct {
			/* EXPR_RANGE, EXPR_BINOP, EXPR_MAPPING, EXPR_RELATIONAL */
			struct expr		*left;
			struct expr		*right;
		};
		struct {
			/* EXPR_MAP */
			struct expr		*map;
			struct expr		*mappings;
		};

		struct {
			/* EXPR_PAYLOAD */
			const struct payload_desc	*desc;
			const struct payload_template	*tmpl;
			enum payload_bases		base;
			unsigned int			offset;
			unsigned int			flags;
		} payload;
		struct {
			/* EXPR_EXTHDR */
			const struct exthdr_desc	*desc;
			const struct payload_template	*tmpl;
		} exthdr;
		struct {
			/* EXPR_META */
			enum nft_meta_keys	key;
		} meta;
		struct {
			/* EXPR_CT */
			enum nft_ct_keys	key;
		} ct;
	};
};

extern struct expr *expr_alloc(const struct location *loc,
			       const struct expr_ops *ops,
			       const struct datatype *dtype,
			       enum byteorder byteorder, unsigned int len);
extern struct expr *expr_clone(const struct expr *expr);
extern struct expr *expr_get(struct expr *expr);
extern void expr_free(struct expr *expr);
extern void expr_print(const struct expr *expr);
extern void expr_describe(const struct expr *expr);

extern const struct datatype *expr_basetype(const struct expr *expr);
extern void expr_set_type(struct expr *expr, const struct datatype *dtype,
			  enum byteorder byteorder);

struct eval_ctx;
extern int expr_binary_error(struct eval_ctx *ctx,
			     const struct expr *e1, const struct expr *e2,
			     const char *fmt, ...) __gmp_fmtstring(4, 5);

#define expr_error(ctx, expr, fmt, args...) \
	expr_binary_error(ctx, expr, NULL, fmt, ## args)

static inline bool expr_is_constant(const struct expr *expr)
{
	return expr->flags & EXPR_F_CONSTANT ? true : false;
}

static inline bool expr_is_singleton(const struct expr *expr)
{
	return expr->flags & EXPR_F_SINGLETON ? true : false;
}

extern struct expr *unary_expr_alloc(const struct location *loc,
				     enum ops op, struct expr *arg);

extern struct expr *binop_expr_alloc(const struct location *loc, enum ops op,
				     struct expr *left, struct expr *right);

extern struct expr *relational_expr_alloc(const struct location *loc, enum ops op,
					  struct expr *left, struct expr *right);

extern struct expr *verdict_expr_alloc(const struct location *loc,
				       int verdict, const char *chain);

extern struct expr *symbol_expr_alloc(const struct location *loc,
				      enum symbol_types type, struct scope *scope,
				      const char *identifier);

static inline void symbol_expr_set_type(struct expr *expr,
					const struct datatype *dtype)
{
	if (expr->ops->type == EXPR_SYMBOL)
		expr->dtype = dtype;
}

extern struct expr *constant_expr_alloc(const struct location *loc,
					const struct datatype *dtype,
					enum byteorder byteorder,
					unsigned int len, const void *data);
extern struct expr *constant_expr_join(const struct expr *e1,
				       const struct expr *e2);
extern struct expr *constant_expr_splice(struct expr *expr, unsigned int len);

extern struct expr *prefix_expr_alloc(const struct location *loc,
				      struct expr *expr,
				      unsigned int prefix_len);

extern struct expr *range_expr_alloc(const struct location *loc,
				     struct expr *low, struct expr *high);

extern void compound_expr_add(struct expr *compound, struct expr *expr);
extern void compound_expr_remove(struct expr *compound, struct expr *expr);

extern struct expr *concat_expr_alloc(const struct location *loc);

extern struct expr *list_expr_alloc(const struct location *loc);

extern struct expr *set_expr_alloc(const struct location *loc);
extern void set_to_intervals(struct set *set);

extern struct expr *mapping_expr_alloc(const struct location *loc,
				       struct expr *from, struct expr *to);
extern struct expr *map_expr_alloc(const struct location *loc,
				   struct expr *arg, struct expr *list);

extern struct expr *set_ref_expr_alloc(const struct location *loc,
				       struct set *set);

#endif /* NFTABLES_EXPRESSION_H */
