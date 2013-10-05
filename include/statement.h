#ifndef NFTABLES_STATEMENT_H
#define NFTABLES_STATEMENT_H

#include <list.h>
#include <expression.h>

extern struct stmt *expr_stmt_alloc(const struct location *loc,
				    struct expr *expr);

extern struct stmt *verdict_stmt_alloc(const struct location *loc,
				       struct expr *expr);

struct counter_stmt {
	uint64_t		packets;
	uint64_t		bytes;
};

extern struct stmt *counter_stmt_alloc(const struct location *loc);

#include <meta.h>
struct meta_stmt {
	enum nft_meta_keys		key;
	const struct meta_template	*tmpl;
	struct expr			*expr;
};

extern struct stmt *meta_stmt_alloc(const struct location *loc,
				    enum nft_meta_keys key,
				    struct expr *expr);

struct log_stmt {
	const char		*prefix;
	unsigned int		snaplen;
	uint16_t		group;
	uint16_t		qthreshold;
};

extern struct stmt *log_stmt_alloc(const struct location *loc);


struct limit_stmt {
	uint64_t		rate;
	uint64_t		unit;
};

extern struct stmt *limit_stmt_alloc(const struct location *loc);

struct reject_stmt {
	enum nft_reject_types	type;
};

extern struct stmt *reject_stmt_alloc(const struct location *loc);

struct nat_stmt {
	enum nft_nat_types	type;
	struct expr		*addr;
	struct expr		*proto;
};

extern struct stmt *nat_stmt_alloc(const struct location *loc);

/**
 * enum stmt_types - statement types
 *
 * @STMT_INVALID:	uninitialised
 * @STMT_EXPRESSION:	expression statement (relational)
 * @STMT_VERDICT:	verdict statement
 * @STMT_COUNTER:	counters
 * @STMT_META:		meta statement
 * @STMT_LIMIT:		limit statement
 * @STMT_LOG:		log statement
 * @STMT_REJECT:	REJECT statement
 * @STMT_NAT:		NAT statement
 */
enum stmt_types {
	STMT_INVALID,
	STMT_EXPRESSION,
	STMT_VERDICT,
	STMT_COUNTER,
	STMT_META,
	STMT_LIMIT,
	STMT_LOG,
	STMT_REJECT,
	STMT_NAT,
};

/**
 * struct stmt_ops
 *
 * @type:	statement type
 * @name:	name
 * @destroy:	destructor
 * @print:	function to print statement
 */
struct stmt;
struct stmt_ops {
	enum stmt_types		type;
	const char		*name;
	void			(*destroy)(struct stmt *stmt);
	void			(*print)(const struct stmt *stmt);
};

enum stmt_flags {
	STMT_F_TERMINAL		= 0x1,
};

/**
 * struct stmt
 *
 * @list:	rule list node
 * @ops:	statement ops
 * @location:	location where the statement was defined
 * @flags:	statement flags
 * @union:	type specific data
 */
struct stmt {
	struct list_head		list;
	const struct stmt_ops		*ops;
	struct location			location;
	enum stmt_flags			flags;

	union {
		struct expr		*expr;
		struct counter_stmt	counter;
		struct meta_stmt	meta;
		struct log_stmt		log;
		struct limit_stmt	limit;
		struct reject_stmt	reject;
		struct nat_stmt		nat;
	};
};

extern struct stmt *stmt_alloc(const struct location *loc,
			       const struct stmt_ops *ops);
extern void stmt_free(struct stmt *stmt);
extern void stmt_list_free(struct list_head *list);
extern void stmt_print(const struct stmt *stmt);

#endif /* NFTABLES_STATEMENT_H */
