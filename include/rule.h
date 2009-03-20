#ifndef NFTABLES_RULE_H
#define NFTABLES_RULE_H

#include <stdint.h>
#include <nftables.h>
#include <list.h>

/**
 * struct handle - handle for tables, chains and rules
 *
 * @family:	protocol family
 * @table:	table name
 * @chain:	chain name (chains and rules only)
 * @handle:	rule handle (rules only)
 */
struct handle {
	int			family;
	const char		*table;
	const char		*chain;
	uint32_t		handle;
};

extern void handle_merge(struct handle *dst, const struct handle *src);
extern void handle_free(struct handle *h);

/**
 * struct scope
 *
 * @parent:	pointer to parent scope
 * @symbols:	symbols bound in the scope
 */
struct scope {
	const struct scope	*parent;
	struct list_head	symbols;
};

extern struct scope *scope_init(struct scope *scope, const struct scope *parent);
extern void scope_release(const struct scope *scope);

/**
 * struct symbol
 *
 * @list:	scope symbol list node
 * @identifier:	identifier
 * @expr:	initializer
 */
struct symbol {
	struct list_head	list;
	const char		*identifier;
	struct expr		*expr;
};

extern void symbol_bind(struct scope *scope, const char *identifier,
			struct expr *expr);
extern struct symbol *symbol_lookup(const struct scope *scope,
				    const char *identifier);

/**
 * struct table - nftables table
 *
 * @list:	list node
 * @handle:	table handle
 * @chains:	chains contained in the table
 */
struct table {
	struct list_head	list;
	struct handle		handle;
	struct scope		scope;
	struct list_head	chains;
};

extern struct table *table_alloc(void);
extern void table_free(struct table *table);
extern void table_add_hash(struct table *table);
extern struct table *table_lookup(const struct handle *h);

/**
 * struct chain - nftables chain
 *
 * @list:	list node in table list
 * @handle:	chain handle
 * @hooknum:	hook number (base chains)
 * @priority:	hook priority (base chains)
 * @rules:	rules contained in the chain
 */
struct chain {
	struct list_head	list;
	struct handle		handle;
	unsigned int		hooknum;
	unsigned int		priority;
	struct scope		scope;
	struct list_head	rules;
};

extern struct chain *chain_alloc(const char *name);
extern void chain_free(struct chain *chain);
extern void chain_add_hash(struct chain *chain, struct table *table);
extern struct chain *chain_lookup(const struct table *table,
				  const struct handle *h);

/**
 * struct rule - nftables rule
 *
 * @list:	list node in chain list
 * @handle:	rule handle
 * @location:	location the rule was defined at
 * @stmt:	list of statements
 * @num_stmts:	number of statements in stmts list
 */
struct rule {
	struct list_head	list;
	struct handle		handle;
	struct location		location;
	struct list_head	stmts;
	unsigned int		num_stmts;
};

extern struct rule *rule_alloc(const struct location *loc,
			       const struct handle *h);
extern void rule_free(struct rule *rule);
extern void rule_print(const struct rule *rule);

/**
 * enum cmd_ops - command operations
 *
 * @CMD_INVALID:	invalid
 * @CMD_ADD:		add object
 * @CMD_DELETE:		delete object
 * @CMD_LIST:		list container
 * @CMD_FLUSH:		flush container
 */
enum cmd_ops {
	CMD_INVALID,
	CMD_ADD,
	CMD_DELETE,
	CMD_LIST,
	CMD_FLUSH,
};

/**
 * enum cmd_obj - command objects
 *
 * @CMD_OBJ_INVALID:	invalid
 * @CMD_OBJ_RULE:	rule
 * @CMD_OBJ_CHAIN:	chain
 * @CMD_OBJ_TABLE:	table
 */
enum cmd_obj {
	CMD_OBJ_INVALID,
	CMD_OBJ_RULE,
	CMD_OBJ_CHAIN,
	CMD_OBJ_TABLE,
};

/**
 * struct cmd - command statement
 *
 * @list:	list node
 * @location:	location of the statement
 * @op:		operation
 * @obj:	object type to perform operation on
 * @handle:	handle for operations working without full objects
 * @union:	object
 */
struct cmd {
	struct list_head	list;
	struct location		location;
	enum cmd_ops		op;
	enum cmd_obj		obj;
	struct handle		handle;
	union {
		void		*data;
		struct rule	*rule;
		struct chain	*chain;
		struct table	*table;
	};
};

extern struct cmd *cmd_alloc(enum cmd_ops op, enum cmd_obj obj,
			     const struct handle *h, void *data);
extern void cmd_free(struct cmd *cmd);

#include <payload.h>
#include <expression.h>

/**
 * struct eval_ctx - evaluation context
 *
 * @msgs:	message queue
 * @stmt:	current statement
 * @ectx:	expression context
 * @pctx:	payload context
 */
struct eval_ctx {
	struct list_head	*msgs;
	struct stmt		*stmt;
	struct expr_ctx		ectx;
	struct payload_ctx	pctx;
};

extern int evaluate(struct eval_ctx *ctx, struct list_head *commands);

extern struct error_record *rule_postprocess(struct rule *rule);

struct netlink_ctx;
extern int do_command(struct netlink_ctx *ctx, struct cmd *cmd);

#endif /* NFTABLES_RULE_H */
