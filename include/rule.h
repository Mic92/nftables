#ifndef NFTABLES_RULE_H
#define NFTABLES_RULE_H

#include <stdint.h>
#include <nftables.h>
#include <list.h>

/**
 * struct handle - handle for tables, chains, rules and sets
 *
 * @family:	protocol family
 * @table:	table name
 * @chain:	chain name (chains and rules only)
 * @set:	set name (sets only)
 * @handle:	rule handle (rules only)
 * @position:	rule position (rules only)
 */
struct handle {
	uint32_t		family;
	const char		*table;
	const char		*chain;
	const char		*set;
	uint64_t		handle;
	uint64_t		position;
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
 * @location:	location the table was defined at
 * @chains:	chains contained in the table
 * @sets:	sets contained in the table
 */
struct table {
	struct list_head	list;
	struct handle		handle;
	struct location		location;
	struct scope		scope;
	struct list_head	chains;
	struct list_head	sets;
};

extern struct table *table_alloc(void);
extern void table_free(struct table *table);
extern void table_add_hash(struct table *table);
extern struct table *table_lookup(const struct handle *h);

/**
 * enum chain_flags - chain flags
 *
 * @CHAIN_F_BASECHAIN:	chain is a base chain
 */
enum chain_flags {
	CHAIN_F_BASECHAIN	= 0x1,
};

/**
 * struct chain - nftables chain
 *
 * @list:	list node in table list
 * @handle:	chain handle
 * @location:	location the chain was defined at
 * @flags:	chain flags
 * @hookstr:	unified and human readable hook name (base chains)
 * @hooknum:	hook number (base chains)
 * @priority:	hook priority (base chains)
 * @type:	chain type
 * @rules:	rules contained in the chain
 */
struct chain {
	struct list_head	list;
	struct handle		handle;
	struct location		location;
	uint32_t		flags;
	const char		*hookstr;
	unsigned int		hooknum;
	unsigned int		priority;
	const char		*type;
	struct scope		scope;
	struct list_head	rules;
};

extern const char *chain_type_name_lookup(const char *name);
extern const char *chain_hookname_lookup(const char *name);
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
 * enum set_flags
 *
 * @SET_F_CONSTANT:		Set content is constant
 * @SET_F_INTERVAL:		set includes ranges and/or prefix expressions
 */
enum set_flags {
	SET_F_ANONYMOUS		= 0x1,
	SET_F_CONSTANT		= 0x2,
	SET_F_INTERVAL		= 0x4,
	SET_F_MAP		= 0x8,
};

/**
 * struct set - nftables set
 *
 * @list:	table set list node
 * @handle:	set handle
 * @location:	location the set was defined/declared at
 * @refcnt:	reference count
 * @flags:	bitmask of set flags
 * @keytype:	key data type
 * @keylen:	key length
 * @datatype:	mapping data type
 * @datalen:	mapping data len
 * @init:	initializer
 */
struct set {
	struct list_head	list;
	struct handle		handle;
	struct location		location;
	unsigned int		refcnt;
	uint32_t		flags;
	const struct datatype	*keytype;
	unsigned int		keylen;
	const struct datatype	*datatype;
	unsigned int		datalen;
	struct expr		*init;
};

extern struct set *set_alloc(const struct location *loc);
extern struct set *set_get(struct set *set);
extern void set_free(struct set *set);
extern void set_add_hash(struct set *set, struct table *table);
extern struct set *set_lookup(const struct table *table, const char *name);
extern void set_print(const struct set *set);

/**
 * enum cmd_ops - command operations
 *
 * @CMD_INVALID:	invalid
 * @CMD_ADD:		add object
 * @CMD_INSERT:		insert object
 * @CMD_DELETE:		delete object
 * @CMD_LIST:		list container
 * @CMD_FLUSH:		flush container
 * @CMD_RENAME:		rename object
 */
enum cmd_ops {
	CMD_INVALID,
	CMD_ADD,
	CMD_INSERT,
	CMD_DELETE,
	CMD_LIST,
	CMD_FLUSH,
	CMD_RENAME,
};

/**
 * enum cmd_obj - command objects
 *
 * @CMD_OBJ_INVALID:	invalid
 * @CMD_OBJ_SETELEM:	set element(s)
 * @CMD_OBJ_SET:	set
 * @CMD_OBJ_SETS:	multiple sets
 * @CMD_OBJ_RULE:	rule
 * @CMD_OBJ_CHAIN:	chain
 * @CMD_OBJ_TABLE:	table
 */
enum cmd_obj {
	CMD_OBJ_INVALID,
	CMD_OBJ_SETELEM,
	CMD_OBJ_SET,
	CMD_OBJ_SETS,
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
 * @seqnum:	sequence number to match netlink errors
 * @union:	object
 * @arg:	argument data
 */
struct cmd {
	struct list_head	list;
	struct location		location;
	enum cmd_ops		op;
	enum cmd_obj		obj;
	struct handle		handle;
	uint32_t		seqnum;
	union {
		void		*data;
		struct expr	*expr;
		struct set	*set;
		struct rule	*rule;
		struct chain	*chain;
		struct table	*table;
	};
	const void		*arg;
};

extern struct cmd *cmd_alloc(enum cmd_ops op, enum cmd_obj obj,
			     const struct handle *h, const struct location *loc,
			     void *data);
extern void cmd_free(struct cmd *cmd);

#include <payload.h>
#include <expression.h>

/**
 * struct eval_ctx - evaluation context
 *
 * @msgs:	message queue
 * @cmd:	current command
 * @table:	current table
 * @set:	current set
 * @stmt:	current statement
 * @ectx:	expression context
 * @pctx:	payload context
 */
struct eval_ctx {
	struct list_head	*msgs;
	struct cmd		*cmd;
	struct table		*table;
	struct set		*set;
	struct stmt		*stmt;
	struct expr_ctx		ectx;
	struct payload_ctx	pctx;
};

extern int evaluate(struct eval_ctx *ctx, struct list_head *commands);

extern struct error_record *rule_postprocess(struct rule *rule);

struct netlink_ctx;
extern int do_command(struct netlink_ctx *ctx, struct cmd *cmd);

#endif /* NFTABLES_RULE_H */
