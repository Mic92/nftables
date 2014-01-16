#ifndef NFTABLES_DATATYPE_H
#define NFTABLES_DATATYPE_H

/**
 * enum datatypes
 *
 * @TYPE_INVALID:	uninitialized
 * @TYPE_VERDICT:	nftables verdict
 * @TYPE_BITMASK:	bitmask
 * @TYPE_INTEGER:	integer
 * @TYPE_STRING:	string
 * @TYPE_LLADDR:	link layer address (integer subtype)
 * @TYPE_IPADDR:	IPv4 address (integer subtype)
 * @TYPE_IP6ADDR:	IPv6 address (integer subtype)
 * @TYPE_ETHERADDR:	Ethernet address (lladdr subtype)
 * @TYPE_ETHERTYPE:	EtherType (integer subtype)
 * @TYPE_ARPOP:		ARP operation (integer subtype)
 * @TYPE_INET_PROTOCOL:	internet protocol (integer subtype)
 * @TYPE_INET_SERVICE:	internet service (integer subtype)
 * @TYPE_ICMP_TYPE:	ICMP type codes (integer subtype)
 * @TYPE_TCP_FLAG:	TCP flag (bitmask subtype)
 * @TCPE_DCCP_PKTTYPE:	DCCP packet type (integer subtype)
 * @TYPE_MH_TYPE:	Mobility Header type (integer subtype)
 * @TYPE_TIME:		relative time
 * @TYPE_MARK:		packet mark (integer subtype)
 * @TYPE_IFINDEX:	interface index (integer subtype)
 * @TYPE_ARPHRD:	interface type (integer subtype)
 * @TYPE_REALM:		routing realm (integer subtype)
 * @TYPE_TC_HANDLE:	TC handle (integer subtype)
 * @TYPE_UID:		user ID (integer subtype)
 * @TYPE_GID:		group ID (integer subtype)
 * @TYPE_CT_STATE:	conntrack state (bitmask subtype)
 * @TYPE_CT_DIR:	conntrack direction
 * @TYPE_CT_STATUS:	conntrack status (bitmask subtype)
 * @TYPE_ICMP6_TYPE:	ICMPv6 type codes (integer subtype)
 */
enum datatypes {
	TYPE_INVALID,
	TYPE_VERDICT,
	TYPE_BITMASK,
	TYPE_INTEGER,
	TYPE_STRING,
	TYPE_LLADDR,
	TYPE_IPADDR,
	TYPE_IP6ADDR,
	TYPE_ETHERADDR,
	TYPE_ETHERTYPE,
	TYPE_ARPOP,
	TYPE_INET_PROTOCOL,
	TYPE_INET_SERVICE,
	TYPE_ICMP_TYPE,
	TYPE_TCP_FLAG,
	TYPE_DCCP_PKTTYPE,
	TYPE_MH_TYPE,
	TYPE_TIME,
	TYPE_MARK,
	TYPE_IFINDEX,
	TYPE_ARPHRD,
	TYPE_REALM,
	TYPE_TC_HANDLE,
	TYPE_UID,
	TYPE_GID,
	TYPE_CT_STATE,
	TYPE_CT_DIR,
	TYPE_CT_STATUS,
	TYPE_ICMP6_TYPE,
	__TYPE_MAX
};
#define TYPE_MAX		(__TYPE_MAX - 1)

/**
 * enum byteorder
 *
 * @BYTEORDER_INVALID:		uninitialized/unknown
 * @BYTEORDER_HOST_ENDIAN:	host endian
 * @BYTEORDER_BIG_ENDIAN:	big endian
 */
enum byteorder {
	BYTEORDER_INVALID,
	BYTEORDER_HOST_ENDIAN,
	BYTEORDER_BIG_ENDIAN,
};

struct expr;

/**
 * enum datatype_flags
 *
 * @DTYPE_F_ALLOC:		datatype is dynamically allocated
 * @DTYPE_F_PREFIX:		preferred representation for ranges is a prefix
 */
enum datatype_flags {
	DTYPE_F_ALLOC		= (1 << 0),
	DTYPE_F_PREFIX		= (1 << 1),
};

/**
 * struct datatype
 *
 * @type:	numeric identifier
 * @byteorder:	byteorder of type (non-basetypes only)
 * @flags:	flags
 * @size:	type size (fixed sized non-basetypes only)
 * @name:	type name
 * @desc:	type description
 * @basetype:	basetype for subtypes, determines type compatibilty
 * @basefmt:	format string for basetype
 * @print:	function to print a constant of this type
 * @parse:	function to parse a symbol and return an expression
 * @sym_tbl:	symbol table for this type
 */
struct datatype {
	uint32_t			type;
	enum byteorder			byteorder;
	unsigned int			flags;
	unsigned int			size;
	const char			*name;
	const char			*desc;
	const struct datatype		*basetype;
	const char			*basefmt;
	void				(*print)(const struct expr *expr);
	struct error_record		*(*parse)(const struct expr *sym,
						  struct expr **res);
	const struct symbol_table	*sym_tbl;
};

extern void datatype_register(const struct datatype *dtype);
extern const struct datatype *datatype_lookup(enum datatypes type);
extern const struct datatype *datatype_lookup_byname(const char *name);

extern struct error_record *symbol_parse(const struct expr *sym,
					 struct expr **res);
extern void datatype_print(const struct expr *expr);

static inline bool datatype_equal(const struct datatype *d1,
				  const struct datatype *d2)
{
	return d1->type == d2->type;
}

/**
 * struct symbolic_constant - symbol <-> constant mapping
 *
 * @identifier:	symbol
 * @value:	symbolic value
 */
struct symbolic_constant {
	const char			*identifier;
	uint64_t			value;
};

#define SYMBOL(id, v)	{ .identifier = (id), .value = (v) }
#define SYMBOL_LIST_END	(struct symbolic_constant) { }

/**
 * struct symbol_table - type construction from symbolic values
 *
 * @symbols:	the symbols
 */
struct symbol_table {
	int				gcc_workaround;
	struct symbolic_constant	symbols[];
};

extern struct error_record *symbolic_constant_parse(const struct expr *sym,
						    const struct symbol_table *tbl,
						    struct expr **res);
extern void symbolic_constant_print(const struct symbol_table *tbl,
				    const struct expr *expr);
extern void symbol_table_print(const struct symbol_table *tbl,
			       const struct datatype *dtype);

extern struct symbol_table *rt_symbol_table_init(const char *filename);
extern void rt_symbol_table_free(struct symbol_table *tbl);

extern const struct datatype invalid_type;
extern const struct datatype verdict_type;
extern const struct datatype bitmask_type;
extern const struct datatype integer_type;
extern const struct datatype string_type;
extern const struct datatype lladdr_type;
extern const struct datatype ipaddr_type;
extern const struct datatype ip6addr_type;
extern const struct datatype etheraddr_type;
extern const struct datatype ethertype_type;
extern const struct datatype arphrd_type;
extern const struct datatype inet_protocol_type;
extern const struct datatype inet_service_type;
extern const struct datatype mark_type;
extern const struct datatype time_type;

extern const struct datatype *concat_type_alloc(const struct expr *expr);
extern void concat_type_destroy(const struct datatype *dtype);

#endif /* NFTABLES_DATATYPE_H */
