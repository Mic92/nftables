#ifndef NFTABLES_PAYLOAD_H
#define NFTABLES_PAYLOAD_H

#include <nftables.h>

/**
 * enum payload_bases
 *
 * @PAYLOAD_BASE_INVALID:	uninitialised, does not happen
 * @PAYLOAD_BASE_LL_HDR:	link layer header
 * @PAYLOAD_BASE_NETWORK_HDR:	network layer header
 * @PAYLOAD_BASE_TRANSPORT_HDR:	transport layer header
 */
enum payload_bases {
	PAYLOAD_BASE_INVALID,
	PAYLOAD_BASE_LL_HDR,
	PAYLOAD_BASE_NETWORK_HDR,
	PAYLOAD_BASE_TRANSPORT_HDR,
	__PAYLOAD_BASE_MAX
};
#define PAYLOAD_BASE_MAX	(__PAYLOAD_BASE_MAX - 1)

/**
 * enum payload_expr_flags
 *
 * @PAYLOAD_PROTOCOL_EXPR:	payload expression contains upper layer protocol
 */
enum payload_expr_flags {
	PAYLOAD_PROTOCOL_EXPR		= 0x1,
};

/**
 * struct payload_template - template for a payload header expression
 *
 * @token:	parser token describing the header field
 * @dtype:	data type of the expression
 * @offset:	offset from base
 * @len:	length of header field
 */
struct payload_template {
	const char			*token;
	const struct datatype		*dtype;
	uint16_t			offset;
	uint16_t			len;
};

#define PAYLOAD_TEMPLATE(__token, __dtype,  __offset, __len)		\
	{								\
		.token		= (__token),				\
		.dtype		= (__dtype),				\
		.offset		= (__offset),				\
		.len		= (__len),				\
	}

#define PAYLOAD_PROTO_MAX		16
#define PAYLOAD_TEMPLATE_MAX		20

/**
 * struct payload_desc - payload protocol description
 *
 * @name:	protocol name
 * @base:	header base
 * @protocol_key: key of template containing upper layer protocol description
 * @protocols:	link to upper layer protocol description indexed by protocol value
 * @templates:	header templates
 */
struct payload_desc {
	const char			*name;
	enum payload_bases		base;
	unsigned int			protocol_key;
	struct {
		unsigned int			num;
		const struct payload_desc	*desc;
	}				protocols[PAYLOAD_PROTO_MAX];
	struct payload_template		templates[PAYLOAD_TEMPLATE_MAX];
};

#define PAYLOAD_PROTO(__num, __desc)	{ .num = (__num), .desc = (__desc), }

/**
 * struct payload_hook_desc - description of constraints imposed by hook family
 *
 * @base:	protocol base of packets
 * @desc:	protocol description of packets
 */
struct payload_hook_desc {
	enum payload_bases		base;
	const struct payload_desc	*desc;
};

#define PAYLOAD_HOOK(__base, __desc)	{ .base = (__base), .desc = (__desc), }

/**
 * struct dev_payload_desc - description of device LL protocol
 *
 * @desc:	protocol description
 * @type:	arphrd value
 */
struct dev_payload_desc {
	const struct payload_desc	*desc;
	uint16_t			type;
};

#define DEV_PAYLOAD_DESC(__type, __desc) { .type = (__type), .desc = (__desc), }

/**
 * struct payload_ctx - payload expression protocol context
 *
 * @family:	hook family
 * @location:	location of expression defining the context
 * @desc:	payload description for this layer
 *
 * The location of the context is the location of the relational expression
 * defining it, either directly through a protocol match or indirectly
 * through a dependency.
 */
struct payload_ctx {
	unsigned int			family;
	struct {
		struct location			location;
		const struct payload_desc	*desc;
	} protocol[PAYLOAD_BASE_MAX + 1];
};

extern struct expr *payload_expr_alloc(const struct location *loc,
				       const struct payload_desc *desc,
				       unsigned int type);
extern void payload_init_raw(struct expr *expr, enum payload_bases base,
			     unsigned int offset, unsigned int len);

extern void payload_ctx_init(struct payload_ctx *ctx, unsigned int family);
extern void payload_ctx_update_meta(struct payload_ctx *ctx,
				    const struct expr *expr);
extern void payload_ctx_update(struct payload_ctx *ctx,
			       const struct expr *expr);

struct eval_ctx;
extern int payload_gen_dependency(struct eval_ctx *ctx, const struct expr *expr,
				  struct expr **res);

extern bool payload_is_adjacent(const struct expr *e1, const struct expr *e2);
extern struct expr *payload_expr_join(const struct expr *e1,
				      const struct expr *e2);

extern void payload_expr_expand(struct list_head *list, struct expr *expr,
				const struct payload_ctx *ctx);
extern void payload_expr_complete(struct expr *expr,
				  const struct payload_ctx *ctx);

enum eth_hdr_fields {
	ETHHDR_INVALID,
	ETHHDR_DADDR,
	ETHHDR_SADDR,
	ETHHDR_TYPE,
};

enum vlan_hdr_fields {
	VLANHDR_INVALID,
	VLANHDR_VID,
	VLANHDR_CFI,
	VLANHDR_PCP,
	VLANHDR_TYPE,
};

enum arp_hdr_fields {
	ARPHDR_INVALID,
	ARPHDR_HRD,
	ARPHDR_PRO,
	ARPHDR_HLN,
	ARPHDR_PLN,
	ARPHDR_OP,
};

enum ip_hdr_fields {
	IPHDR_INVALID,
	IPHDR_VERSION,
	IPHDR_HDRLENGTH,
	IPHDR_TOS,
	IPHDR_LENGTH,
	IPHDR_ID,
	IPHDR_FRAG_OFF,
	IPHDR_TTL,
	IPHDR_PROTOCOL,
	IPHDR_CHECKSUM,
	IPHDR_SADDR,
	IPHDR_DADDR,
};

enum icmp_hdr_fields {
	ICMPHDR_INVALID,
	ICMPHDR_TYPE,
	ICMPHDR_CODE,
	ICMPHDR_CHECKSUM,
	ICMPHDR_ID,
	ICMPHDR_SEQ,
	ICMPHDR_GATEWAY,
	ICMPHDR_MTU,
};

enum icmp6_hdr_fields {
	ICMP6HDR_INVALID,
	ICMP6HDR_TYPE,
	ICMP6HDR_CODE,
	ICMP6HDR_CHECKSUM,
	ICMP6HDR_PPTR,
	ICMP6HDR_MTU,
	ICMP6HDR_ID,
	ICMP6HDR_SEQ,
	ICMP6HDR_MAXDELAY,
};

enum ip6_hdr_fields {
	IP6HDR_INVALID,
	IP6HDR_VERSION,
	IP6HDR_PRIORITY,
	IP6HDR_FLOWLABEL,
	IP6HDR_LENGTH,
	IP6HDR_NEXTHDR,
	IP6HDR_HOPLIMIT,
	IP6HDR_SADDR,
	IP6HDR_DADDR,
	IP6HDR_PROTOCOL,
};

enum ah_hdr_fields {
	AHHDR_INVALID,
	AHHDR_NEXTHDR,
	AHHDR_HDRLENGTH,
	AHHDR_RESERVED,
	AHHDR_SPI,
	AHHDR_SEQUENCE,
};

enum esp_hdr_fields {
	ESPHDR_INVALID,
	ESPHDR_SPI,
	ESPHDR_SEQUENCE,
};

enum comp_hdr_fields {
	COMPHDR_INVALID,
	COMPHDR_NEXTHDR,
	COMPHDR_FLAGS,
	COMPHDR_CPI,
};

enum udp_hdr_fields {
	UDPHDR_INVALID,
	UDPHDR_SPORT,
	UDPHDR_DPORT,
	UDPHDR_LENGTH,
	UDPHDR_CSUMCOV = UDPHDR_LENGTH,
	UDPHDR_CHECKSUM,
};

enum tcp_hdr_fields {
	TCPHDR_INVALID,
	TCPHDR_SPORT,
	TCPHDR_DPORT,
	TCPHDR_SEQ,
	TCPHDR_ACKSEQ,
	TCPHDR_DOFF,
	TCPHDR_RESERVED,
	TCPHDR_FLAGS,
	TCPHDR_WINDOW,
	TCPHDR_CHECKSUM,
	TCPHDR_URGPTR,
};

enum dccp_hdr_fields {
	DCCPHDR_INVALID,
	DCCPHDR_SPORT,
	DCCPHDR_DPORT,
	DCCPHDR_TYPE,
};

enum sctp_hdr_fields {
	SCTPHDR_INVALID,
	SCTPHDR_SPORT,
	SCTPHDR_DPORT,
	SCTPHDR_VTAG,
	SCTPHDR_CHECKSUM,
};

extern const struct payload_desc payload_icmp;
extern const struct payload_desc payload_ah;
extern const struct payload_desc payload_esp;
extern const struct payload_desc payload_comp;
extern const struct payload_desc payload_udp;
extern const struct payload_desc payload_udplite;
extern const struct payload_desc payload_tcp;
extern const struct payload_desc payload_dccp;
extern const struct payload_desc payload_sctp;
extern const struct payload_desc payload_icmp6;

extern const struct payload_desc payload_ip;
extern const struct payload_desc payload_ip6;

extern const struct payload_desc payload_arp;

extern const struct payload_desc payload_vlan;
extern const struct payload_desc payload_eth;

#endif /* NFTABLES_PAYLOAD_H */
