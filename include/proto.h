#ifndef NFTABLES_PROTO_H
#define NFTABLES_PROTO_H

#include <nftables.h>
#include <linux/netfilter/nf_tables.h>

/**
 * enum proto_bases - protocol bases
 *
 * @PROTO_BASE_INVALID:		uninitialised, does not happen
 * @PROTO_BASE_LL_HDR:		link layer header
 * @PROTO_BASE_NETWORK_HDR:	network layer header
 * @PROTO_BASE_TRANSPORT_HDR:	transport layer header
 */
enum proto_bases {
	PROTO_BASE_INVALID,
	PROTO_BASE_LL_HDR,
	PROTO_BASE_NETWORK_HDR,
	PROTO_BASE_TRANSPORT_HDR,
	__PROTO_BASE_MAX
};
#define PROTO_BASE_MAX		(__PROTO_BASE_MAX - 1)

extern const char *proto_base_names[];
extern const char *proto_base_tokens[];

/**
 * struct proto_hdr_template - protocol header field description
 *
 * @token:	parser token describing the header field
 * @dtype:	data type of the header field
 * @offset:	offset of the header field from base
 * @len:	length of header field
 * @meta_key:	special case: meta expression key
 */
struct proto_hdr_template {
	const char			*token;
	const struct datatype		*dtype;
	uint16_t			offset;
	uint16_t			len;
	enum nft_meta_keys		meta_key;
};

#define PROTO_HDR_TEMPLATE(__token, __dtype,  __offset, __len)		\
	{								\
		.token		= (__token),				\
		.dtype		= (__dtype),				\
		.offset		= (__offset),				\
		.len		= (__len),				\
	}

#define PROTO_META_TEMPLATE(__token, __dtype, __key, __len)		\
	{								\
		.token		= (__token),				\
		.dtype		= (__dtype),				\
		.meta_key	= (__key),				\
		.len		= (__len),				\
	}

#define PROTO_UPPER_MAX		16
#define PROTO_HDRS_MAX		20

/**
 * struct proto_desc - protocol header description
 *
 * @name:	protocol name
 * @base:	header base
 * @protocol_key: key of template containing upper layer protocol description
 * @protocols:	link to upper layer protocol descriptions indexed by protocol value
 * @templates:	header templates
 */
struct proto_desc {
	const char			*name;
	enum proto_bases		base;
	unsigned int			protocol_key;
	struct {
		unsigned int			num;
		const struct proto_desc		*desc;
	}				protocols[PROTO_UPPER_MAX];
	struct proto_hdr_template	templates[PROTO_HDRS_MAX];
};

#define PROTO_LINK(__num, __desc)	{ .num = (__num), .desc = (__desc), }

/**
 * struct hook_proto_desc - description of protocol constraints imposed by hook family
 *
 * @base:	protocol base of packets
 * @desc:	protocol description of packets
 */
struct hook_proto_desc {
	enum proto_bases		base;
	const struct proto_desc		*desc;
};

#define HOOK_PROTO_DESC(__base, __desc)	{ .base = (__base), .desc = (__desc), }

extern const struct hook_proto_desc hook_proto_desc[];

/**
 * struct dev_proto_desc - description of device LL protocol
 *
 * @desc:	protocol description
 * @type:	arphrd value
 */
struct dev_proto_desc {
	const struct proto_desc		*desc;
	uint16_t			type;
};

#define DEV_PROTO_DESC(__type, __desc)	{ .type = (__type), .desc = (__desc), }

extern int proto_dev_type(const struct proto_desc *desc, uint16_t *res);
extern const struct proto_desc *proto_dev_desc(uint16_t type);

/**
 * struct proto_ctx - protocol context
 *
 * @family:	hook family
 * @location:	location of the relational expression defining the context
 * @desc:	protocol description for this layer
 *
 * The location of the context is the location of the relational expression
 * defining it, either directly through a protocol match or indirectly
 * through a dependency.
 */
struct proto_ctx {
	unsigned int			family;
	struct {
		struct location			location;
		const struct proto_desc		*desc;
	} protocol[PROTO_BASE_MAX + 1];
};

extern void proto_ctx_init(struct proto_ctx *ctx, unsigned int family);
extern void proto_ctx_update(struct proto_ctx *ctx, enum proto_bases base,
			     const struct location *loc,
			     const struct proto_desc *desc);
extern const struct proto_desc *proto_find_upper(const struct proto_desc *base,
						 unsigned int num);
extern int proto_find_num(const struct proto_desc *base,
			  const struct proto_desc *desc);

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

extern const struct proto_desc proto_icmp;
extern const struct proto_desc proto_ah;
extern const struct proto_desc proto_esp;
extern const struct proto_desc proto_comp;
extern const struct proto_desc proto_udp;
extern const struct proto_desc proto_udplite;
extern const struct proto_desc proto_tcp;
extern const struct proto_desc proto_dccp;
extern const struct proto_desc proto_sctp;
extern const struct proto_desc proto_icmp6;

extern const struct proto_desc proto_ip;
extern const struct proto_desc proto_ip6;

extern const struct proto_desc proto_inet;
extern const struct proto_desc proto_inet_service;

extern const struct proto_desc proto_arp;

extern const struct proto_desc proto_vlan;
extern const struct proto_desc proto_eth;

extern const struct proto_desc proto_unknown;
extern const struct proto_hdr_template proto_unknown_template;

#endif /* NFTABLES_PROTO_H */
