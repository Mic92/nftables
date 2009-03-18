#ifndef NFTABLES_EXTHDR_H
#define NFTABLES_EXTHDR_H

/**
 * struct exthdr_desc - extension header description
 *
 * @name:	extension header name
 * @type:	extension header protocol value
 * @templates:	header templates
 */
struct exthdr_desc {
	const char			*name;
	uint8_t				type;
	struct payload_template		templates[10];
};

extern struct expr *exthdr_expr_alloc(const struct location *loc,
				      const struct exthdr_desc *desc,
				      uint8_t type);

extern void exthdr_init_raw(struct expr *expr, uint8_t type,
			    unsigned int offset, unsigned int len);


enum hbh_hdr_fields {
	HBHHDR_INVALID,
	HBHHDR_NEXTHDR,
	HBHHDR_HDRLENGTH,
};

enum rt_hdr_fields {
	RTHDR_INVALID,
	RTHDR_NEXTHDR,
	RTHDR_HDRLENGTH,
	RTHDR_TYPE,
	RTHDR_SEG_LEFT,
};

enum rt0_hdr_fields {
	RT0HDR_INVALID,
	RT0HDR_RESERVED,
	RT0HDR_ADDR_1,
};

enum rt2_hdr_fields {
	RT2HDR_INVALID,
	RT2HDR_RESERVED,
	RT2HDR_ADDR,
};

enum frag_hdr_fields {
	FRAGHDR_INVALID,
	FRAGHDR_NEXTHDR,
	FRAGHDR_RESERVED,
	FRAGHDR_FRAG_OFF,
	FRAGHDR_RESERVED2,
	FRAGHDR_MFRAGS,
	FRAGHDR_ID,
};

enum dst_hdr_fields {
	DSTHDR_INVALID,
	DSTHDR_NEXTHDR,
	DSTHDR_HDRLENGTH,
};

enum mh_hdr_fields {
	MHHDR_INVALID,
	MHHDR_NEXTHDR,
	MHHDR_HDRLENGTH,
	MHHDR_TYPE,
	MHHDR_RESERVED,
	MHHDR_CHECKSUM,
};

extern const struct exthdr_desc exthdr_hbh;
extern const struct exthdr_desc exthdr_rt;
extern const struct exthdr_desc exthdr_rt0;
extern const struct exthdr_desc exthdr_rt2;
extern const struct exthdr_desc exthdr_frag;
extern const struct exthdr_desc exthdr_dst;
extern const struct exthdr_desc exthdr_mh;

#endif /* NFTABLES_EXTHDR_H */
