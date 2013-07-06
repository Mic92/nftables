/*
 * Copyright (c) 2013 Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Development of this code funded by Astaro AG (http://www.astaro.com/)
 */

#include <libmnl/libmnl.h>
#include <libnftables/table.h>
#include <libnftables/chain.h>
#include <libnftables/rule.h>
#include <libnftables/expr.h>
#include <libnftables/set.h>

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

#include <mnl.h>
#include <errno.h>
#include <utils.h>

static int seq;

static int
mnl_talk(struct mnl_socket *nf_sock, const void *data, unsigned int len,
	 int (*cb)(const struct nlmsghdr *nlh, void *data), void *cb_data)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	uint32_t portid = mnl_socket_get_portid(nf_sock);
	int ret;

	if (mnl_socket_sendto(nf_sock, data, len) < 0)
		return -1;

	ret = mnl_socket_recvfrom(nf_sock, buf, sizeof(buf));
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, seq, portid, cb, cb_data);
		if (ret <= 0)
			goto out;

		ret = mnl_socket_recvfrom(nf_sock, buf, sizeof(buf));
	}
out:
	if (ret < 0 && errno == EAGAIN)
		return 0;

	return ret;
}

/*
 * Rule
 */
int mnl_nft_rule_add(struct mnl_socket *nf_sock, struct nft_rule *nlr,
		     unsigned int flags)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;

	nlh = nft_table_nlmsg_build_hdr(buf, NFT_MSG_NEWRULE,
			nft_rule_attr_get_u32(nlr, NFT_RULE_ATTR_FAMILY),
			flags|NLM_F_ACK|NLM_F_CREATE, seq);
	nft_rule_nlmsg_build_payload(nlh, nlr);

	return mnl_talk(nf_sock, nlh, nlh->nlmsg_len, NULL, NULL);
}

int mnl_nft_rule_delete(struct mnl_socket *nf_sock, struct nft_rule *nlr,
			unsigned int flags)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;

	nlh = nft_table_nlmsg_build_hdr(buf, NFT_MSG_DELRULE,
			nft_rule_attr_get_u32(nlr, NFT_RULE_ATTR_FAMILY),
			NLM_F_ACK, seq);
	nft_rule_nlmsg_build_payload(nlh, nlr);

	return mnl_talk(nf_sock, nlh, nlh->nlmsg_len, NULL, NULL);
}

static int rule_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nft_rule_list *nlr_list = data;
	struct nft_rule *r;

	r = nft_rule_alloc();
	if (r == NULL)
		memory_allocation_error();

	if (nft_rule_nlmsg_parse(nlh, r) < 0)
		goto err_free;

	nft_rule_list_add_tail(r, nlr_list);
	return MNL_CB_OK;

err_free:
	nft_rule_free(r);
	return MNL_CB_OK;
}

struct nft_rule_list *mnl_nft_rule_dump(struct mnl_socket *nf_sock, int family)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct nft_rule_list *nlr_list;
	int ret;

	nlr_list = nft_rule_list_alloc();
	if (nlr_list == NULL)
		memory_allocation_error();

	nlh = nft_rule_nlmsg_build_hdr(buf, NFT_MSG_GETRULE, family,
				       NLM_F_DUMP, seq);

	ret = mnl_talk(nf_sock, nlh, nlh->nlmsg_len, rule_cb, nlr_list);
	if (ret < 0)
		goto err;

	return nlr_list;
err:
	nft_rule_list_free(nlr_list);
	return NULL;
}

/*
 * Chain
 */
int mnl_nft_chain_add(struct mnl_socket *nf_sock, struct nft_chain *nlc,
		      unsigned int flags)

{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;

	nlh = nft_table_nlmsg_build_hdr(buf, NFT_MSG_NEWCHAIN,
			nft_chain_attr_get_u32(nlc, NFT_CHAIN_ATTR_FAMILY),
			NLM_F_ACK|flags, seq);
	nft_chain_nlmsg_build_payload(nlh, nlc);

	return mnl_talk(nf_sock, nlh, nlh->nlmsg_len, NULL, NULL);
}

int mnl_nft_chain_delete(struct mnl_socket *nf_sock, struct nft_chain *nlc,
			 unsigned int flags)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;

	nlh = nft_table_nlmsg_build_hdr(buf, NFT_MSG_DELCHAIN,
			nft_chain_attr_get_u32(nlc, NFT_CHAIN_ATTR_FAMILY),
			NLM_F_ACK, seq);
	nft_chain_nlmsg_build_payload(nlh, nlc);

	return mnl_talk(nf_sock, nlh, nlh->nlmsg_len, NULL, NULL);
}

static int chain_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nft_chain_list *nlc_list = data;
	struct nft_chain *c;

	c = nft_chain_alloc();
	if (c == NULL)
		memory_allocation_error();

	if (nft_chain_nlmsg_parse(nlh, c) < 0)
		goto err_free;

	nft_chain_list_add_tail(c, nlc_list);
	return MNL_CB_OK;

err_free:
	nft_chain_free(c);
	return MNL_CB_OK;
}

struct nft_chain_list *mnl_nft_chain_dump(struct mnl_socket *nf_sock, int family)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct nft_chain_list *nlc_list;
	int ret;

	nlc_list = nft_chain_list_alloc();
	if (nlc_list == NULL)
		memory_allocation_error();

	nlh = nft_chain_nlmsg_build_hdr(buf, NFT_MSG_GETCHAIN, family,
					NLM_F_DUMP, seq);

	ret = mnl_talk(nf_sock, nlh, nlh->nlmsg_len, chain_cb, nlc_list);
	if (ret < 0)
		goto err;

	return nlc_list;
err:
	nft_chain_list_free(nlc_list);
	return NULL;
}

static int chain_get_cb(const struct nlmsghdr *nlh, void *data)
{
	nft_chain_nlmsg_parse(nlh, data);
	return MNL_CB_OK;
}

int mnl_nft_chain_get(struct mnl_socket *nf_sock, struct nft_chain *nlc,
		      unsigned int flags)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;

	nlh = nft_table_nlmsg_build_hdr(buf, NFT_MSG_GETCHAIN,
			nft_chain_attr_get_u32(nlc, NFT_CHAIN_ATTR_FAMILY),
			NLM_F_ACK|flags, seq);
	nft_chain_nlmsg_build_payload(nlh, nlc);

	return mnl_talk(nf_sock, nlh, nlh->nlmsg_len, chain_get_cb, nlc);
}

/*
 * Table
 */
int mnl_nft_table_add(struct mnl_socket *nf_sock, struct nft_table *nlt,
		      unsigned int flags)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;

	nlh = nft_table_nlmsg_build_hdr(buf, NFT_MSG_NEWTABLE,
			nft_table_attr_get_u32(nlt, NFT_TABLE_ATTR_FAMILY),
			NLM_F_EXCL|NLM_F_ACK, seq);
	nft_table_nlmsg_build_payload(nlh, nlt);

	return mnl_talk(nf_sock, nlh, nlh->nlmsg_len, NULL, NULL);
}

int mnl_nft_table_delete(struct mnl_socket *nf_sock, struct nft_table *nlt,
		      unsigned int flags)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;

	nlh = nft_table_nlmsg_build_hdr(buf, NFT_MSG_DELTABLE,
			nft_table_attr_get_u32(nlt, NFT_TABLE_ATTR_FAMILY),
			NLM_F_ACK, seq);
	nft_table_nlmsg_build_payload(nlh, nlt);

	return mnl_talk(nf_sock, nlh, nlh->nlmsg_len, NULL, NULL);
}

static int table_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nft_table_list *nlt_list = data;
	struct nft_table *t;

	t = nft_table_alloc();
	if (t == NULL)
		memory_allocation_error();

	if (nft_table_nlmsg_parse(nlh, t) < 0)
		goto err_free;

	nft_table_list_add_tail(t, nlt_list);
	return MNL_CB_OK;

err_free:
	nft_table_free(t);
	return MNL_CB_OK;
}

struct nft_table_list *mnl_nft_table_dump(struct mnl_socket *nf_sock, int family)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct nft_table_list *nlt_list;
	int ret;

	nlt_list = nft_table_list_alloc();
	if (nlt_list == NULL)
		memory_allocation_error();

	nlh = nft_table_nlmsg_build_hdr(buf, NFT_MSG_GETTABLE, family,
					NLM_F_DUMP, seq);

	ret = mnl_talk(nf_sock, nlh, nlh->nlmsg_len, table_cb, nlt_list);
	if (ret < 0)
		goto err;

	return nlt_list;
err:
	nft_table_list_free(nlt_list);
	return NULL;
}

static int table_get_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nft_table *t = data;

	nft_table_nlmsg_parse(nlh, t);
	return MNL_CB_OK;
}

int mnl_nft_table_get(struct mnl_socket *nf_sock, struct nft_table *nlt,
		      unsigned int flags)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;

	nlh = nft_table_nlmsg_build_hdr(buf, NFT_MSG_GETTABLE,
					nft_table_attr_get_u32(nlt, NFT_TABLE_ATTR_FAMILY),
					NLM_F_ACK, seq);
	return mnl_talk(nf_sock, nlh, nlh->nlmsg_len, table_get_cb, nlt);
}

/*
 * Set
 */
static int set_add_cb(const struct nlmsghdr *nlh, void *data)
{
	nft_set_nlmsg_parse(nlh, data);
	return MNL_CB_OK;
}

int mnl_nft_set_add(struct mnl_socket *nf_sock, struct nft_set *nls,
		    unsigned int flags)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;

	nlh = nft_set_nlmsg_build_hdr(buf, NFT_MSG_NEWSET,
				      nft_set_attr_get_u32(nls, NFT_SET_ATTR_FAMILY),
				      flags|NLM_F_CREATE|NLM_F_ACK, seq);
	nft_set_nlmsg_build_payload(nlh, nls);

	return mnl_talk(nf_sock, nlh, nlh->nlmsg_len, set_add_cb, nls);
}

int mnl_nft_set_delete(struct mnl_socket *nf_sock, struct nft_set *nls,
		       unsigned int flags)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;

	nlh = nft_set_nlmsg_build_hdr(buf, NFT_MSG_DELSET,
				      nft_set_attr_get_u32(nls, NFT_SET_ATTR_FAMILY),
				      flags|NLM_F_ACK, seq);
	nft_set_nlmsg_build_payload(nlh, nls);

	return mnl_talk(nf_sock, nlh, nlh->nlmsg_len, NULL, NULL);
}

static int set_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nft_set_list *nls_list = data;
	struct nft_set *s;

	s = nft_set_alloc();
	if (s == NULL)
		memory_allocation_error();

	if (nft_set_nlmsg_parse(nlh, s) < 0)
		goto err_free;

	nft_set_list_add_tail(s, nls_list);
	return MNL_CB_OK;

err_free:
	nft_set_free(s);
	return MNL_CB_OK;
}

struct nft_set_list *
mnl_nft_set_dump(struct mnl_socket *nf_sock, int family, const char *table)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct nft_set *s;
	struct nft_set_list *nls_list;
	int ret;

	s = nft_set_alloc();
	if (s == NULL)
		memory_allocation_error();

	nlh = nft_set_nlmsg_build_hdr(buf, NFT_MSG_GETSET, family,
				      NLM_F_DUMP|NLM_F_ACK, seq);
	nft_set_attr_set(s, NFT_SET_ATTR_TABLE, table);
	nft_set_nlmsg_build_payload(nlh, s);
	nft_set_free(s);

	nls_list = nft_set_list_alloc();
	if (nls_list == NULL)
		memory_allocation_error();

	ret = mnl_talk(nf_sock, nlh, nlh->nlmsg_len, set_cb, nls_list);
	if (ret < 0)
		goto err;

	return nls_list;
err:
	nft_set_list_free(nls_list);
	return NULL;
}

static int set_get_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nft_set *s = data;

	nft_set_nlmsg_parse(nlh, s);
	return MNL_CB_OK;
}

int mnl_nft_set_get(struct mnl_socket *nf_sock, struct nft_set *nls)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;

	nlh = nft_set_nlmsg_build_hdr(buf, NFT_MSG_GETSET,
				      nft_set_attr_get_u32(nls, NFT_SET_ATTR_FAMILY),
				      NLM_F_ACK, seq);
	nft_set_nlmsg_build_payload(nlh, nls);

	return mnl_talk(nf_sock, nlh, nlh->nlmsg_len, set_get_cb, nls);
}

/*
 * Set elements
 */
int mnl_nft_setelem_add(struct mnl_socket *nf_sock, struct nft_set *nls,
			unsigned int flags)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;

	nlh = nft_set_nlmsg_build_hdr(buf, NFT_MSG_NEWSETELEM,
				      nft_set_attr_get_u32(nls, NFT_SET_ATTR_FAMILY),
				      NLM_F_CREATE|NLM_F_EXCL|NLM_F_ACK, seq);
	nft_set_elems_nlmsg_build_payload(nlh, nls);

	return mnl_talk(nf_sock, nlh, nlh->nlmsg_len, NULL, NULL);
}

int mnl_nft_setelem_delete(struct mnl_socket *nf_sock, struct nft_set *nls,
			   unsigned int flags)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;

	nlh = nft_set_nlmsg_build_hdr(buf, NFT_MSG_DELSETELEM,
				      nft_set_attr_get_u32(nls, NFT_SET_ATTR_FAMILY),
				      NLM_F_ACK, seq);
	nft_set_elems_nlmsg_build_payload(nlh, nls);

	return mnl_talk(nf_sock, nlh, nlh->nlmsg_len, NULL, NULL);
}

static int set_elem_cb(const struct nlmsghdr *nlh, void *data)
{
	nft_set_elems_nlmsg_parse(nlh, data);
	return MNL_CB_OK;
}

int mnl_nft_setelem_get(struct mnl_socket *nf_sock, struct nft_set *nls)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;

	nlh = nft_set_nlmsg_build_hdr(buf, NFT_MSG_GETSETELEM,
				      nft_set_attr_get_u32(nls, NFT_SET_ATTR_FAMILY),
				      NLM_F_DUMP|NLM_F_ACK, seq);
	nft_set_nlmsg_build_payload(nlh, nls);

	return mnl_talk(nf_sock, nlh, nlh->nlmsg_len, set_elem_cb, nls);
}
