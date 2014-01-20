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
#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/rule.h>
#include <libnftnl/expr.h>
#include <libnftnl/set.h>

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

#include <mnl.h>
#include <errno.h>
#include <utils.h>
#include <nftables.h>

static int seq;

uint32_t mnl_seqnum_alloc(void)
{
	return seq++;
}

static int
mnl_talk(struct mnl_socket *nf_sock, const void *data, unsigned int len,
	 int (*cb)(const struct nlmsghdr *nlh, void *data), void *cb_data)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	uint32_t portid = mnl_socket_get_portid(nf_sock);
	int ret;

#ifdef DEBUG
	if (debug_level & DEBUG_MNL)
		mnl_nlmsg_fprintf(stdout, data, len, sizeof(struct nfgenmsg));
#endif

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
 * Batching
 */

/* selected batch page is 256 Kbytes long to load ruleset of
 * half a million rules without hitting -EMSGSIZE due to large
 * iovec.
 */
#define BATCH_PAGE_SIZE getpagesize() * 32

static struct mnl_nlmsg_batch *batch;

static struct mnl_nlmsg_batch *mnl_batch_alloc(void)
{
	static char *buf;

	/* libmnl needs higher buffer to handle batch overflows */
	buf = xmalloc(BATCH_PAGE_SIZE + getpagesize());
	return mnl_nlmsg_batch_start(buf, BATCH_PAGE_SIZE);
}

void mnl_batch_init(void)
{
	batch = mnl_batch_alloc();
}

static LIST_HEAD(batch_page_list);
static int batch_num_pages;

struct batch_page {
	struct list_head	head;
	struct mnl_nlmsg_batch *batch;
};

static void mnl_batch_page_add(void)
{
	struct batch_page *batch_page;

	batch_page = xmalloc(sizeof(struct batch_page));
	batch_page->batch = batch;
	list_add_tail(&batch_page->head, &batch_page_list);
	batch_num_pages++;
	batch = mnl_batch_alloc();
}

static uint32_t mnl_batch_put(int type)
{
	struct nlmsghdr *nlh;
	struct nfgenmsg *nfg;

	nlh = mnl_nlmsg_put_header(mnl_nlmsg_batch_current(batch));
	nlh->nlmsg_type = type;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq = mnl_seqnum_alloc();

	nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
	nfg->nfgen_family = AF_INET;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = NFNL_SUBSYS_NFTABLES;

	if (!mnl_nlmsg_batch_next(batch))
		mnl_batch_page_add();

	return nlh->nlmsg_seq;
}

uint32_t mnl_batch_begin(void)
{
	return mnl_batch_put(NFNL_MSG_BATCH_BEGIN);
}

void mnl_batch_end(void)
{
	mnl_batch_put(NFNL_MSG_BATCH_END);
}

bool mnl_batch_ready(void)
{
	/* Check if the batch only contains the initial and trailing batch
	 * messages. In that case, the batch is empty.
	 */
	return mnl_nlmsg_batch_size(batch) != (NLMSG_HDRLEN+sizeof(struct nfgenmsg)) * 2;
}

void mnl_batch_reset(void)
{
	mnl_nlmsg_batch_reset(batch);
}

static void mnl_err_list_node_add(struct list_head *err_list, int error,
				  int seqnum)
{
	struct mnl_err *err = xmalloc(sizeof(struct mnl_err));

	err->seqnum = seqnum;
	err->err = error;
	list_add_tail(&err->head, err_list);
}

void mnl_err_list_free(struct mnl_err *err)
{
	list_del(&err->head);
	xfree(err);
}

static int nlbuffsiz;

static void mnl_set_sndbuffer(const struct mnl_socket *nl)
{
	int newbuffsiz;

	if (batch_num_pages * BATCH_PAGE_SIZE <= nlbuffsiz)
		return;

	newbuffsiz = batch_num_pages * BATCH_PAGE_SIZE;

	/* Rise sender buffer length to avoid hitting -EMSGSIZE */
	if (setsockopt(mnl_socket_get_fd(nl), SOL_SOCKET, SO_SNDBUFFORCE,
		       &newbuffsiz, sizeof(socklen_t)) < 0)
		return;

	nlbuffsiz = newbuffsiz;
}

static ssize_t mnl_nft_socket_sendmsg(const struct mnl_socket *nl)
{
	static const struct sockaddr_nl snl = {
		.nl_family = AF_NETLINK
	};
	struct iovec iov[batch_num_pages];
	struct msghdr msg = {
		.msg_name	= (struct sockaddr *) &snl,
		.msg_namelen	= sizeof(snl),
		.msg_iov	= iov,
		.msg_iovlen	= batch_num_pages,
	};
	struct batch_page *batch_page, *next;
	int i = 0;

	mnl_set_sndbuffer(nl);

	list_for_each_entry_safe(batch_page, next, &batch_page_list, head) {
		iov[i].iov_base = mnl_nlmsg_batch_head(batch_page->batch);
		iov[i].iov_len = mnl_nlmsg_batch_size(batch_page->batch);
		i++;
#ifdef DEBUG
		if (debug_level & DEBUG_MNL) {
			mnl_nlmsg_fprintf(stdout,
					  mnl_nlmsg_batch_head(batch_page->batch),
					  mnl_nlmsg_batch_size(batch_page->batch),
					  sizeof(struct nfgenmsg));
		}
#endif
		list_del(&batch_page->head);
		xfree(batch_page->batch);
		xfree(batch_page);
		batch_num_pages--;
	}

	return sendmsg(mnl_socket_get_fd(nl), &msg, 0);
}

int mnl_batch_talk(struct mnl_socket *nl, struct list_head *err_list)
{
	int ret, fd = mnl_socket_get_fd(nl), portid = mnl_socket_get_portid(nl);
	char rcv_buf[MNL_SOCKET_BUFFER_SIZE];
	fd_set readfds;
	struct timeval tv = {
		.tv_sec		= 0,
		.tv_usec	= 0
	};

	if (!mnl_nlmsg_batch_is_empty(batch))
		mnl_batch_page_add();

	ret = mnl_nft_socket_sendmsg(nl);
	if (ret == -1)
		goto err;

	FD_ZERO(&readfds);
	FD_SET(fd, &readfds);

	/* receive and digest all the acknowledgments from the kernel. */
	ret = select(fd+1, &readfds, NULL, NULL, &tv);
	if (ret == -1)
		goto err;

	while (ret > 0 && FD_ISSET(fd, &readfds)) {
		struct nlmsghdr *nlh = (struct nlmsghdr *)rcv_buf;

		ret = mnl_socket_recvfrom(nl, rcv_buf, sizeof(rcv_buf));
		if (ret == -1)
			goto err;

		ret = mnl_cb_run(rcv_buf, ret, 0, portid, NULL, NULL);
		/* Continue on error, make sure we get all acknowledgments */
		if (ret == -1)
			mnl_err_list_node_add(err_list, errno, nlh->nlmsg_seq);

		ret = select(fd+1, &readfds, NULL, NULL, &tv);
		if (ret == -1)
			goto err;

		FD_ZERO(&readfds);
		FD_SET(fd, &readfds);
	}
err:
	mnl_nlmsg_batch_reset(batch);
	return ret;
}

int mnl_nft_rule_batch_add(struct nft_rule *nlr, unsigned int flags,
			   uint32_t seqnum)
{
	struct nlmsghdr *nlh;

	nlh = nft_rule_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
			NFT_MSG_NEWRULE,
			nft_rule_attr_get_u32(nlr, NFT_RULE_ATTR_FAMILY),
			flags|NLM_F_CREATE, seqnum);

	nft_rule_nlmsg_build_payload(nlh, nlr);
	if (!mnl_nlmsg_batch_next(batch))
		mnl_batch_page_add();

	return 0;
}

int mnl_nft_rule_batch_del(struct nft_rule *nlr, unsigned int flags,
			   uint32_t seqnum)
{
	struct nlmsghdr *nlh;

	nlh = nft_rule_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
			NFT_MSG_DELRULE,
			nft_rule_attr_get_u32(nlr, NFT_RULE_ATTR_FAMILY),
			0, seqnum);

	nft_rule_nlmsg_build_payload(nlh, nlr);

	if (!mnl_nlmsg_batch_next(batch))
		mnl_batch_page_add();

	return 0;
}

/*
 * Rule
 */
int mnl_nft_rule_add(struct mnl_socket *nf_sock, struct nft_rule *nlr,
		     unsigned int flags)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;

	nlh = nft_rule_nlmsg_build_hdr(buf, NFT_MSG_NEWRULE,
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

	nlh = nft_rule_nlmsg_build_hdr(buf, NFT_MSG_DELRULE,
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

	nlh = nft_chain_nlmsg_build_hdr(buf, NFT_MSG_NEWCHAIN,
			nft_chain_attr_get_u32(nlc, NFT_CHAIN_ATTR_FAMILY),
			NLM_F_CREATE|NLM_F_ACK|flags, seq);
	nft_chain_nlmsg_build_payload(nlh, nlc);

	return mnl_talk(nf_sock, nlh, nlh->nlmsg_len, NULL, NULL);
}

int mnl_nft_chain_delete(struct mnl_socket *nf_sock, struct nft_chain *nlc,
			 unsigned int flags)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;

	nlh = nft_chain_nlmsg_build_hdr(buf, NFT_MSG_DELCHAIN,
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

	nlh = nft_chain_nlmsg_build_hdr(buf, NFT_MSG_GETCHAIN,
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

	nlh = nft_set_elem_nlmsg_build_hdr(buf, NFT_MSG_NEWSETELEM,
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

	nlh = nft_set_elem_nlmsg_build_hdr(buf, NFT_MSG_DELSETELEM,
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

	nlh = nft_set_elem_nlmsg_build_hdr(buf, NFT_MSG_GETSETELEM,
			nft_set_attr_get_u32(nls, NFT_SET_ATTR_FAMILY),
			NLM_F_DUMP|NLM_F_ACK, seq);
	nft_set_nlmsg_build_payload(nlh, nls);

	return mnl_talk(nf_sock, nlh, nlh->nlmsg_len, set_elem_cb, nls);
}
