#ifndef _NFTABLES_MNL_H_
#define _NFTABLES_MNL_H_

#include <list.h>

struct mnl_socket;

uint32_t mnl_seqnum_alloc(void);

struct mnl_err {
	struct list_head	head;
	int			err;
	uint32_t		seqnum;
};

void mnl_err_list_free(struct mnl_err *err);

void mnl_batch_init(void);
bool mnl_batch_ready(void);
void mnl_batch_reset(void);
uint32_t mnl_batch_begin(void);
void mnl_batch_end(void);
int mnl_batch_talk(struct mnl_socket *nl, struct list_head *err_list);
int mnl_nft_rule_batch_add(struct nft_rule *nlr, unsigned int flags,
			   uint32_t seqnum);
int mnl_nft_rule_batch_del(struct nft_rule *nlr, unsigned int flags,
			   uint32_t seqnum);

int mnl_nft_rule_add(struct mnl_socket *nf_sock, struct nft_rule *r,
		     unsigned int flags);
int mnl_nft_rule_delete(struct mnl_socket *nf_sock, struct nft_rule *r,
			unsigned int flags);
struct nft_rule_list *mnl_nft_rule_dump(struct mnl_socket *nf_sock,
					int family);

int mnl_nft_chain_add(struct mnl_socket *nf_sock, struct nft_chain *nlc,
		      unsigned int flags);
int mnl_nft_chain_delete(struct mnl_socket *nf_sock, struct nft_chain *nlc,
                         unsigned int flags);
struct nft_chain_list *mnl_nft_chain_dump(struct mnl_socket *nf_sock,
					  int family);
int mnl_nft_chain_get(struct mnl_socket *nf_sock, struct nft_chain *nlc,
		      unsigned int flags);

int mnl_nft_table_add(struct mnl_socket *nf_sock, struct nft_table *nlt,
		      unsigned int flags);
int mnl_nft_table_delete(struct mnl_socket *nf_sock, struct nft_table *nlt,
		      unsigned int flags);
struct nft_table_list *mnl_nft_table_dump(struct mnl_socket *nf_sock,
					  int family);
int mnl_nft_table_get(struct mnl_socket *nf_sock, struct nft_table *nlt,
		      unsigned int flags);

int mnl_nft_set_add(struct mnl_socket *nf_sock, struct nft_set *nls,
		    unsigned int flags);
int mnl_nft_set_delete(struct mnl_socket *nf_sock, struct nft_set *nls,
		       unsigned int flags);
struct nft_set_list *mnl_nft_set_dump(struct mnl_socket *nf_sock, int family,
				      const char *table);
int mnl_nft_set_get(struct mnl_socket *nf_sock, struct nft_set *nls);

int mnl_nft_setelem_add(struct mnl_socket *nf_sock, struct nft_set *nls,
			unsigned int flags);
int mnl_nft_setelem_delete(struct mnl_socket *nf_sock, struct nft_set *nls,
			   unsigned int flags);
int mnl_nft_setelem_get(struct mnl_socket *nf_sock, struct nft_set *nls);

#endif /* _NFTABLES_MNL_H_ */
