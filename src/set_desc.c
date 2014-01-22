#include <string.h>

#include <expression.h>
#include <rule.h>
#include <gmputil.h>
#include <utils.h>
#include <rbtree.h>

extern void set_desc_create(struct set *set);

struct cluster {
	struct rb_node		rb_node;
	struct list_head	list;
	mpz_t			val;
};

static struct cluster *cl_alloc(const mpz_t val)
{
	struct cluster *cl;

	cl = xzalloc(sizeof(*cl));
	mpz_init_set(cl->val, val);
	return cl;
}

static struct cluster *cl_lookup(struct rb_root *root, const mpz_t val)
{
	struct rb_node *n = root->rb_node;
	struct cluster *cl;
	int d;

	while (n != NULL) {
		cl = rb_entry(n, struct cluster, rb_node);

		d = mpz_cmp(val, cl->val);
		if (d < 0)
			n = n->rb_left;
		else if (d > 0)
			n = n->rb_right;
		else
			return cl;
	}
	return NULL;
}

static void cl_insert(struct rb_root *root, struct cluster *new)
{
	struct rb_node **p = &root->rb_node;
	struct rb_node *parent = NULL;
	struct cluster *cl;
	int d;

	while (*p != NULL) {
		parent = *p;
		cl = rb_entry(parent, struct cluster, rb_node);

		d = mpz_cmp(new->val, cl->val);
		if (d < 0)
			p = &(*p)->rb_left;
		else if (d > 0)
			p = &(*p)->rb_right;
		else
			break;
	}

	rb_link_node(&new->rb_node, parent, p);
	rb_insert_color(&new->rb_node, root);
}

void set_desc_create(struct set *set)
{
	struct cluster *cl, *next;
	struct expr *i;
	mpz_t mask, tmp;
	unsigned int n;

	printf("desc: ");
	expr_print(set->init); printf("\n");

	mpz_init(tmp);
	for (n = 1; n < set->init->dtype->size; n++) {
		struct rb_root root = RB_ROOT;
		LIST_HEAD(list);
		unsigned int cnt = 0;

		mpz_init(mask);
		mpz_prefixmask(mask, set->init->dtype->size, n);

		gmp_printf("mask %u 0x%08Zx: %u\n", n, mask);
		list_for_each_entry(i, &set->init->expressions, list) {
			mpz_and(tmp, i->value, mask);
			cl = cl_lookup(&root, tmp);
			if (cl == NULL) {
				gmp_printf("  new 0x%08Zx\n", tmp);
				cl = cl_alloc(tmp);
				cl_insert(&root, cl);
				list_add_tail(&cl->list, &list);
				cnt++;
			}
		}

		list_for_each_entry_safe(cl, next, &list, list)
			xfree(cl);
		mpz_clear(mask);
		printf("  cnt: %u\n", cnt);
	}
	printf("\n");
}
