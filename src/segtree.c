/*
 * Copyright (c) 2008-2012 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Development of this code funded by Astaro AG (http://www.astaro.com/)
 */

#include <stdlib.h>
#include <inttypes.h>
#include <arpa/inet.h>

#include <rule.h>
#include <expression.h>
#include <gmputil.h>
#include <utils.h>
#include <rbtree.h>

/**
 * struct seg_tree - segment tree
 *
 * @root:	the rbtree's root
 * @type:	the datatype of the dimension
 * @dwidth:	width of the dimension
 * @byteorder:	byteorder of elements
 */
struct seg_tree {
	struct rb_root			root;
	const struct datatype		*keytype;
	unsigned int			keylen;
	const struct datatype		*datatype;
	unsigned int			datalen;
	enum byteorder			byteorder;
};

enum elementary_interval_flags {
	EI_F_INTERVAL_END	= 0x1,
};

/**
 * struct elementary_interval - elementary interval [left, right]
 *
 * @rb_node:	seg_tree rb node
 * @list:	list node for linearized tree
 * @left:	left endpoint
 * @right:	right endpoint
 * @size:	interval size (right - left)
 * @flags:	flags
 * @expr:	associated expression
 */
struct elementary_interval {
	union {
		struct rb_node		rb_node;
		struct list_head	list;
	};

	mpz_t				left;
	mpz_t				right;
	mpz_t				size;

	enum elementary_interval_flags	flags;
	struct expr			*expr;
};

static void seg_tree_init(struct seg_tree *tree, const struct set *set)
{
	struct expr *first;

	first = list_entry(set->init->expressions.next, struct expr, list);
	tree->root	= RB_ROOT;
	tree->keytype	= set->keytype;
	tree->keylen	= set->keylen;
	tree->datatype	= set->datatype;
	tree->datalen	= set->datalen;
	tree->byteorder	= first->byteorder;
}

static struct elementary_interval *ei_alloc(const mpz_t left, const mpz_t right,
					    struct expr *expr,
					    enum elementary_interval_flags flags)
{
	struct elementary_interval *ei;

	ei = xzalloc(sizeof(*ei));
	mpz_init_set(ei->left, left);
	mpz_init_set(ei->right, right);
	mpz_init(ei->size);
	mpz_sub(ei->size, right, left);
	if (expr != NULL)
		ei->expr = expr_get(expr);
	ei->flags = flags;
	return ei;
}

static void ei_destroy(struct elementary_interval *ei)
{
	mpz_clear(ei->left);
	mpz_clear(ei->right);
	mpz_clear(ei->size);
	if (ei->expr != NULL)
		expr_free(ei->expr);
	xfree(ei);
}

/**
 * ei_lookup - find elementary interval containing point p
 *
 * @tree:	segment tree
 * @p:		the point
 */
static struct elementary_interval *ei_lookup(struct seg_tree *tree, const mpz_t p)
{
	struct rb_node *n = tree->root.rb_node;
	struct elementary_interval *ei;

	while (n != NULL) {
		ei = rb_entry(n, struct elementary_interval, rb_node);

		if (mpz_cmp(p, ei->left) >= 0 &&
		    mpz_cmp(p, ei->right) <= 0)
			return ei;
		else if (mpz_cmp(p, ei->left) <= 0)
			n = n->rb_left;
		else if (mpz_cmp(p, ei->right) > 0)
			n = n->rb_right;
	}
	return NULL;
}

static void ei_remove(struct seg_tree *tree, struct elementary_interval *ei)
{
	rb_erase(&ei->rb_node, &tree->root);
}

static void __ei_insert(struct seg_tree *tree, struct elementary_interval *new)
{
	struct rb_node **p = &tree->root.rb_node;
	struct rb_node *parent = NULL;
	struct elementary_interval *ei;

	while (*p != NULL) {
		parent = *p;
		ei = rb_entry(parent, struct elementary_interval, rb_node);

		if (mpz_cmp(new->left, ei->left) >= 0 &&
		    mpz_cmp(new->left, ei->right) <= 0)
			break;
		else if (mpz_cmp(new->left, ei->left) <= 0)
			p = &(*p)->rb_left;
		else if (mpz_cmp(new->left, ei->left) > 0)
			p = &(*p)->rb_right;
	}

	rb_link_node(&new->rb_node, parent, p);
	rb_insert_color(&new->rb_node, &tree->root);
}

static bool segtree_debug(void)
{
#ifdef DEBUG
	if (debug_level & DEBUG_SEGTREE)
		return true;
#endif
	return false;
}

/**
 * ei_insert - insert an elementary interval into the tree
 *
 * @tree:	the seg_tree
 * @new:	the elementary interval
 *
 * New entries take precedence over existing ones. Insertions are assumed to
 * be ordered by descending interval size, meaning the new interval never
 * extends over more than two existing intervals.
 */
static void ei_insert(struct seg_tree *tree, struct elementary_interval *new)
{
	struct elementary_interval *lei, *rei;
	mpz_t p;

	mpz_init2(p, tree->keylen);

	/*
	 * Lookup the intervals containing the left and right endpoints.
	 */
	lei = ei_lookup(tree, new->left);
	rei = ei_lookup(tree, new->right);

	if (segtree_debug())
		pr_debug("insert: [%Zx %Zx]\n", new->left, new->right);

	if (lei != NULL && rei != NULL && lei == rei) {
		/*
		 * The new interval is entirely contained in the same interval,
		 * split it into two parts:
		 *
		 * [lei_left, new_left) and (new_right, rei_right]
		 */
		if (segtree_debug())
			pr_debug("split [%Zx %Zx]\n", lei->left, lei->right);

		ei_remove(tree, lei);

		mpz_sub_ui(p, new->left, 1);
		if (mpz_cmp(lei->left, p) <= 0)
			__ei_insert(tree, ei_alloc(lei->left, p, lei->expr, 0));

		mpz_add_ui(p, new->right, 1);
		if (mpz_cmp(p, rei->right) < 0)
			__ei_insert(tree, ei_alloc(p, rei->right, lei->expr, 0));
		ei_destroy(lei);
	} else {
		if (lei != NULL) {
			/*
			 * Left endpoint is within lei, adjust it so we have:
			 *
			 * [lei_left, new_left)[new_left, new_right]
			 */
			if (segtree_debug()) {
				pr_debug("adjust left [%Zx %Zx]\n",
					 lei->left, lei->right);
			}

			mpz_sub_ui(lei->right, new->left, 1);
			mpz_sub(lei->size, lei->right, lei->left);
			if (mpz_sgn(lei->size) < 0) {
				ei_remove(tree, lei);
				ei_destroy(lei);
			}
		}
		if (rei != NULL) {
			/*
			 * Right endpoint is within rei, adjust it so we have:
			 *
			 * [new_left, new_right](new_right, rei_right]
			 */
			if (segtree_debug()) {
				pr_debug("adjust right [%Zx %Zx]\n",
					 rei->left, rei->right);
			}

			mpz_add_ui(rei->left, new->right, 1);
			mpz_sub(rei->size, rei->right, rei->left);
			if (mpz_sgn(rei->size) < 0) {
				ei_remove(tree, rei);
				ei_destroy(rei);
			}
		}
	}

	__ei_insert(tree, new);

	mpz_clear(p);
}

static void range_low(mpz_t rop, struct expr *expr)
{
	switch (expr->ops->type) {
	case EXPR_VALUE:
		return mpz_set(rop, expr->value);
	case EXPR_PREFIX:
		return range_low(rop, expr->prefix);
	case EXPR_RANGE:
		return range_low(rop, expr->left);
	case EXPR_MAPPING:
		return range_low(rop, expr->left);
	default:
		BUG("invalid range expression type %s\n", expr->ops->name);
	}
}

static void range_high(mpz_t rop, const struct expr *expr)
{
	mpz_t tmp;

	switch (expr->ops->type) {
	case EXPR_VALUE:
		return mpz_set(rop, expr->value);
	case EXPR_PREFIX:
		range_low(rop, expr->prefix);
		mpz_init_bitmask(tmp, expr->len - expr->prefix_len);
		mpz_add(rop, rop, tmp);
		mpz_clear(tmp);
		return;
	case EXPR_RANGE:
		return range_high(rop, expr->right);
	case EXPR_MAPPING:
		return range_high(rop, expr->left);
	default:
		BUG("invalid range expression type %s\n", expr->ops->name);
	}
}

/*
 * Sort intervals according to their priority, which is defined inversely to
 * their size.
 *
 * The beginning of the interval is used as secondary sorting criterion. This
 * makes sure that overlapping ranges with equal priority are next to each
 * other, allowing to easily detect unsolvable conflicts during insertion.
 *
 * Note: unsolvable conflicts can only occur when using ranges or two identical
 * prefix specifications.
 */
static int interval_cmp(const void *p1, const void *p2)
{
	const struct elementary_interval *e1 = *(void * const *)p1;
	const struct elementary_interval *e2 = *(void * const *)p2;
	mpz_t d;
	int ret;

	mpz_init(d);

	mpz_sub(d, e2->size, e1->size);
	if (mpz_cmp_ui(d, 0))
		ret = mpz_sgn(d);
	else
		ret = mpz_cmp(e1->left, e2->left);

	mpz_clear(d);
	return ret;
}

static bool interval_conflict(const struct elementary_interval *e1,
			      const struct elementary_interval *e2)
{
	if (mpz_cmp(e1->left, e2->left) <= 0 &&
	    mpz_cmp(e1->right, e2->left) >= 0 &&
	    mpz_cmp(e1->size, e2->size) == 0)
		return true;
	else
		return false;
}

static void set_to_segtree(struct expr *set, struct seg_tree *tree)
{
	struct elementary_interval *intervals[set->size];
	struct elementary_interval *ei;
	struct expr *i, *next;
	unsigned int n;
	mpz_t low, high;

	mpz_init2(low, tree->keylen);
	mpz_init2(high, tree->keylen);

	/*
	 * Convert elements to intervals and sort by priority.
	 */
	n = 0;
	list_for_each_entry_safe(i, next, &set->expressions, list) {
		range_low(low, i);
		range_high(high, i);
		ei = ei_alloc(low, high, i, 0);
		intervals[n++] = ei;

		list_del(&i->list);
		expr_free(i);
	}
	qsort(intervals, n, sizeof(intervals[0]), interval_cmp);

	/*
	 * Insert elements into tree
	 */
	for (n = 0; n < set->size; n++) {
		if (n < set->size - 1 &&
		    interval_conflict(intervals[n], intervals[n+1]))
			pr_debug("conflict\n");
		ei_insert(tree, intervals[n]);
	}

	mpz_clear(high);
	mpz_clear(low);
}

static void segtree_linearize(struct list_head *list, struct seg_tree *tree)
{
	struct rb_node *node, *next;
	struct elementary_interval *ei, *nei, *prev = NULL;
	mpz_t p, q;

	mpz_init2(p, tree->keylen);
	mpz_init2(q, tree->keylen);

	/*
	 * Convert the tree of open intervals to half-closed map expressions.
	 */
	rb_for_each_entry_safe(ei, node, next, &tree->root, rb_node) {
		if (segtree_debug())
			pr_debug("iter: [%Zx %Zx]\n", ei->left, ei->right);

		if (prev == NULL) {
			/*
			 * If the first segment doesn't begin at zero, insert a
			 * non-matching segment to cover [0, first_left).
			 */
			if (mpz_cmp_ui(ei->left, 0)) {
				mpz_set_ui(p, 0);
				mpz_sub_ui(q, ei->left, 1);
				nei = ei_alloc(p, q, NULL, EI_F_INTERVAL_END);
				list_add_tail(&nei->list, list);
			}
		} else {
			/*
			 * If the previous segment doesn't end directly left to
			 * this one, insert a non-matching segment to cover
			 * (prev_right, ei_left).
			 */
			mpz_add_ui(p, prev->right, 1);
			if (mpz_cmp(p, ei->left) < 0) {
				mpz_sub_ui(q, ei->left, 1);
				nei = ei_alloc(p, q, NULL, EI_F_INTERVAL_END);
				list_add_tail(&nei->list, list);
			} else if (ei->expr->ops->type != EXPR_MAPPING) {
				mpz_set(prev->right, ei->right);
				ei_remove(tree, ei);
				ei_destroy(ei);
				continue;
			}
		}

		ei_remove(tree, ei);
		list_add_tail(&ei->list, list);

		prev = ei;
	}

	/*
	 * If the last segment doesn't end at the right side of the dimension,
	 * insert a non-matching segment to cover (last_right, end].
	 */
	if (mpz_scan0(prev->right, 0) != tree->keylen) {
		mpz_add_ui(p, prev->right, 1);
		mpz_bitmask(q, tree->keylen);
		nei = ei_alloc(p, q, NULL, EI_F_INTERVAL_END);
		list_add_tail(&nei->list, list);
	}

	mpz_clear(p);
	mpz_clear(q);
}

static void set_insert_interval(struct expr *set, struct seg_tree *tree,
				const struct elementary_interval *ei)
{
	struct expr *expr;

	expr = constant_expr_alloc(&internal_location, tree->keytype,
				   tree->byteorder, tree->keylen, NULL);
	mpz_set(expr->value, ei->left);

	if (ei->expr != NULL && ei->expr->ops->type == EXPR_MAPPING)
		expr = mapping_expr_alloc(&ei->expr->location, expr,
					  expr_get(ei->expr->right));

	if (ei->flags & EI_F_INTERVAL_END)
		expr->flags |= EXPR_F_INTERVAL_END;

	compound_expr_add(set, expr);
}

void set_to_intervals(struct set *set)
{
	struct elementary_interval *ei, *next;
	struct seg_tree tree;
	LIST_HEAD(list);

	seg_tree_init(&tree, set);
	set_to_segtree(set->init, &tree);
	segtree_linearize(&list, &tree);

	list_for_each_entry_safe(ei, next, &list, list) {
		if (segtree_debug()) {
			pr_debug("list: [%.*Zx %.*Zx]\n",
				 2 * tree.keylen / BITS_PER_BYTE, ei->left,
				 2 * tree.keylen / BITS_PER_BYTE, ei->right);
		}
		set_insert_interval(set->init, &tree, ei);
		ei_destroy(ei);
	}

	if (segtree_debug()) {
		expr_print(set->init);
		pr_debug("\n");
	}
}

static bool range_is_prefix(const mpz_t range)
{
	mpz_t tmp;

	mpz_init_set(tmp, range);
	mpz_add_ui(tmp, tmp, 1);
	mpz_and(tmp, range, tmp);
	return !mpz_cmp_ui(tmp, 0);
}

extern void interval_map_decompose(struct expr *set);

static struct expr *expr_value(struct expr *expr)
{
	if (expr->ops->type == EXPR_MAPPING)
		return expr->left;
	else
		return expr;
}

void interval_map_decompose(struct expr *set)
{
	struct expr *ranges[set->size * 2];
	struct expr *i, *next, *low = NULL, *end;
	unsigned int n, size;
	mpz_t range, p;
	bool interval;

	mpz_init(range);
	mpz_init(p);

	size = set->size;
	n = 0;

	interval = false;
	list_for_each_entry_safe_reverse(i, next, &set->expressions, list) {
		compound_expr_remove(set, i);

		if (i->flags & EXPR_F_INTERVAL_END)
			interval = false;
		else if (interval) {
			end = expr_clone(expr_value(i));
			end->flags |= EXPR_F_INTERVAL_END;
			ranges[n++] = end;
			size++;
		} else
			interval = true;

		ranges[n++] = i;
	}

	for (n = 0; n < size; n++) {
		i = ranges[n];

		if (low == NULL) {
			if (i->flags & EXPR_F_INTERVAL_END) {
				/*
				 * End of interval mark
				 */
				expr_free(i);
				continue;
			} else {
				/*
				 * Start a new interval
				 */
				low = i;
				continue;
			}
		} else
			expr_get(low);

		mpz_sub(range, expr_value(i)->value, expr_value(low)->value);
		mpz_sub_ui(range, range, 1);

		mpz_and(p, expr_value(low)->value, range);

		if (!mpz_cmp_ui(range, 0))
			compound_expr_add(set, low);
		else if ((!range_is_prefix(range) ||
			  !(i->dtype->flags & DTYPE_F_PREFIX)) ||
			 mpz_cmp_ui(p, 0)) {
			struct expr *tmp;

			tmp = constant_expr_alloc(&low->location, low->dtype,
						  low->byteorder, low->len,
						  NULL);

			mpz_add(range, range, expr_value(low)->value);
			mpz_set(tmp->value, range);

			tmp = range_expr_alloc(&low->location, expr_value(low), tmp);
			if (low->ops->type == EXPR_MAPPING)
				tmp = mapping_expr_alloc(&tmp->location, tmp, low->right);

			compound_expr_add(set, tmp);
		} else {
			struct expr *prefix;
			unsigned int prefix_len;

			prefix_len = expr_value(i)->len - mpz_scan0(range, 0);
			prefix = prefix_expr_alloc(&low->location, expr_value(low),
						   prefix_len);
			if (low->ops->type == EXPR_MAPPING)
				prefix = mapping_expr_alloc(&low->location, prefix,
							    low->right);

			compound_expr_add(set, prefix);
		}

		if (i->flags & EXPR_F_INTERVAL_END) {
			expr_free(low);
			low = NULL;
		}
		expr_free(i);
	}

	/* Unclosed interval */
	if (low != NULL) {
		i = constant_expr_alloc(&low->location, low->dtype,
					low->byteorder, expr_value(low)->len,
					NULL);
		mpz_init_bitmask(i->value, i->len);

		i = range_expr_alloc(&low->location, expr_value(low), i);
		if (low->ops->type == EXPR_MAPPING)
			i = mapping_expr_alloc(&i->location, i, low->right);

		compound_expr_add(set, i);
	}
}
