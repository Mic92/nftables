/*
 * Copyright (c) 2008 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Development of this code funded by Astaro AG (http://www.astaro.com/)
 */

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <syslog.h>

#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <statement.h>
#include <utils.h>
#include <list.h>

#include <netinet/in.h>
#include <linux/netfilter/nf_nat.h>

struct stmt *stmt_alloc(const struct location *loc,
			const struct stmt_ops *ops)
{
	struct stmt *stmt;

	stmt = xzalloc(sizeof(*stmt));
	init_list_head(&stmt->list);
	stmt->location = *loc;
	stmt->ops      = ops;
	return stmt;
}

void stmt_free(struct stmt *stmt)
{
	if (stmt->ops->destroy)
		stmt->ops->destroy(stmt);
	xfree(stmt);
}

void stmt_list_free(struct list_head *list)
{
	struct stmt *i, *next;

	list_for_each_entry_safe(i, next, list, list) {
		list_del(&i->list);
		stmt_free(i);
	}
}

void stmt_print(const struct stmt *stmt)
{
	stmt->ops->print(stmt);
}

static void expr_stmt_print(const struct stmt *stmt)
{
	expr_print(stmt->expr);
}

static void expr_stmt_destroy(struct stmt *stmt)
{
	expr_free(stmt->expr);
}

static const struct stmt_ops expr_stmt_ops = {
	.type		= STMT_EXPRESSION,
	.name		= "expression",
	.print		= expr_stmt_print,
	.destroy	= expr_stmt_destroy,
};

struct stmt *expr_stmt_alloc(const struct location *loc, struct expr *expr)
{
	struct stmt *stmt;

	stmt = stmt_alloc(loc, &expr_stmt_ops);
	stmt->expr = expr;
	return stmt;
}

static const struct stmt_ops verdict_stmt_ops = {
	.type		= STMT_VERDICT,
	.name		= "verdict",
	.print		= expr_stmt_print,
	.destroy	= expr_stmt_destroy,
};

struct stmt *verdict_stmt_alloc(const struct location *loc, struct expr *expr)
{
	struct stmt *stmt;

	stmt = stmt_alloc(loc, &verdict_stmt_ops);
	stmt->expr = expr;
	return stmt;
}

static void counter_stmt_print(const struct stmt *stmt)
{
	printf("counter packets %" PRIu64 " bytes %" PRIu64,
	       stmt->counter.packets, stmt->counter.bytes);
}

static const struct stmt_ops counter_stmt_ops = {
	.type		= STMT_COUNTER,
	.name		= "counter",
	.print		= counter_stmt_print,
};

struct stmt *counter_stmt_alloc(const struct location *loc)
{
	return stmt_alloc(loc, &counter_stmt_ops);
}

static const char *syslog_level[LOG_DEBUG + 1] = {
	[LOG_EMERG]	= "emerg",
	[LOG_ALERT]	= "alert",
	[LOG_CRIT]	= "crit",
	[LOG_ERR]       = "err",
	[LOG_WARNING]	= "warn",
	[LOG_NOTICE]	= "notice",
	[LOG_INFO]	= "info",
	[LOG_DEBUG]	= "debug",
};

static const char *log_level(uint32_t level)
{
	if (level > LOG_DEBUG)
		return "unknown";

	return syslog_level[level];
}

static void log_stmt_print(const struct stmt *stmt)
{
	printf("log");
	if (stmt->log.flags & STMT_LOG_PREFIX)
		printf(" prefix \"%s\"", stmt->log.prefix);
	if (stmt->log.flags & STMT_LOG_GROUP)
		printf(" group %u", stmt->log.group);
	if (stmt->log.flags & STMT_LOG_SNAPLEN)
		printf(" snaplen %u", stmt->log.snaplen);
	if (stmt->log.flags & STMT_LOG_QTHRESHOLD)
		printf(" queue-threshold %u", stmt->log.qthreshold);
	if ((stmt->log.flags & STMT_LOG_LEVEL) &&
	    stmt->log.level != LOG_WARNING)
		printf(" level %s", log_level(stmt->log.level));
}

static void log_stmt_destroy(struct stmt *stmt)
{
	xfree(stmt->log.prefix);
}

static const struct stmt_ops log_stmt_ops = {
	.type		= STMT_LOG,
	.name		= "log",
	.print		= log_stmt_print,
	.destroy	= log_stmt_destroy,
};

struct stmt *log_stmt_alloc(const struct location *loc)
{
	return stmt_alloc(loc, &log_stmt_ops);
}

static const char *get_unit(uint64_t u)
{
	switch (u) {
	case 1: return "second";
	case 60: return "minute";
	case 60 * 60: return "hour";
	case 60 * 60 * 24: return "day";
	case 60 * 60 * 24 * 7: return "week";
	}

	return "error";
}

static void limit_stmt_print(const struct stmt *stmt)
{
	printf("limit rate %" PRIu64 "/%s",
	       stmt->limit.rate, get_unit(stmt->limit.unit));
}

static const struct stmt_ops limit_stmt_ops = {
	.type		= STMT_LIMIT,
	.name		= "limit",
	.print		= limit_stmt_print,
};

struct stmt *limit_stmt_alloc(const struct location *loc)
{
	return stmt_alloc(loc, &limit_stmt_ops);
}

static void queue_stmt_print(const struct stmt *stmt)
{
	const char *delim = " ";

	printf("queue");
	if (stmt->queue.queue != NULL) {
		printf(" num ");
		expr_print(stmt->queue.queue);
	}
	if (stmt->queue.flags & NFT_QUEUE_FLAG_BYPASS) {
		printf("%sbypass", delim);
		delim = ",";
	}
	if (stmt->queue.flags & NFT_QUEUE_FLAG_CPU_FANOUT)
		printf("%sfanout", delim);

}

static const struct stmt_ops queue_stmt_ops = {
	.type		= STMT_QUEUE,
	.name		= "queue",
	.print		= queue_stmt_print,
};

struct stmt *queue_stmt_alloc(const struct location *loc)
{
	return stmt_alloc(loc, &queue_stmt_ops);
}

static void reject_stmt_print(const struct stmt *stmt)
{
	printf("reject");
	switch (stmt->reject.type) {
	case NFT_REJECT_TCP_RST:
		printf(" with tcp reset");
		break;
	case NFT_REJECT_ICMPX_UNREACH:
		if (stmt->reject.icmp_code == NFT_REJECT_ICMPX_PORT_UNREACH)
			break;
		printf(" with icmpx type ");
		expr_print(stmt->reject.expr);
		break;
	case NFT_REJECT_ICMP_UNREACH:
		switch (stmt->reject.family) {
		case NFPROTO_IPV4:
			if (stmt->reject.icmp_code == ICMP_PORT_UNREACH)
				break;
			printf(" with icmp type ");
			expr_print(stmt->reject.expr);
			break;
		case NFPROTO_IPV6:
			if (stmt->reject.icmp_code == ICMP6_DST_UNREACH_NOPORT)
				break;
			printf(" with icmpv6 type ");
			expr_print(stmt->reject.expr);
			break;
		}
		break;
	}
}

static const struct stmt_ops reject_stmt_ops = {
	.type		= STMT_REJECT,
	.name		= "reject",
	.print		= reject_stmt_print,
};

struct stmt *reject_stmt_alloc(const struct location *loc)
{
	return stmt_alloc(loc, &reject_stmt_ops);
}

static void print_nf_nat_flags(uint32_t flags)
{
	const char *delim = " ";

	if (flags == 0)
		return;

	if (flags & NF_NAT_RANGE_PROTO_RANDOM) {
		printf("%srandom", delim);
		delim = ",";
	}

	if (flags & NF_NAT_RANGE_PROTO_RANDOM_FULLY) {
		printf("%srandom-fully", delim);
		delim = ",";
	}

	if (flags & NF_NAT_RANGE_PERSISTENT)
		printf("%spersistent", delim);
}

static void nat_stmt_print(const struct stmt *stmt)
{
	static const char *nat_types[] = {
		[NFT_NAT_SNAT]	= "snat",
		[NFT_NAT_DNAT]	= "dnat",
	};

	printf("%s ", nat_types[stmt->nat.type]);
	if (stmt->nat.addr)
		expr_print(stmt->nat.addr);
	if (stmt->nat.proto) {
		printf(":");
		expr_print(stmt->nat.proto);
	}

	print_nf_nat_flags(stmt->nat.flags);
}

static void nat_stmt_destroy(struct stmt *stmt)
{
	expr_free(stmt->nat.addr);
	expr_free(stmt->nat.proto);
}

static const struct stmt_ops nat_stmt_ops = {
	.type		= STMT_NAT,
	.name		= "nat",
	.print		= nat_stmt_print,
	.destroy	= nat_stmt_destroy,
};

struct stmt *nat_stmt_alloc(const struct location *loc)
{
	return stmt_alloc(loc, &nat_stmt_ops);
}

static void masq_stmt_print(const struct stmt *stmt)
{
	printf("masquerade");

	print_nf_nat_flags(stmt->masq.flags);
}

static const struct stmt_ops masq_stmt_ops = {
	.type		= STMT_MASQ,
	.name		= "masq",
	.print		= masq_stmt_print,
};

struct stmt *masq_stmt_alloc(const struct location *loc)
{
	return stmt_alloc(loc, &masq_stmt_ops);
}

static void redir_stmt_print(const struct stmt *stmt)
{
	printf("redirect");

	if (stmt->redir.proto) {
		printf(" :");
		expr_print(stmt->redir.proto);
	}

	print_nf_nat_flags(stmt->redir.flags);
}

static void redir_stmt_destroy(struct stmt *stmt)
{
	expr_free(stmt->redir.proto);
}

static const struct stmt_ops redir_stmt_ops = {
	.type		= STMT_REDIR,
	.name		= "redir",
	.print		= redir_stmt_print,
	.destroy	= redir_stmt_destroy,
};

struct stmt *redir_stmt_alloc(const struct location *loc)
{
	return stmt_alloc(loc, &redir_stmt_ops);
}
