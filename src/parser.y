/*
 * Copyright (c) 2007-2008 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Development of this code funded by Astaro AG (http://www.astaro.com/)
 */

%{

#include <stddef.h>
#include <stdio.h>
#include <inttypes.h>
#include <netinet/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nf_conntrack_tuple_common.h>

#include <rule.h>
#include <statement.h>
#include <expression.h>
#include <utils.h>
#include <parser.h>
#include <erec.h>

#include "parser.h"
#include "scanner.h"

void parser_init(struct parser_state *state, struct list_head *msgs)
{
	memset(state, 0, sizeof(*state));
	init_list_head(&state->cmds);
	state->msgs = msgs;
}

static void yyerror(struct location *loc, void *scanner,
		    struct parser_state *state, const char *s)
{
	erec_queue(error(loc, "%s", s), state->msgs);
}

static void location_init(void *scanner, struct parser_state *state,
			  struct location *loc)
{
	memset(loc, 0, sizeof(*loc));
	loc->indesc = state->indesc;
}

static void location_update(struct location *loc, struct location *rhs, int n)
{
	if (n) {
		loc->indesc       = rhs[n].indesc;
		loc->token_offset = rhs[1].token_offset;
		loc->line_offset  = rhs[1].line_offset;
		loc->first_line   = rhs[1].first_line;
		loc->first_column = rhs[1].first_column;
		loc->last_line    = rhs[n].last_line;
		loc->last_column  = rhs[n].last_column;
	} else {
		loc->indesc       = rhs[0].indesc;
		loc->token_offset = rhs[0].token_offset;
		loc->line_offset  = rhs[0].line_offset;
		loc->first_line   = loc->last_line   = rhs[0].last_line;
		loc->first_column = loc->last_column = rhs[0].last_column;
	}
}

#define YYLLOC_DEFAULT(Current, Rhs, N)	location_update(&Current, Rhs, N)

%}

/* Declaration section */

%name-prefix="nft_"
%debug
%pure-parser
%parse-param		{ void *scanner }
%parse-param		{ struct parser_state *state }
%lex-param		{ scanner }
%error-verbose
%locations

%initial-action {
	location_init(scanner, state, &yylloc);
#if 0
	nft_set_debug(1, scanner);
	yydebug = 1;
#endif
}

%union {
	uint64_t		val;
	const char *		string;

	struct list_head	*list;
	struct cmd		*cmd;
	struct handle		handle;
	struct table		*table;
	struct chain		*chain;
	struct rule		*rule;
	struct stmt		*stmt;
	struct expr		*expr;
}

%token TOKEN_EOF 0		"end of file"
%token JUNK			"junk"

%token NEWLINE			"newline"
%token COLON			"colon"
%token SEMICOLON		"semicolon"
%token COMMA			"comma"
%token DOT			"."

%token EQ			"=="
%token NEQ			"!="
%token LT			"<"
%token GT			">"
%token GTE			">="
%token LTE			"<="
%token LSHIFT			"<<"
%token RSHIFT			">>"
%token AMPERSAND		"&"
%token CARET			"^"
%token NOT			"!"
%token SLASH			"/"
%token ASTERISK			"*"
%token DASH			"-"
%token AT			"@"
%token ARROW			"=>"
%token MAP			"map"
%token VMAP			"vmap"
%token SET			"set"

%token INCLUDE			"include"

%token HOOK			"hook"
%token <val> HOOKNUM		"hooknum"
%token TABLE			"table"
%token CHAIN			"chain"
%token RULE			"rule"
%token HANDLE			"handle"

%token ADD			"add"
%token DELETE			"delete"
%token LIST			"list"
%token FLUSH			"flush"
%token DESCRIBE			"describe"

%token ACCEPT			"accept"
%token DROP			"drop"
%token CONTINUE			"continue"
%token JUMP			"jump"
%token GOTO			"goto"
%token RETURN			"return"
%token QUEUE			"queue"

%token <val> NUM		"number"
%token <string> STRING		"string"
%token <string> QUOTED_STRING
%destructor { xfree($$); }	STRING QUOTED_STRING

%token LL_HDR			"ll"
%token NETWORK_HDR		"nh"
%token TRANSPORT_HDR		"th"

%token BRIDGE			"bridge"

%token ETH			"eth"
%token SADDR			"saddr"
%token DADDR			"daddr"
%token TYPE			"type"

%token VLAN			"vlan"
%token ID			"id"
%token CFI			"cfi"
%token PCP			"pcp"

%token ARP			"arp"
%token HTYPE			"htype"
%token PTYPE			"ptype"
%token HLEN			"hlen"
%token PLEN			"plen"
%token OPERATION		"operation"

%token IP			"ip"
%token VERSION			"version"
%token HDRLENGTH		"hdrlength"
%token TOS			"tos"
%token LENGTH			"length"
%token FRAG_OFF			"frag-off"
%token TTL			"ttl"
%token PROTOCOL			"protocol"
%token CHECKSUM			"checksum"

%token ICMP			"icmp"
%token CODE			"code"
%token SEQUENCE			"seq"
%token GATEWAY			"gateway"
%token MTU			"mtu"

%token IP6			"ip6"
%token PRIORITY			"priority"
%token FLOWLABEL		"flowlabel"
%token NEXTHDR			"nexthdr"
%token HOPLIMIT			"hoplimit"

%token AH			"ah"
%token RESERVED			"reserved"
%token SPI			"spi"

%token ESP			"esp"

%token COMP			"comp"
%token FLAGS			"flags"
%token CPI			"cpi"

%token UDP			"udp"
%token SPORT			"sport"
%token DPORT			"dport"
%token UDPLITE			"udplite"
%token CSUMCOV			"csumcov"

%token TCP			"tcp"
%token ACKSEQ			"ackseq"
%token DOFF			"doff"
%token WINDOW			"window"
%token URGPTR			"urgptr"

%token DCCP			"dccp"

%token SCTP			"sctp"
%token VTAG			"vtag"

%token RT			"rt"
%token RT0			"rt0"
%token RT2			"rt2"
%token SEG_LEFT			"seg-left"
%token ADDR			"addr"

%token HBH			"hbh"

%token FRAG			"frag"
%token RESERVED2		"reserved2"
%token MORE_FRAGMENTS		"more-fragments"

%token DST			"dst"

%token MH			"mh"

%token META			"meta"
%token MARK			"mark"
%token IIF			"iif"
%token IIFNAME			"iifname"
%token IIFTYPE			"iiftype"
%token OIF			"oif"
%token OIFNAME			"oifname"
%token OIFTYPE			"oiftype"
%token SKUID			"skuid"
%token SKGID			"skgid"
%token NFTRACE			"nftrace"
%token RTCLASSID		"rtclassid"
%token SECMARK			"secmark"

%token CT			"ct"
%token DIRECTION		"direction"
%token STATE			"state"
%token STATUS			"status"
%token EXPIRATION		"expiration"
%token HELPER			"helper"
%token PROTO_SRC		"proto-src"
%token PROTO_DST		"proto-dst"

%token COUNTER			"counter"

%token LOG			"log"
%token PREFIX			"prefix"
%token GROUP			"group"
%token SNAPLEN			"snaplen"
%token QUEUE_THRESHOLD		"queue-threshold"

%token LIMIT			"limit"
%token RATE			"rate"

%token NANOSECOND		"nanosecond"
%token MICROSECOND		"microsecond"
%token MILLISECOND		"millisecond"
%token SECOND			"second"
%token MINUTE			"minute"
%token HOUR			"hour"
%token DAY			"day"
%token WEEK			"week"

%token _REJECT			"reject"

%token SNAT			"snat"
%token DNAT			"dnat"

%type <string>			identifier string
%destructor { xfree($$); }	identifier string

%type <cmd>			line
%destructor { cmd_free($$); }	line

%type <cmd>			base_cmd add_cmd delete_cmd list_cmd flush_cmd
%destructor { cmd_free($$); }	base_cmd add_cmd delete_cmd list_cmd flush_cmd

%type <handle>			table_spec chain_spec chain_identifier ruleid_spec
%destructor { handle_free(&$$); } table_spec chain_spec chain_identifier ruleid_spec
%type <val>			handle_spec family_spec

%type <table>			table_block_alloc table_block
%destructor { table_free($$); }	table_block_alloc
%type <chain>			table_line chain_block_alloc chain_block
%destructor { chain_free($$); }	table_line chain_block_alloc
%type <rule>			rule
%destructor { rule_free($$); }	rule

%type <list>			stmt_list
%destructor { stmt_list_free($$); xfree($$); } stmt_list
%type <stmt>			stmt match_stmt verdict_stmt
%destructor { stmt_free($$); }	stmt match_stmt verdict_stmt
%type <stmt>			counter_stmt
%destructor { stmt_free($$); }	counter_stmt
%type <stmt>			meta_stmt
%destructor { stmt_free($$); }	meta_stmt
%type <stmt>			log_stmt log_stmt_alloc
%destructor { stmt_free($$); }	log_stmt log_stmt_alloc
%type <stmt>			limit_stmt
%destructor { stmt_free($$); }	limit_stmt
%type <val>			time_unit
%type <stmt>			reject_stmt
%destructor { stmt_free($$); }	reject_stmt
%type <stmt>			nat_stmt nat_stmt_alloc
%destructor { stmt_free($$); }	nat_stmt nat_stmt_alloc

%type <expr>			symbol_expr verdict_expr integer_expr
%destructor { expr_free($$); }	symbol_expr verdict_expr integer_expr
%type <expr>			primary_expr shift_expr and_expr
%destructor { expr_free($$); }	primary_expr shift_expr and_expr
%type <expr>			exclusive_or_expr inclusive_or_expr
%destructor { expr_free($$); }	exclusive_or_expr inclusive_or_expr
%type <expr>			basic_expr
%destructor { expr_free($$); }	basic_expr

%type <expr>			multiton_expr
%destructor { expr_free($$); }	multiton_expr
%type <expr>			prefix_expr range_expr wildcard_expr
%destructor { expr_free($$); }	prefix_expr range_expr wildcard_expr
%type <expr>			list_expr
%destructor { expr_free($$); }	list_expr
%type <expr>			concat_expr map_lhs_expr
%destructor { expr_free($$); }	concat_expr map_lhs_expr

%type <expr>			map_expr map_list map_list_expr
%destructor { expr_free($$); }	map_expr map_list map_list_expr

%type <expr>			verdict_map_expr verdict_map_list verdict_map_list_expr
%destructor { expr_free($$); }	verdict_map_expr verdict_map_list verdict_map_list_expr

%type <expr>			set_expr
%destructor { expr_free($$); }	set_expr

%type <expr>			expr
%destructor { expr_free($$); }	expr

%type <expr>			match_expr
%destructor { expr_free($$); }	match_expr
%type <expr>			relational_expr membership_expr
%destructor { expr_free($$); }	relational_expr membership_expr
%type <val>			relational_op

%type <expr>			payload_expr payload_raw_expr
%destructor { expr_free($$); }	payload_expr payload_raw_expr
%type <val>			payload_base_spec
%type <expr>			eth_hdr_expr	vlan_hdr_expr
%destructor { expr_free($$); }	eth_hdr_expr	vlan_hdr_expr
%type <val>			eth_hdr_field	vlan_hdr_field
%type <expr>			arp_hdr_expr
%destructor { expr_free($$); }	arp_hdr_expr
%type <val>			arp_hdr_field
%type <expr>			ip_hdr_expr	icmp_hdr_expr
%destructor { expr_free($$); }	ip_hdr_expr	icmp_hdr_expr
%type <val>			ip_hdr_field	icmp_hdr_field
%type <expr>			ip6_hdr_expr
%destructor { expr_free($$); }	ip6_hdr_expr
%type <val>			ip6_hdr_field
%type <expr>			auth_hdr_expr	esp_hdr_expr		comp_hdr_expr
%destructor { expr_free($$); }	auth_hdr_expr	esp_hdr_expr		comp_hdr_expr
%type <val>			auth_hdr_field	esp_hdr_field		comp_hdr_field
%type <expr>			udp_hdr_expr	udplite_hdr_expr	tcp_hdr_expr
%destructor { expr_free($$); }	udp_hdr_expr	udplite_hdr_expr	tcp_hdr_expr
%type <val>			udp_hdr_field	udplite_hdr_field	tcp_hdr_field
%type <expr>			dccp_hdr_expr	sctp_hdr_expr
%destructor { expr_free($$); }	dccp_hdr_expr	sctp_hdr_expr
%type <val>			dccp_hdr_field	sctp_hdr_field

%type <expr>			exthdr_expr
%destructor { expr_free($$); }	exthdr_expr
%type <expr>			hbh_hdr_expr	frag_hdr_expr		dst_hdr_expr
%destructor { expr_free($$); }	hbh_hdr_expr	frag_hdr_expr		dst_hdr_expr
%type <val>			hbh_hdr_field	frag_hdr_field		dst_hdr_field
%type <expr>			rt_hdr_expr	rt0_hdr_expr		rt2_hdr_expr
%destructor { expr_free($$); }	rt_hdr_expr	rt0_hdr_expr		rt2_hdr_expr
%type <val>			rt_hdr_field	rt0_hdr_field		rt2_hdr_field
%type <expr>			mh_hdr_expr
%destructor { expr_free($$); }	mh_hdr_expr
%type <val>			mh_hdr_field

%type <expr>			meta_expr
%destructor { expr_free($$); }	meta_expr
%type <val>			meta_key

%type <expr>			ct_expr
%destructor { expr_free($$); }	ct_expr
%type <val>			ct_key

%%

input			:	/* empty */
			|	input		line
			{
				if ($2 != NULL) {
					$2->location = @2;
					list_add_tail(&$2->list, &state->cmds);
				}
			}
			;

stmt_seperator		:	NEWLINE
			|	SEMICOLON
			;

common_block		:	INCLUDE		QUOTED_STRING	stmt_seperator
			{
				if (scanner_include_file(scanner, $2, &@$) < 0) {
					xfree($2);
					YYERROR;
				}
				xfree($2);
			}
			;

line			:	common_block			{ $$ = NULL; }
			|	stmt_seperator			{ $$ = NULL; }
			|	base_cmd	stmt_seperator	{ $$ = $1; }
			|	base_cmd	TOKEN_EOF	{ $$ = $1; }
			|	base_cmd	error		{ $$ = $1; }
			;

base_cmd		:	/* empty */	add_cmd		{ $$ = $1; }
	  		|	ADD		add_cmd		{ $$ = $2; }
			|	DELETE		delete_cmd	{ $$ = $2; }
			|	LIST		list_cmd	{ $$ = $2; }
			|	FLUSH		flush_cmd	{ $$ = $2; }
			|	DESCRIBE	primary_expr
			{
				expr_describe($2);
				expr_free($2);
				$$ = NULL;
			}
			;

add_cmd			:	TABLE		table_spec
			{
				$$ = cmd_alloc(CMD_ADD, CMD_OBJ_TABLE, &$2, NULL);
			}
			|	TABLE		table_spec	table_block_alloc
						'{'	table_block	'}'
			{
				handle_merge(&$3->handle, &$2);
				$$ = cmd_alloc(CMD_ADD, CMD_OBJ_TABLE, &$2, $5);
			}
			|	CHAIN		chain_spec
			{
				$$ = cmd_alloc(CMD_ADD, CMD_OBJ_CHAIN, &$2, NULL);
			}
			|	CHAIN		chain_spec	chain_block_alloc
						'{'	chain_block	'}'
			{
				handle_merge(&$3->handle, &$2);
				$$ = cmd_alloc(CMD_ADD, CMD_OBJ_CHAIN, &$2, $5);
			}
			|	RULE		ruleid_spec	rule
			{
				$$ = cmd_alloc(CMD_ADD, CMD_OBJ_RULE, &$2, $3);
			}
			|	/* empty */	ruleid_spec	rule
			{
				$$ = cmd_alloc(CMD_ADD, CMD_OBJ_RULE, &$1, $2);
			}
			;

delete_cmd		:	TABLE		table_spec
			{
				$$ = cmd_alloc(CMD_DELETE, CMD_OBJ_TABLE, &$2, NULL);
			}
			|	CHAIN		chain_spec
			{
				$$ = cmd_alloc(CMD_DELETE, CMD_OBJ_CHAIN, &$2, NULL);
			}
			|	RULE		ruleid_spec
			{
				$$ = cmd_alloc(CMD_DELETE, CMD_OBJ_RULE, &$2, NULL);
			}
			;

list_cmd		:	TABLE		table_spec
			{
				$$ = cmd_alloc(CMD_LIST, CMD_OBJ_TABLE, &$2, NULL);
			}
			|	CHAIN		chain_spec
			{
				$$ = cmd_alloc(CMD_LIST, CMD_OBJ_CHAIN, &$2, NULL);
			}
			;

flush_cmd		:	TABLE		table_spec
			{
				$$ = cmd_alloc(CMD_FLUSH, CMD_OBJ_TABLE, &$2, NULL);
			}
			|	CHAIN		chain_spec
			{
				$$ = cmd_alloc(CMD_FLUSH, CMD_OBJ_CHAIN, &$2, NULL);
			}
			;

table_block_alloc	:	/* empty */	{ $$ = table_alloc(); }
			;

table_block		:	/* empty */	{ $$ = $<table>-1; }
			|	common_block	{ $$ = $<table>-1; }
			|	table_block	stmt_seperator
			|	table_block	table_line	stmt_seperator
			{
				list_add_tail(&$2->list, &$1->chains);
				$$ = $1;
			}
			;

table_line		:	CHAIN		chain_identifier	chain_block_alloc
	    					'{' 	chain_block	'}'
	    		{
				handle_merge(&$3->handle, &$2);
				$$ = $3;
			}
			;

chain_block_alloc	:	/* empty */	{ $$ = chain_alloc(NULL); }
			;

chain_block		:	/* empty */	{ $$ = $<chain>-1; }
			|	common_block	{ $$ = $<chain>-1; }
	     		|	chain_block	stmt_seperator
			|	chain_block	hook_spec	stmt_seperator
			|	chain_block	rule		stmt_seperator
			{
				list_add_tail(&$2->list, &$1->rules);
				$$ = $1;
			}
			;

hook_spec		:	HOOK		HOOKNUM		NUM
			{
				$<chain>0->hooknum	= $2;
				$<chain>0->priority	= $3;
			}
			|	HOOK		HOOKNUM		DASH	NUM
			{
				$<chain>0->hooknum	= $2;
				$<chain>0->priority	= -$4;
			}
			;

identifier		:	STRING
			;

string			:	STRING
			|	QUOTED_STRING
			;

family_spec		:	/* empty */	{ $$ = NFPROTO_IPV4; }
			|	IP		{ $$ = NFPROTO_IPV4; }
			|	IP6		{ $$ = NFPROTO_IPV6; }
			|	ARP		{ $$ = NFPROTO_ARP; }
			|	BRIDGE		{ $$ = NFPROTO_BRIDGE; }
			;

table_spec		:	family_spec	identifier
			{
				memset(&$$, 0, sizeof($$));
				$$.family	= $1;
				$$.table	= $2;
			}
			;

chain_spec		:	table_spec	identifier
			{
				$$		= $1;
				$$.chain	= $2;
			}
			;

chain_identifier	:	identifier
			{
				memset(&$$, 0, sizeof($$));
				$$.chain	= $1;
			}
			;

handle_spec		:	/* empty */
			{
				$$ = 0;
			}
			|	HANDLE		NUM
			{
				$$ = $2;
			}
			;

ruleid_spec		:	chain_spec	handle_spec
			{
				$$		= $1;
				$$.handle	= $2;
			}
			;

rule			:	stmt_list
			{
				struct stmt *i;

				$$ = rule_alloc(&@$, NULL);
				list_for_each_entry(i, $1, list)
					$$->num_stmts++;
				list_splice_tail($1, &$$->stmts);
				xfree($1);
			}
			;

stmt_list		:	stmt
			{
				$$ = xmalloc(sizeof(*$$));
				init_list_head($$);
				list_add_tail(&$1->list, $$);
			}
			|	stmt_list		stmt
			{
				$$ = $1;
				list_add_tail(&$2->list, $1);
			}
			;

stmt			:	verdict_stmt
			|	match_stmt
			|	counter_stmt
			|	meta_stmt
			|	log_stmt
			|	limit_stmt
			|	reject_stmt
			|	nat_stmt
			;

verdict_stmt		:	verdict_expr
			{
				$$ = verdict_stmt_alloc(&@1, $1);
			}
			|	verdict_map_expr
			{
				$$ = verdict_stmt_alloc(&@1, $1);
			}
			;

counter_stmt		:	COUNTER
			{
				$$ = counter_stmt_alloc(&@1);
			}
			;

log_stmt		:	log_stmt_alloc
			|	log_stmt_alloc		log_args
			;

log_stmt_alloc		:	LOG
			{
				$$ = log_stmt_alloc(&@1);
			}
			;

log_args		:	log_arg
			{
				$<stmt>$	= $<stmt>0;
			}
			|	log_args	log_arg
			;

log_arg			:	PREFIX			string
			{
				$<stmt>0->log.prefix	 = $2;
			}
			|	GROUP			NUM
			{
				$<stmt>0->log.group	 = $2;
			}
			|	SNAPLEN			NUM
			{
				$<stmt>0->log.snaplen	 = $2;
			}
			|	QUEUE_THRESHOLD		NUM
			{
				$<stmt>0->log.qthreshold = $2;
			}
			;

limit_stmt		:	LIMIT	RATE	NUM	SLASH	time_unit
	    		{
				$$ = limit_stmt_alloc(&@$);
				$$->limit.rate	= $3;
				$$->limit.unit	= $5;
			}
			;

time_unit		:	NANOSECOND	{ $$ = 1ULL; }
			|	MICROSECOND	{ $$ = 1ULL * 1000; }
			|	MILLISECOND	{ $$ = 1ULL * 1000 * 1000; }
			|	SECOND		{ $$ = 1ULL * 1000 * 1000 * 1000; }
			|	MINUTE		{ $$ = 1ULL * 1000 * 1000 * 1000 * 60; }
			|	HOUR		{ $$ = 1ULL * 1000 * 1000 * 1000 * 60 * 60; }
			|	DAY		{ $$ = 1ULL * 1000 * 1000 * 1000 * 60 * 60 * 24; }
			|	WEEK		{ $$ = 1ULL * 1000 * 1000 * 1000 * 60 * 60 * 24 * 7; }
			;

reject_stmt		:	_REJECT
			{
				$$ = reject_stmt_alloc(&@$);
			}
			;

nat_stmt		:	nat_stmt_alloc	nat_stmt_args
			;

nat_stmt_alloc		:	SNAT
			{
				$$ = nat_stmt_alloc(&@$);
				$$->nat.type = NFT_NAT_SNAT;
			}
			|	DNAT
			{
				$$ = nat_stmt_alloc(&@$);
				$$->nat.type = NFT_NAT_DNAT;
			}
			;

nat_stmt_args		:	expr
			{
				$<stmt>0->nat.addr = $1;
			}
			|	expr	COLON	expr
			{
				$<stmt>0->nat.addr = $1;
				$<stmt>0->nat.proto = $3;
			}
			|	COLON	expr
			{
				$<stmt>0->nat.proto = $2;
			}
			;

match_stmt		:	match_expr
			{
				$$ = expr_stmt_alloc(&@$, $1);
			}
			;

symbol_expr		:	string
			{
				$$ = symbol_expr_alloc(&@1, $1);
				xfree($1);
			}
			;

integer_expr		:	NUM
			{
				char str[64];

				snprintf(str, sizeof(str), "%" PRIu64, $1);
				$$ = symbol_expr_alloc(&@1, str);
			}
			;

primary_expr		:	symbol_expr			{ $$ = $1; }
			|	integer_expr			{ $$ = $1; }
			|	payload_expr			{ $$ = $1; }
			|	exthdr_expr			{ $$ = $1; }
			|	meta_expr			{ $$ = $1; }
			|	ct_expr				{ $$ = $1; }
			|	'('	basic_expr	')'	{ $$ = $2; }
			;

shift_expr		:	primary_expr
			|	shift_expr		LSHIFT		primary_expr
			{
				$$ = binop_expr_alloc(&@$, OP_LSHIFT, $1, $3);
			}
			|	shift_expr		RSHIFT		primary_expr
			{
				$$ = binop_expr_alloc(&@$, OP_RSHIFT, $1, $3);
			}
			;

and_expr		:	shift_expr
			|	and_expr		AMPERSAND	shift_expr
			{
				$$ = binop_expr_alloc(&@$, OP_AND, $1, $3);
			}
			;

exclusive_or_expr	:	and_expr
			|	exclusive_or_expr	CARET		and_expr
			{
				$$ = binop_expr_alloc(&@$, OP_XOR, $1, $3);
			}
			;

inclusive_or_expr	:	exclusive_or_expr
			|	inclusive_or_expr	'|'		exclusive_or_expr
			{
				$$ = binop_expr_alloc(&@$, OP_OR, $1, $3);
			}
			;

basic_expr		:	inclusive_or_expr
			;

concat_expr		:	basic_expr
			|	concat_expr		DOT		basic_expr
			{
				if ($$->ops->type != EXPR_CONCAT) {
					$$ = concat_expr_alloc(&@$);
					compound_expr_add($$, $1);
				} else {
					$$ = $1;
					$$->location = @$;
				}
				compound_expr_add($$, $3);
			}
			;

list_expr		:	basic_expr		COMMA		basic_expr
			{
				$$ = list_expr_alloc(&@$);
				compound_expr_add($$, $1);
				compound_expr_add($$, $3);
			}
			|	list_expr		COMMA		basic_expr
			{
				$1->location = @$;
				compound_expr_add($1, $3);
				$$ = $1;
			}
			;

prefix_expr		:	basic_expr		SLASH	NUM
			{
				$$ = prefix_expr_alloc(&@$, $1, $3);
			}
			;

range_expr		:	basic_expr		DASH	basic_expr
			{
				$$ = range_expr_alloc(&@$, $1, $3);
			}
			;

wildcard_expr		:	ASTERISK
	       		{
				struct expr *expr;

				expr = constant_expr_alloc(&@1, &integer_type,
							   BYTEORDER_HOST_ENDIAN,
							   0, NULL);
				$$ = prefix_expr_alloc(&@$, expr, 0);
			}
			;

multiton_expr		:	prefix_expr
			|	range_expr
			|	wildcard_expr
			;

map_lhs_expr		:	multiton_expr
			|	concat_expr
			;

map_expr		:	concat_expr	MAP	'{'	map_list '}'
			{
				$$ = map_expr_alloc(&@$, $1, $4);
			}
			;

map_list		:	map_list_expr
			{
				$$ = set_expr_alloc(&@$);
				compound_expr_add($$, $1);
			}
			|	map_list	COMMA	map_list_expr
			{
				compound_expr_add($1, $3);
				$1->location = @$;
				$$ = $1;
			}
			|	map_list	COMMA
			;

map_list_expr		:	map_lhs_expr	ARROW	concat_expr
			{
				$$ = mapping_expr_alloc(&@$, $1, $3);
			}
			;

verdict_map_expr	:	concat_expr	VMAP	'{'	verdict_map_list '}'
			{
				$$ = map_expr_alloc(&@$, $1, $4);
			}
			;

verdict_map_list	:	verdict_map_list_expr
			{
				$$ = set_expr_alloc(&@$);
				compound_expr_add($$, $1);
			}
			|	verdict_map_list	COMMA	verdict_map_list_expr
			{
				compound_expr_add($1, $3);
				$1->location = @$;
				$$ = $1;
			}
			|	verdict_map_list	COMMA
			;

verdict_map_list_expr	:	map_lhs_expr	ARROW	verdict_expr
			{
				$$ = mapping_expr_alloc(&@$, $1, $3);
			}
			;

expr			:	concat_expr
			|       map_expr
			|	multiton_expr
			;

match_expr		:	relational_expr
			|	membership_expr
			;

relational_expr		:	expr	/* implicit */	expr
			{
				enum ops op;

				/* RHS determines operation */
				op = ($2->ops->type == EXPR_RANGE) ? OP_RANGE : OP_EQ;
				$$ = relational_expr_alloc(&@$, op, $1, $2);
			}
			|	expr	/* implicit */	list_expr
			{
				$$ = relational_expr_alloc(&@$, OP_FLAGCMP, $1, $2);
			}
			|	expr	relational_op	expr
			{
				$$ = relational_expr_alloc(&@2, $2, $1, $3);
			}
			;

relational_op		:	EQ		{ $$ = OP_EQ; }
			|	NEQ		{ $$ = OP_NEQ; }
			|	LT		{ $$ = OP_LT; }
			|	GT		{ $$ = OP_GT; }
			|	GTE		{ $$ = OP_GTE; }
			|	LTE		{ $$ = OP_LTE; }
			;

membership_expr		:	expr	'{'	set_expr	'}'
			{
				$3->location = @$;
				$$ = relational_expr_alloc(&@$, OP_LOOKUP, $1, $3);
			}
			;

set_expr		:	expr
			{
				$$ = set_expr_alloc(&@1);
				compound_expr_add($$, $1);
			}
			|	set_expr	COMMA	expr
			{
				compound_expr_add($1, $3);
				$$ = $1;
			}
			|	set_expr	COMMA
			;

verdict_expr		:	ACCEPT
			{
				$$ = verdict_expr_alloc(&@1, NF_ACCEPT, NULL);
			}
			|	DROP
			{
				$$ = verdict_expr_alloc(&@1, NF_DROP, NULL);
			}
			|	QUEUE
			{
				$$ = verdict_expr_alloc(&@1, NF_QUEUE, NULL);
			}
			|	CONTINUE
			{
				$$ = verdict_expr_alloc(&@1, NFT_CONTINUE, NULL);
			}
			|	JUMP			identifier
			{
				$$ = verdict_expr_alloc(&@1, NFT_JUMP, $2);
			}
			|	GOTO			identifier
			{
				$$ = verdict_expr_alloc(&@1, NFT_GOTO, $2);
			}
			|	RETURN
			{
				$$ = verdict_expr_alloc(&@1, NFT_RETURN, NULL);
			}
			;

meta_expr		:	META	meta_key
			{
				$$ = meta_expr_alloc(&@$, $2);
			}
			;

meta_key		:	LENGTH		{ $$ = NFT_META_LEN; }
			|	PROTOCOL	{ $$ = NFT_META_PROTOCOL; }
			|	PRIORITY	{ $$ = NFT_META_PRIORITY; }
			|	MARK		{ $$ = NFT_META_MARK; }
			|	IIF		{ $$ = NFT_META_IIF; }
			|	IIFNAME		{ $$ = NFT_META_IIFNAME; }
			|	IIFTYPE		{ $$ = NFT_META_IIFTYPE; }
			|	OIF		{ $$ = NFT_META_OIF; }
			|	OIFNAME		{ $$ = NFT_META_OIFNAME; }
			|	OIFTYPE		{ $$ = NFT_META_OIFTYPE; }
			|	SKUID		{ $$ = NFT_META_SKUID; }
			|	SKGID		{ $$ = NFT_META_SKGID; }
			|	NFTRACE		{ $$ = NFT_META_NFTRACE; }
			|	RTCLASSID	{ $$ = NFT_META_RTCLASSID; }
			|	SECMARK		{ $$ = NFT_META_SECMARK; }
			;

meta_stmt		:	META	meta_key	SET	expr
			{
				$$ = meta_stmt_alloc(&@$, $2, $4);
			}
			;

ct_expr			:	CT	ct_key
			{
				$$ = ct_expr_alloc(&@$, $2);
			}
			;

ct_key			:	STATE		{ $$ = NFT_CT_STATE; }
			|	DIRECTION	{ $$ = NFT_CT_DIRECTION; }
			|	STATUS		{ $$ = NFT_CT_STATUS; }
			|	MARK		{ $$ = NFT_CT_MARK; }
			|	SECMARK		{ $$ = NFT_CT_SECMARK; }
			|	EXPIRATION	{ $$ = NFT_CT_EXPIRATION; }
			|	HELPER		{ $$ = NFT_CT_HELPER; }
			|	PROTOCOL	{ $$ = NFT_CT_PROTOCOL; }
			|	SADDR		{ $$ = NFT_CT_SADDR; }
			|	DADDR		{ $$ = NFT_CT_DADDR; }
			|	PROTO_SRC	{ $$ = NFT_CT_PROTO_SRC; }
			|	PROTO_DST	{ $$ = NFT_CT_PROTO_DST; }
			;

payload_expr		:	payload_raw_expr
			|	eth_hdr_expr
			|	vlan_hdr_expr
			|	arp_hdr_expr
			|	ip_hdr_expr
			|	icmp_hdr_expr
			|	ip6_hdr_expr
			|	auth_hdr_expr
			|	esp_hdr_expr
			|	comp_hdr_expr
			|	udp_hdr_expr
			|	udplite_hdr_expr
			|	tcp_hdr_expr
			|	dccp_hdr_expr
			|	sctp_hdr_expr
			;

payload_raw_expr	:	AT	payload_base_spec	COMMA	NUM	COMMA	NUM
			{
				$$ = payload_expr_alloc(&@$, NULL, 0);
				$$->payload.base	= $2;
				$$->payload.offset	= $4;
				$$->len			= $6;
				$$->dtype		= &integer_type;
			}
			;

payload_base_spec	:	LL_HDR		{ $$ = PAYLOAD_BASE_LL_HDR; }
			|	NETWORK_HDR	{ $$ = PAYLOAD_BASE_NETWORK_HDR; }
			|	TRANSPORT_HDR	{ $$ = PAYLOAD_BASE_TRANSPORT_HDR; }
			;

eth_hdr_expr		:	ETH	eth_hdr_field
			{
				$$ = payload_expr_alloc(&@$, &payload_eth, $2);
			}
			;

eth_hdr_field		:	SADDR		{ $$ = ETHHDR_SADDR; }
			|	DADDR		{ $$ = ETHHDR_DADDR; }
			|	TYPE		{ $$ = ETHHDR_TYPE; }
			;

vlan_hdr_expr		:	VLAN	vlan_hdr_field
			{
				$$ = payload_expr_alloc(&@$, &payload_vlan, $2);
			}
			;

vlan_hdr_field		:	ID		{ $$ = VLANHDR_VID; }
			|	CFI		{ $$ = VLANHDR_CFI; }
			|	PCP		{ $$ = VLANHDR_PCP; }
			|	TYPE		{ $$ = VLANHDR_TYPE; }
			;

arp_hdr_expr		:	ARP	arp_hdr_field
			{
				$$ = payload_expr_alloc(&@$, &payload_arp, $2);
			}
			;

arp_hdr_field		:	HTYPE		{ $$ = ARPHDR_HRD; }
			|	PTYPE		{ $$ = ARPHDR_PRO; }
			|	HLEN		{ $$ = ARPHDR_HLN; }
			|	PLEN		{ $$ = ARPHDR_PLN; }
			|	OPERATION	{ $$ = ARPHDR_OP; }
			;

ip_hdr_expr		:	IP	ip_hdr_field
			{
				$$ = payload_expr_alloc(&@$, &payload_ip, $2);
			}
			;

ip_hdr_field		:	VERSION		{ $$ = IPHDR_VERSION; }
			|	HDRLENGTH	{ $$ = IPHDR_HDRLENGTH; }
			|	TOS		{ $$ = IPHDR_TOS; }
			|	LENGTH		{ $$ = IPHDR_LENGTH; }
			|	ID		{ $$ = IPHDR_ID; }
			|	FRAG_OFF	{ $$ = IPHDR_FRAG_OFF; }
			|	TTL		{ $$ = IPHDR_TTL; }
			|	PROTOCOL	{ $$ = IPHDR_PROTOCOL; }
			|	CHECKSUM	{ $$ = IPHDR_CHECKSUM; }
			|	SADDR		{ $$ = IPHDR_SADDR; }
			|	DADDR		{ $$ = IPHDR_DADDR; }
			;

icmp_hdr_expr		:	ICMP	icmp_hdr_field
			{
				$$ = payload_expr_alloc(&@$, &payload_icmp, $2);
			}
			;

icmp_hdr_field		:	TYPE		{ $$ = ICMPHDR_TYPE; }
			|	CODE		{ $$ = ICMPHDR_CODE; }
			|	CHECKSUM	{ $$ = ICMPHDR_CHECKSUM; }
			|	ID		{ $$ = ICMPHDR_ID; }
			|	SEQUENCE	{ $$ = ICMPHDR_SEQ; }
			|	GATEWAY		{ $$ = ICMPHDR_GATEWAY; }
			|	MTU		{ $$ = ICMPHDR_MTU; }
			;

ip6_hdr_expr		:	IP6	ip6_hdr_field
			{
				$$ = payload_expr_alloc(&@$, &payload_ip6, $2);
			}
			;

ip6_hdr_field		:	VERSION		{ $$ = IP6HDR_VERSION; }
			|	PRIORITY	{ $$ = IP6HDR_PRIORITY; }
			|	FLOWLABEL	{ $$ = IP6HDR_FLOWLABEL; }
			|	LENGTH		{ $$ = IP6HDR_LENGTH; }
			|	NEXTHDR		{ $$ = IP6HDR_NEXTHDR; }
			|	HOPLIMIT	{ $$ = IP6HDR_HOPLIMIT; }
			|	SADDR		{ $$ = IP6HDR_SADDR; }
			|	DADDR		{ $$ = IP6HDR_DADDR; }
			;

auth_hdr_expr		:	AH	auth_hdr_field
			{
				$$ = payload_expr_alloc(&@$, &payload_ah, $2);
			}
			;

auth_hdr_field		:	NEXTHDR		{ $$ = AHHDR_NEXTHDR; }
			|	HDRLENGTH	{ $$ = AHHDR_HDRLENGTH; }
			|	RESERVED	{ $$ = AHHDR_RESERVED; }
			|	SPI		{ $$ = AHHDR_SPI; }
			|	SEQUENCE	{ $$ = AHHDR_SEQUENCE; }
			;

esp_hdr_expr		:	ESP	esp_hdr_field
			{
				$$ = payload_expr_alloc(&@$, &payload_esp, $2);
			}
			;

esp_hdr_field		:	SPI		{ $$ = ESPHDR_SPI; }
			|	SEQUENCE	{ $$ = ESPHDR_SEQUENCE; }
			;

comp_hdr_expr		:	COMP	comp_hdr_field
			{
				$$ = payload_expr_alloc(&@$, &payload_comp, $2);
			}
			;

comp_hdr_field		:	NEXTHDR		{ $$ = COMPHDR_NEXTHDR; }
			|	FLAGS		{ $$ = COMPHDR_FLAGS; }
			|	CPI		{ $$ = COMPHDR_CPI; }
			;

udp_hdr_expr		:	UDP	udp_hdr_field
			{
				$$ = payload_expr_alloc(&@$, &payload_udp, $2);
			}
			;

udp_hdr_field		:	SPORT		{ $$ = UDPHDR_SPORT; }
			|	DPORT		{ $$ = UDPHDR_DPORT; }
			|	LENGTH		{ $$ = UDPHDR_LENGTH; }
			|	CHECKSUM	{ $$ = UDPHDR_CHECKSUM; }
			;

udplite_hdr_expr	:	UDPLITE	udplite_hdr_field
			{
				$$ = payload_expr_alloc(&@$, &payload_udplite, $2);
			}
			;

udplite_hdr_field	:	SPORT		{ $$ = UDPHDR_SPORT; }
			|	DPORT		{ $$ = UDPHDR_DPORT; }
			|	CSUMCOV		{ $$ = UDPHDR_LENGTH; }
			|	CHECKSUM	{ $$ = UDPHDR_CHECKSUM; }
			;

tcp_hdr_expr		:	TCP	tcp_hdr_field
			{
				$$ = payload_expr_alloc(&@$, &payload_tcp, $2);
			}
			;

tcp_hdr_field		:	SPORT		{ $$ = TCPHDR_SPORT; }
			|	DPORT		{ $$ = TCPHDR_DPORT; }
			|	SEQUENCE	{ $$ = TCPHDR_SEQ; }
			|	ACKSEQ		{ $$ = TCPHDR_ACKSEQ; }
			|	DOFF		{ $$ = TCPHDR_DOFF; }
			|	RESERVED	{ $$ = TCPHDR_RESERVED; }
			|	FLAGS		{ $$ = TCPHDR_FLAGS; }
			|	WINDOW		{ $$ = TCPHDR_WINDOW; }
			|	CHECKSUM	{ $$ = TCPHDR_CHECKSUM; }
			|	URGPTR		{ $$ = TCPHDR_URGPTR; }
			;

dccp_hdr_expr		:	DCCP	dccp_hdr_field
			{
				$$ = payload_expr_alloc(&@$, &payload_dccp, $2);
			}
			;

dccp_hdr_field		:	SPORT		{ $$ = DCCPHDR_SPORT; }
			|	DPORT		{ $$ = DCCPHDR_DPORT; }
			;

sctp_hdr_expr		:	SCTP	sctp_hdr_field
			{
				$$ = payload_expr_alloc(&@$, &payload_sctp, $2);
			}
			;

sctp_hdr_field		:	SPORT		{ $$ = SCTPHDR_SPORT; }
			|	DPORT		{ $$ = SCTPHDR_DPORT; }
			|	VTAG		{ $$ = SCTPHDR_VTAG; }
			|	CHECKSUM	{ $$ = SCTPHDR_CHECKSUM; }
			;

exthdr_expr		:	hbh_hdr_expr
			|	rt_hdr_expr
			|	rt0_hdr_expr
			|	rt2_hdr_expr
			|	frag_hdr_expr
			|	dst_hdr_expr
			|	mh_hdr_expr
			;

hbh_hdr_expr		:	HBH	hbh_hdr_field
			{
				$$ = exthdr_expr_alloc(&@$, &exthdr_hbh, $2);
			}
			;

hbh_hdr_field		:	NEXTHDR		{ $$ = HBHHDR_NEXTHDR; }
			|	HDRLENGTH	{ $$ = HBHHDR_HDRLENGTH; }
			;

rt_hdr_expr		:	RT	rt_hdr_field
			{
				$$ = exthdr_expr_alloc(&@$, &exthdr_rt, $2);
			}
			;

rt_hdr_field		:	NEXTHDR		{ $$ = RTHDR_NEXTHDR; }
			|	HDRLENGTH	{ $$ = RTHDR_HDRLENGTH; }
			|	TYPE		{ $$ = RTHDR_TYPE; }
			|	SEG_LEFT	{ $$ = RTHDR_SEG_LEFT; }
			;

rt0_hdr_expr		:	RT0	rt0_hdr_field
			{
				$$ = exthdr_expr_alloc(&@$, &exthdr_rt0, $2);
			}
			;

rt0_hdr_field		:	ADDR	'['	NUM	']'
			{
				$$ = RT0HDR_ADDR_1 + $3 - 1;
			}
			;

rt2_hdr_expr		:	RT2	rt2_hdr_field
			{
				$$ = exthdr_expr_alloc(&@$, &exthdr_rt2, $2);
			}
			;

rt2_hdr_field		:	ADDR		{ $$ = RT2HDR_ADDR; }
			;

frag_hdr_expr		:	FRAG	frag_hdr_field
			{
				$$ = exthdr_expr_alloc(&@$, &exthdr_frag, $2);
			}
			;

frag_hdr_field		:	NEXTHDR		{ $$ = FRAGHDR_NEXTHDR; }
			|	RESERVED	{ $$ = FRAGHDR_RESERVED; }
			|	FRAG_OFF	{ $$ = FRAGHDR_FRAG_OFF; }
			|	RESERVED2	{ $$ = FRAGHDR_RESERVED2; }
			|	MORE_FRAGMENTS	{ $$ = FRAGHDR_MFRAGS; }
			|	ID		{ $$ = FRAGHDR_ID; }
			;

dst_hdr_expr		:	DST	dst_hdr_field
			{
				$$ = exthdr_expr_alloc(&@$, &exthdr_dst, $2);
			}
			;

dst_hdr_field		:	NEXTHDR		{ $$ = DSTHDR_NEXTHDR; }
			|	HDRLENGTH	{ $$ = DSTHDR_HDRLENGTH; }
			;

mh_hdr_expr		:	MH	mh_hdr_field
			{
				$$ = exthdr_expr_alloc(&@$, &exthdr_mh, $2);
			}
			;

mh_hdr_field		:	NEXTHDR		{ $$ = MHHDR_NEXTHDR; }
			|	HDRLENGTH	{ $$ = MHHDR_HDRLENGTH; }
			|	TYPE		{ $$ = MHHDR_TYPE; }
			|	RESERVED	{ $$ = MHHDR_RESERVED; }
			|	CHECKSUM	{ $$ = MHHDR_CHECKSUM; }
			;

%%
