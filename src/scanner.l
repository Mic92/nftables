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

#include <limits.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <linux/netfilter.h>

#include <nftables.h>
#include <erec.h>
#include <rule.h>
#include <parser.h>
#include "parser.h"

#define YY_NO_INPUT

/*
 * Work around flex behaviour when reaching the end of buffer: normally, flex
 * regexes are greedy, when reaching the end of buffer however it tries to
 * match whatever is left in the buffer and only backs up in case it doesn't
 * match *any* pattern. Since we accept unquoted strings, this means any partial
 * token will be recognized as string.
 *
 * Make sure to only pass input to flex linewise to avoid this.
 */
#define YY_INPUT(buf,result,max_size)						\
{										\
	long n = 0;								\
	errno = 0;								\
	while ((result = fread(buf, 1, max_size, yyin)) == 0 &&			\
		ferror(yyin)) {							\
		if (errno != EINTR) {						\
			YY_FATAL_ERROR("input in flex scanner failed");		\
			break;							\
		}								\
		errno = 0;							\
		clearerr(yyin);							\
	}									\
	if (result > 1) {							\
		while (result > 1 && buf[result - 1] != '\n')			\
			result--, n++;						\
		result--, n++;							\
		fseek(yyin, -n, SEEK_CUR);					\
	}									\
}

static void scanner_pop_buffer(yyscan_t scanner);


static void init_pos(struct parser_state *state)
{
	state->indesc->lineno		= 1;
	state->indesc->column		= 1;
	state->indesc->token_offset	= 0;
	state->indesc->line_offset 	= 0;
}

static void update_pos(struct parser_state *state, struct location *loc,
		       int len)
{
	loc->indesc			= state->indesc;
	loc->first_line			= state->indesc->lineno;
	loc->first_column		= state->indesc->column;
	loc->last_column		= state->indesc->column + len - 1;
	state->indesc->column		+= len;
}

static void update_offset(struct parser_state *state, struct location *loc,
			  unsigned int len)
{
	state->indesc->token_offset	+= len;
	loc->token_offset		= state->indesc->token_offset;
	loc->line_offset		= state->indesc->line_offset;
}

static void reset_pos(struct parser_state *state, struct location *loc)
{
	state->indesc->line_offset	= state->indesc->token_offset;
	state->indesc->lineno		+= 1;
	state->indesc->column		= 1;
	loc->line_offset		= state->indesc->line_offset;
}

#define YY_USER_ACTION {					\
	update_pos(yyget_extra(yyscanner), yylloc, yyleng);	\
	update_offset(yyget_extra(yyscanner), yylloc, yyleng);	\
}

/* avoid warnings with -Wmissing-prototypes */
extern int	yyget_column(yyscan_t);
extern void	yyset_column(int, yyscan_t);

%}

space		[ ]
tab		\t
newline		\n
digit		[0-9]
hexdigit	[0-9a-fA-F]
decstring	{digit}+
hexstring	0[xX]{hexdigit}+
range		({decstring}?:{decstring}?)
letter		[a-zA-Z]
string		({letter})({letter}|{digit}|[/\-_\.])*
quotedstring	\"[^"]*\"
comment		#.*$
slash		\/

hex4		([[:xdigit:]]{1,4})
v680		(({hex4}:){7}{hex4})
v670		((:)((:{hex4}){7}))
v671		((({hex4}:){1})((:{hex4}){6}))
v672		((({hex4}:){2})((:{hex4}){5}))
v673		((({hex4}:){3})((:{hex4}){4}))
v674		((({hex4}:){4})((:{hex4}){3}))
v675		((({hex4}:){5})((:{hex4}){2}))
v676		((({hex4}:){6})(:{hex4}{1}))
v677		((({hex4}:){7})(:))
v67		({v670}|{v671}|{v672}|{v673}|{v674}|{v675}|{v676}|{v677})
v660		((:)((:{hex4}){6}))
v661		((({hex4}:){1})((:{hex4}){5}))
v662		((({hex4}:){2})((:{hex4}){4}))
v663		((({hex4}:){3})((:{hex4}){3}))
v664		((({hex4}:){4})((:{hex4}){2}))
v665		((({hex4}:){5})((:{hex4}){1}))
v666		((({hex4}:){6})(:))
v66		({v660}|{v661}|{v662}|{v663}|{v664}|{v665}|{v666})
v650		((:)((:{hex4}){5}))
v651		((({hex4}:){1})((:{hex4}){4}))
v652		((({hex4}:){2})((:{hex4}){3}))
v653		((({hex4}:){3})((:{hex4}){2}))
v654		((({hex4}:){4})(:{hex4}{1}))
v655		((({hex4}:){5})(:))
v65		({v650}|{v651}|{v652}|{v653}|{v654}|{v655})
v640		((:)((:{hex4}){4}))
v641		((({hex4}:){1})((:{hex4}){3}))
v642		((({hex4}:){2})((:{hex4}){2}))
v643		((({hex4}:){3})((:{hex4}){1}))
v644		((({hex4}:){4})(:))
v64		({v640}|{v641}|{v642}|{v643}|{v644})
v630		((:)((:{hex4}){3}))
v631		((({hex4}:){1})((:{hex4}){2}))
v632		((({hex4}:){2})((:{hex4}){1}))
v633		((({hex4}:){3})(:))
v63		({v630}|{v631}|{v632}|{v633})
v620		((:)((:{hex4}){2}))
v621		((({hex4}:){1})((:{hex4}){1}))
v622		((({hex4}:){2})(:))
v62		({v620}|{v621}|{v622})
v610		((:)(:{hex4}{1}))
v611		((({hex4}:){1})(:))
v61		({v610}|{v611})
v60		(::)

macaddr		(([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2})
ip4addr		(([[:digit:]]{1,3}"."){3}([[:digit:]]{1,3}))
ip6addr		({v680}|{v67}|{v66}|{v65}|{v64}|{v63}|{v62}|{v61}|{v60})

addrstring	({macaddr}|{ip4addr}|{ip6addr})

%option prefix="nft_"
%option reentrant
%option noyywrap
%option nounput
%option bison-bridge
%option bison-locations
%option debug
%option yylineno
%option nodefault
%option warn

%%

"=="			{ return EQ; }
"eq"			{ return EQ; }
"!="			{ return NEQ; }
"ne"			{ return NEQ; }
"<="			{ return LTE; }
"le"			{ return LTE; }
"<"			{ return LT; }
"lt"			{ return LT; }
">="			{ return GTE; }
"ge"			{ return GTE; }
">"			{ return GT; }
"gt"			{ return GT; }
","			{ return COMMA; }
"."			{ return DOT; }
":"			{ return COLON; }
";"			{ return SEMICOLON; }
"{"			{ return '{'; }
"}"			{ return '}'; }
"["			{ return '['; }
"]"			{ return ']'; }
"("			{ return '('; }
")"			{ return ')'; }
"<<"			{ return LSHIFT; }
"lshift"		{ return LSHIFT; }
">>"			{ return RSHIFT; }
"rshift"		{ return RSHIFT; }
"^"			{ return CARET; }
"xor"			{ return CARET; }
"&"			{ return AMPERSAND; }
"and"			{ return AMPERSAND; }
"|"			{ return '|'; }
"or"			{ return '|'; }
"!"			{ return NOT; }
"not"			{ return NOT; }
"/"			{ return SLASH; }
"-"			{ return DASH; }
"*"			{ return ASTERISK; }
"@"			{ return AT; }
"$"			{ return '$'; }
"="			{ return '='; }
"vmap"			{ return VMAP; }

"include"		{ return INCLUDE; }
"define"		{ return DEFINE; }

"describe"		{ return DESCRIBE; }

"hook"			{ return HOOK; }
"table"			{ return TABLE; }
"tables"		{ return TABLES; }
"chain"			{ return CHAIN; }
"rule"			{ return RULE; }
"sets"			{ return SETS; }
"set"			{ return SET; }
"element"		{ return ELEMENT; }
"map"			{ return MAP; }
"handle"		{ return HANDLE; }

"accept"		{ return ACCEPT; }
"drop"			{ return DROP; }
"continue"		{ return CONTINUE; }
"jump"			{ return JUMP; }
"goto"			{ return GOTO; }
"return"		{ return RETURN; }
"queue"			{ return QUEUE; }

"add"			{ return ADD; }
"insert"		{ return INSERT; }
"delete"		{ return DELETE; }
"list"			{ return LIST; }
"flush"			{ return FLUSH; }
"rename"		{ return RENAME; }

"position"		{ return POSITION; }

"constant"		{ return CONSTANT; }
"interval"		{ return INTERVAL; }
"elements"		{ return ELEMENTS; }

"counter"		{ return COUNTER; }
"packets"		{ return PACKETS; }
"bytes"			{ return BYTES; }

"log"			{ return LOG; }
"prefix"		{ return PREFIX; }
"group"			{ return GROUP; }
"snaplen"		{ return SNAPLEN; }
"queue-threshold"	{ return QUEUE_THRESHOLD; }

"limit"			{ return LIMIT; }
"rate"			{ return RATE; }

"nanosecond"		{ return NANOSECOND; }
"microsecond"		{ return MICROSECOND; }
"millisecond"		{ return MILLISECOND; }
"second"		{ return SECOND; }
"minute"		{ return MINUTE; }
"hour"			{ return HOUR; }
"day"			{ return DAY; }
"week"			{ return WEEK; }

"reject"		{ return _REJECT; }

"snat"			{ return SNAT; }
"dnat"			{ return DNAT; }

"ll"			{ return LL_HDR; }
"nh"			{ return NETWORK_HDR; }
"th"			{ return TRANSPORT_HDR; }

"bridge"		{ return BRIDGE; }

"ether"			{ return ETHER; }
"saddr"			{ return SADDR; }
"daddr"			{ return DADDR; }
"type"			{ return TYPE; }

"vlan"			{ return VLAN; }
"id"			{ return ID; }
"cfi"			{ return CFI; }
"pcp"			{ return PCP; }

"arp"			{ return ARP; }
"htype"			{ return HTYPE; }
"ptype"			{ return PTYPE; }
"hlen"			{ return HLEN; }
"plen"			{ return PLEN; }
"operation"		{ return OPERATION; }

"ip"			{ return IP; }
"version"		{ return VERSION; }
"hdrlength"		{ return HDRLENGTH; }
"tos"			{ return TOS; }
"length"		{ return LENGTH; }
"frag-off"		{ return FRAG_OFF; }
"ttl"			{ return TTL; }
"protocol"		{ return PROTOCOL; }
"checksum"		{ return CHECKSUM; }

"icmp"			{ return ICMP; }
"code"			{ return CODE; }
"sequence"		{ return SEQUENCE; }
"gateway"		{ return GATEWAY; }
"mtu"			{ return MTU; }

"ip6"			{ return IP6; }
"priority"		{ return PRIORITY; }
"flowlabel"		{ return FLOWLABEL; }
"nexthdr"		{ return NEXTHDR; }
"hoplimit"		{ return HOPLIMIT; }

"icmpv6"		{ return ICMP6; }
"param-problem"		{ return PPTR; }
"max-delay"		{ return MAXDELAY; }

"ah"			{ return AH; }
"reserved"		{ return RESERVED; }
"spi"			{ return SPI; }

"esp"			{ return ESP; }

"comp"			{ return COMP; }
"flags"			{ return FLAGS; }
"cpi"			{ return CPI; }

"udp"			{ return UDP; }
"sport"			{ return SPORT; }
"dport"			{ return DPORT; }

"tcp"			{ return TCP; }
"ackseq"		{ return ACKSEQ; }
"doff"			{ return DOFF; }
"window"		{ return WINDOW; }
"urgptr"		{ return URGPTR; }

"dccp"			{ return DCCP; }

"sctp"			{ return SCTP; }
"vtag"			{ return VTAG; }

"rt"			{ return RT; }
"rt0"			{ return RT0; }
"rt2"			{ return RT2; }
"seg-left"		{ return SEG_LEFT; }
"addr"			{ return ADDR; }

"hbh"			{ return HBH; }

"frag"			{ return FRAG; }
"reserved2"		{ return RESERVED2; }
"more-fragments"	{ return MORE_FRAGMENTS; }

"dst"			{ return DST; }

"mh"			{ return MH; }

"meta"			{ return META; }
"mark"			{ return MARK; }
"iif"			{ return IIF; }
"iifname"		{ return IIFNAME; }
"iiftype"		{ return IIFTYPE; }
"oif"			{ return OIF; }
"oifname"		{ return OIFNAME; }
"oiftype"		{ return OIFTYPE; }
"skuid"			{ return SKUID; }
"skgid"			{ return SKGID; }
"nftrace"		{ return NFTRACE; }
"rtclassid"		{ return RTCLASSID; }

"ct"			{ return CT; }
"direction"		{ return DIRECTION; }
"state"			{ return STATE; }
"status"		{ return STATUS; }
"expiration"		{ return EXPIRATION; }
"helper"		{ return HELPER; }
"l3proto"		{ return L3PROTOCOL; }
"proto-src"		{ return PROTO_SRC; }
"proto-dst"		{ return PROTO_DST; }

{addrstring}		{
				yylval->string = xstrdup(yytext);
				return STRING;
			}

{decstring}		{
				errno = 0;
				yylval->val = strtoull(yytext, NULL, 0);
				if (errno != 0)
					BUG();
				return NUM;
			}

{hexstring}		{
				errno = 0;
				yylval->val = strtoull(yytext, NULL, 0);
				if (errno != 0)
					BUG();
				return NUM;
			}

{quotedstring}		{
				yytext[yyleng - 1] = '\0';
				yylval->string = xstrdup(yytext + 1);
				return QUOTED_STRING;
			}

{string}		{
				yylval->string = xstrdup(yytext);
				return STRING;
			}

\\{newline}		{
				reset_pos(yyget_extra(yyscanner), yylloc);
			}

{newline}		{
				reset_pos(yyget_extra(yyscanner), yylloc);
				return NEWLINE;
			}

{tab}			{
				/*
				 * Compensate difference between visible length
				 * and real length.
				 */
				struct parser_state *state = yyget_extra(yyscanner);
				unsigned int diff;

				diff = TABSIZE - strlen("\t");
				diff -= (state->indesc->column -
					 strlen("\t") - 1) % TABSIZE;

				update_pos(state, yylloc, diff);
			}

{space}+
{comment}

<<EOF>> 		{
				update_pos(yyget_extra(yyscanner), yylloc, 1);
				scanner_pop_buffer(yyscanner);
				if (YY_CURRENT_BUFFER == NULL)
					return TOKEN_EOF;
			}

.			{ return JUNK; }

%%

static void scanner_pop_buffer(yyscan_t scanner)
{
	struct parser_state *state = yyget_extra(scanner);

	yypop_buffer_state(scanner);
	state->indesc = &state->indescs[--state->indesc_idx - 1];
}

static struct error_record *scanner_push_file(void *scanner, const char *filename,
					      FILE *f, const struct location *loc)
{
	struct parser_state *state = yyget_extra(scanner);
	YY_BUFFER_STATE b;

	if (state->indesc_idx == MAX_INCLUDE_DEPTH) {
		fclose(f);
		return error(loc, "Include nested too deeply, max %u levels",
			     MAX_INCLUDE_DEPTH);
	}

	b = yy_create_buffer(f, YY_BUF_SIZE, scanner);
	yypush_buffer_state(b, scanner);

	state->indesc = &state->indescs[state->indesc_idx++];
	if (loc != NULL)
		state->indesc->location = *loc;
	state->indesc->type	= INDESC_FILE;
	state->indesc->name	= xstrdup(filename);
	state->indesc->fd	= fileno(f);
	init_pos(state);
	return NULL;
}

int scanner_read_file(void *scanner, const char *filename,
		      const struct location *loc)
{
	struct parser_state *state = yyget_extra(scanner);
	struct error_record *erec;
	FILE *f;

	f = fopen(filename, "r");
	if (f == NULL) {
		erec = error(loc, "Could not open file \"%s\": %s\n",
			     filename, strerror(errno));
		goto err;
	}

	erec = scanner_push_file(scanner, filename, f, loc);
	if (erec != NULL)
		goto err;
	return 0;

err:
	erec_queue(erec, state->msgs);
	return -1;
}

int scanner_include_file(void *scanner, const char *filename,
			 const struct location *loc)
{
	struct parser_state *state = yyget_extra(scanner);
	struct error_record *erec;
	char buf[PATH_MAX];
	const char *name = buf;
	unsigned int i;
	FILE *f;

	f = NULL;
	for (i = 0; i < INCLUDE_PATHS_MAX; i++) {
		if (include_paths[i] == NULL)
			break;
		snprintf(buf, sizeof(buf), "%s/%s", include_paths[i], filename);
		f = fopen(buf, "r");
		if (f != NULL)
			break;
	}
	if (f == NULL) {
		f = fopen(filename, "r");
		if (f == NULL) {
			erec = error(loc, "Could not open file \"%s\": %s\n",
				     filename, strerror(errno));
			goto err;
		}
		name = filename;
	}

	erec = scanner_push_file(scanner, name, f, loc);
	if (erec != NULL)
		goto err;
	return 0;

err:
	erec_queue(erec, state->msgs);
	return -1;
}

void scanner_push_buffer(void *scanner, const struct input_descriptor *indesc,
			 const char *buffer)
{
	struct parser_state *state = yyget_extra(scanner);
	YY_BUFFER_STATE b;

	state->indesc = &state->indescs[state->indesc_idx++];
	memcpy(state->indesc, indesc, sizeof(*state->indesc));
	state->indesc->data = buffer;

	b = yy_scan_string(buffer, scanner);
	assert(b != NULL);
	init_pos(state);
}

void *scanner_init(struct parser_state *state)
{
	yyscan_t scanner;

	state->indesc = state->indescs;

	yylex_init(&scanner);
	yyset_extra(state, scanner),
	yyset_out(NULL, scanner);

	return scanner;
}

void scanner_destroy(struct parser_state *scanner)
{
	struct parser_state *state = yyget_extra(scanner);

	/* Can't free indesc name - locations might still be in use */
	while (state->indesc_idx--)
		yypop_buffer_state(scanner);

	yylex_destroy(scanner);
}
