/*
 * Copyright (c) 2008 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Development of this code funded by Astaro AG (http://www.astaro.com/)
 */

#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/types.h>

#include <nftables.h>
#include <utils.h>
#include <parser.h>
#include <rule.h>
#include <netlink.h>
#include <erec.h>
#include <mnl.h>

unsigned int numeric_output;
unsigned int handle_output;
#ifdef DEBUG
unsigned int debug_level;
#endif

const char *include_paths[INCLUDE_PATHS_MAX] = { DEFAULT_INCLUDE_PATH };
static unsigned int num_include_paths = 1;

enum opt_vals {
	OPT_HELP		= 'h',
	OPT_VERSION		= 'v',
	OPT_FILE		= 'f',
	OPT_INTERACTIVE		= 'i',
	OPT_INCLUDEPATH		= 'I',
	OPT_NUMERIC		= 'n',
	OPT_DEBUG		= 'd',
	OPT_HANDLE_OUTPUT	= 'a',
	OPT_INVALID		= '?',
};

#define OPTSTRING	"hvf:iI:vna"

static const struct option options[] = {
	{
		.name		= "help",
		.val		= OPT_HELP,
	},
	{
		.name		= "version",
		.val		= OPT_VERSION,
	},
	{
		.name		= "file",
		.val		= OPT_FILE,
		.has_arg	= 1,
	},
	{
		.name		= "interactive",
		.val		= OPT_INTERACTIVE,
	},
	{
		.name		= "numeric",
		.val		= OPT_NUMERIC,
	},
	{
		.name		= "includepath",
		.val		= OPT_INCLUDEPATH,
		.has_arg	= 1,
	},
#ifdef DEBUG
	{
		.name		= "debug",
		.val		= OPT_DEBUG,
		.has_arg	= 1,
	},
#endif
	{
		.name		= "handle",
		.val		= OPT_HANDLE_OUTPUT,
	},
	{
		.name		= NULL
	}
};

static void show_help(const char *name)
{
	printf(
"Usage: %s [ options ] [ cmds... ]\n"
"\n"
"Options:\n"
"  -h/--help			Show this help\n"
"  -v/--version			Show version information\n"
"\n"
"  -f/--file <filename>		Read input from <filename>\n"
"  -i/--interactive		Read input from interactive CLI\n"
"\n"
"  -n/--numeric			When specified once, show network addresses numerically.\n"
"  				When specified twice, also show Internet services,\n"
"				user IDs and group IDs numerically.\n"
"				When specified thrice, also show protocols numerically.\n"
"  -a/--handle			Output rule handle.\n"
"  -I/--includepath <directory>	Add <directory> to the paths searched for include files.\n"
#ifdef DEBUG
"  --debug <level [,level...]>	Specify debugging level (scanner, parser, eval, netlink, mnl, segtree, all)\n"
#endif
"\n",
	name);
}

#ifdef DEBUG
static const struct {
	const char		*name;
	enum debug_level	level;
} debug_param[] = {
	{
		.name		= "scanner",
		.level		= DEBUG_SCANNER,
	},
	{
		.name		= "parser",
		.level		= DEBUG_PARSER,
	},
	{
		.name		= "eval",
		.level		= DEBUG_EVALUATION,
	},
	{
		.name		= "netlink",
		.level		= DEBUG_NETLINK,
	},
	{
		.name		= "mnl",
		.level		= DEBUG_MNL,
	},
	{
		.name		= "segtree",
		.level		= DEBUG_SEGTREE,
	},
	{
		.name		= "all",
		.level		= ~0,
	},
};
#endif

static const struct input_descriptor indesc_cmdline = {
	.type	= INDESC_BUFFER,
	.name	= "<cmdline>",
};

static int nft_netlink(struct parser_state *state, struct list_head *msgs)
{
	struct netlink_ctx ctx;
	struct cmd *cmd, *next;
	struct mnl_err *err, *tmp;
	LIST_HEAD(err_list);
	uint32_t batch_seqnum;
	int ret = 0;

	batch_seqnum = mnl_batch_begin();
	list_for_each_entry(cmd, &state->cmds, list) {
		memset(&ctx, 0, sizeof(ctx));
		ctx.msgs = msgs;
		ctx.seqnum = cmd->seqnum = mnl_seqnum_alloc();
		init_list_head(&ctx.list);
		ret = do_command(&ctx, cmd);
		if (ret < 0)
			return ret;
	}
	mnl_batch_end();

	if (mnl_batch_ready())
		ret = netlink_batch_send(&err_list);
	else {
		mnl_batch_reset();
		goto out;
	}

	list_for_each_entry_safe(err, tmp, &err_list, head) {
		list_for_each_entry(cmd, &state->cmds, list) {
			if (err->seqnum == cmd->seqnum ||
			    err->seqnum == batch_seqnum) {
				netlink_io_error(&ctx, &cmd->location,
						 "Could not process rule: %s",
						 strerror(err->err));
				if (err->seqnum == cmd->seqnum) {
					mnl_err_list_free(err);
					break;
				}
			}
		}
	}
out:
	list_for_each_entry_safe(cmd, next, &state->cmds, list) {
		list_del(&cmd->list);
		cmd_free(cmd);
	}

	return ret;
}

int nft_run(void *scanner, struct parser_state *state, struct list_head *msgs)
{
	struct eval_ctx ctx;
	int ret = 0;

	ret = nft_parse(scanner, state);
	if (ret != 0)
		return -1;

	memset(&ctx, 0, sizeof(ctx));
	ctx.msgs = msgs;
	if (evaluate(&ctx, &state->cmds) < 0)
		return -1;

	return nft_netlink(state, msgs);
}

int main(int argc, char * const *argv)
{
	struct parser_state state;
	void *scanner;
	LIST_HEAD(msgs);
	char *buf = NULL, *filename = NULL;
	unsigned int len;
	bool interactive = false;
	int i, val, rc = NFT_EXIT_SUCCESS;

	while (1) {
		val = getopt_long(argc, argv, OPTSTRING, options, NULL);
		if (val == -1)
			break;

		switch (val) {
		case OPT_HELP:
			show_help(argv[0]);
			exit(NFT_EXIT_SUCCESS);
		case OPT_VERSION:
			printf("%s v%s (%s)\n",
			       PACKAGE_NAME, PACKAGE_VERSION, RELEASE_NAME);
			exit(NFT_EXIT_SUCCESS);
		case OPT_FILE:
			filename = optarg;
			break;
		case OPT_INTERACTIVE:
			interactive = true;
			break;
		case OPT_INCLUDEPATH:
			if (num_include_paths >= INCLUDE_PATHS_MAX) {
				fprintf(stderr, "Too many include paths "
						"specified, max. %u\n",
					INCLUDE_PATHS_MAX - 1);
				exit(NFT_EXIT_FAILURE);
			}
			include_paths[num_include_paths++] = optarg;
			break;
		case OPT_NUMERIC:
			numeric_output++;
			break;
#ifdef DEBUG
		case OPT_DEBUG:
			for (;;) {
				unsigned int i;
				char *end;

				end = strchr(optarg, ',');
				if (end)
					*end = '\0';

				for (i = 0; i < array_size(debug_param); i++) {
					if (strcmp(debug_param[i].name, optarg))
						continue;
					debug_level |= debug_param[i].level;
					break;
				}

				if (i == array_size(debug_param)) {
					fprintf(stderr, "invalid debug parameter `%s'\n",
						optarg);
					exit(NFT_EXIT_FAILURE);
				}

				if (end == NULL)
					break;
				optarg = end + 1;
			}
			break;
#endif
		case OPT_HANDLE_OUTPUT:
			handle_output++;
			break;
		case OPT_INVALID:
			exit(NFT_EXIT_FAILURE);
		}
	}

	if (optind != argc) {
		for (len = 0, i = optind; i < argc; i++)
			len += strlen(argv[i]) + strlen(" ");

		buf = xzalloc(len + 1);
		for (i = optind; i < argc; i++) {
			strcat(buf, argv[i]);
			if (i + 1 < argc)
				strcat(buf, " ");
		}
		parser_init(&state, &msgs);
		scanner = scanner_init(&state);
		scanner_push_buffer(scanner, &indesc_cmdline, buf);
	} else if (filename != NULL) {
		parser_init(&state, &msgs);
		scanner = scanner_init(&state);
		if (scanner_read_file(scanner, filename, &internal_location) < 0)
			goto out;
	} else if (interactive) {
		cli_init(&state);
		return 0;
	} else {
		fprintf(stderr, "%s: no command specified\n", argv[0]);
		exit(NFT_EXIT_FAILURE);
	}

	if (nft_run(scanner, &state, &msgs) != 0)
		rc = NFT_EXIT_FAILURE;
out:
	scanner_destroy(scanner);
	erec_print_list(stdout, &msgs);

	xfree(buf);
	return rc;
}
