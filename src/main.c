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

unsigned int numeric_output;
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
	OPT_INVALID		= '?',
};

#define OPTSTRING	"hvf:iI:vn"

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
"  				When specified twice, also show Internet protocols,\n"
"				Internet services, user IDs and group IDs numerically.\n"
"  -i/--includepath <directory>	Add <directory> to the paths searched for include files.\n"
#ifdef DEBUG
"  --debug <level>		Specify debugging level\n"
#endif
"\n",
	name);
}

static const struct input_descriptor indesc_cmdline = {
	.type	= INDESC_BUFFER,
	.name	= "<cmdline>",
};

int main(int argc, char * const *argv)
{
	struct parser_state state;
	struct eval_ctx ctx;
	void *scanner;
	LIST_HEAD(msgs);
	char *buf = NULL, *filename = NULL;
	unsigned int len;
	bool interactive = false;
	int i, val;
	int ret;

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
			debug_level |= DEBUG_NETLINK;
			break;
#endif
		case OPT_INVALID:
			exit(NFT_EXIT_FAILURE);
		}
	}

	parser_init(&state, &msgs);
	scanner = scanner_init(&state);

	if (optind != argc) {
		for (len = 0, i = optind; i < argc; i++)
			len += strlen(argv[i]) + strlen(" ");

		buf = xzalloc(len + 1);
		for (i = optind; i < argc; i++) {
			strcat(buf, argv[i]);
			if (i + 1 < argc)
				strcat(buf, " ");
		}

		scanner_push_buffer(scanner, &indesc_cmdline, buf);
	} else if (filename != NULL) {
		if (scanner_read_file(scanner, filename, &internal_location) < 0)
			goto out;
	} else if (interactive) {
		cli_init(scanner, &state);
	} else {
		fprintf(stderr, "%s: no command specified\n", argv[0]);
		exit(NFT_EXIT_FAILURE);
	}

	ret = nft_parse(scanner, &state);
	if (ret < 0)
		goto out;

	memset(&ctx, 0, sizeof(ctx));
	ctx.msgs = &msgs;
	if (evaluate(&ctx, &state.cmds) < 0)
		goto out;

	{
		struct netlink_ctx ctx;
		struct cmd *cmd, *next;

		list_for_each_entry_safe(cmd, next, &state.cmds, list) {
			memset(&ctx, 0, sizeof(ctx));
			ctx.msgs = &msgs;
			init_list_head(&ctx.list);
			if (do_command(&ctx, cmd) < 0)
				goto out;
			list_del(&cmd->list);
			cmd_free(cmd);
		}
	}
out:
	scanner_destroy(scanner);
	scope_release(&state.top_scope);
	erec_print_list(stdout, &msgs);

	xfree(buf);
	return 0;
}
