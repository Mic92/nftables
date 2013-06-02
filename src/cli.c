/*
 * Asynchronous readline-based interactive interface
 *
 * Actually not asynchronous so far, but intended to be.
 *
 * Copyright (c) 2008 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Development of this code funded by Astaro AG (http://www.astaro.com/)
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <readline/readline.h>
#include <readline/history.h>

#include <nftables.h>
#include <parser.h>
#include <erec.h>
#include <utils.h>

#define CMDLINE_HISTFILE	".nft.history"

static const struct input_descriptor indesc_cli = {
	.type	= INDESC_CLI,
	.name   = "<cli>",
};

static struct parser_state *state;
static void *scanner;

static char histfile[PATH_MAX];
static char *multiline;
static bool eof;

static char *cli_append_multiline(char *line)
{
	bool complete = false;
	size_t len;
	char *s;

	if (line == NULL && multiline == NULL) {
		eof = true;
		return NULL;
	}

	len = strlen(line);
	if (line[len - 1] == '\\') {
		line[len - 1] = '\0';
		len--;
	} else if (multiline == NULL)
		return line;
	else
		complete = 1;

	if (multiline == NULL) {
		multiline = line;
		rl_save_prompt();
		rl_clear_message();
	} else {
		len += strlen(multiline);
		s = xmalloc(len + 1);
		snprintf(s, len + 1, "%s%s", multiline, line);
		xfree(multiline);
		multiline = s;
	}
	line = NULL;

	if (complete) {
		line = multiline;
		multiline = NULL;
		rl_restore_prompt();
	}
	return line;
}

static void cli_complete(char *line)
{
	const HIST_ENTRY *hist;
	const char *c;
	LIST_HEAD(msgs);

	line = cli_append_multiline(line);
	if (line == NULL) {
		printf("\n");
		cli_exit();
		return;
	}

	for (c = line; *c != '\0'; c++)
		if (!isspace(*c))
			break;
	if (*c == '\0')
		return;

	if (!strcmp(line, "quit")) {
		cli_exit();
		exit(0);
	}

	/* avoid duplicate history entries */
	hist = history_get(history_length);
	if (hist == NULL || strcmp(hist->line, line))
		add_history(line);

	parser_init(state, &msgs);
	scanner_push_buffer(scanner, &indesc_cli, line);
	nft_run(scanner, state, &msgs);
	erec_print_list(stdout, &msgs);
	xfree(line);
}

static char **cli_completion(const char *text, int start, int end)
{
	return NULL;
}

void __fmtstring(1, 0) cli_display(const char *fmt, va_list ap)
{
	int point, end;
	char *buf;

	point = rl_point;
	end   = rl_end;
	rl_point = rl_end = 0;

	rl_save_prompt();
	rl_clear_message();

	if (vasprintf(&buf, fmt, ap) < 0)
		fprintf(rl_outstream, "cli_display: out of memory\n");
	else {
		fprintf(rl_outstream, "%s\n", buf);
		xfree(buf);
	}

	rl_restore_prompt();

	rl_point = point;
	rl_end   = end;
	rl_forced_update_display();
}

int cli_init(struct parser_state *_state)
{
	const char *home;

	rl_readline_name = "nft";
	rl_instream  = stdin;
	rl_outstream = stdout;

	rl_callback_handler_install("nft> ", cli_complete);
	rl_attempted_completion_function = cli_completion;

	home = getenv("HOME");
	if (home == NULL)
		home = "";
	snprintf(histfile, sizeof(histfile), "%s/%s", home, CMDLINE_HISTFILE);

	read_history(histfile);
	history_set_pos(history_length);

	state	= _state;
	scanner = scanner_init(state);

	while (!eof)
		rl_callback_read_char();
	return 0;
}

void cli_exit(void)
{
	rl_callback_handler_remove();
	rl_deprep_terminal();
	write_history(histfile);
}
