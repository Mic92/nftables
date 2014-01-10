/*
 * Copyright (c) 2008 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Development of this code funded by Astaro AG (http://www.astaro.com/)
 */

#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include <netlink.h>
#include <gmputil.h>
#include <erec.h>

static const struct input_descriptor internal_indesc = {
	.type	= INDESC_INTERNAL,
	.name	= "internal",
};

const struct location internal_location = {
	.indesc	= &internal_indesc,
};

static const char *error_record_names[] = {
	[EREC_INFORMATIONAL]	= NULL,
	[EREC_WARNING]		= "Warning",
	[EREC_ERROR]		= "Error"
};

void erec_add_location(struct error_record *erec, const struct location *loc)
{
	assert(erec->num_locations < EREC_LOCATIONS_MAX);
	erec->locations[erec->num_locations++] = *loc;
}

static void erec_destroy(struct error_record *erec)
{
	xfree(erec->msg);
	xfree(erec);
}

struct error_record *erec_vcreate(enum error_record_types type,
				  const struct location *loc,
				  const char *fmt, va_list ap)
{
	struct error_record *erec;

	erec = xmalloc(sizeof(*erec));
	erec->type		= type;
	erec->num_locations	= 0;
	erec_add_location(erec, loc);

	gmp_vasprintf(&erec->msg, fmt, ap);
	return erec;
}

struct error_record *erec_create(enum error_record_types type,
				 const struct location *loc,
				 const char *fmt, ...)
{
	struct error_record *erec;
	va_list ap;

	va_start(ap, fmt);
	erec = erec_vcreate(type, loc, fmt, ap);
	va_end(ap);
	return erec;
}

void erec_print(FILE *f, const struct error_record *erec)
{
	const struct location *loc = erec->locations, *iloc;
	const struct input_descriptor *indesc = loc->indesc, *tmp;
	const char *line = NULL; /* silence gcc */
	char buf[1024];
	unsigned int i, end;
	int l, ret;

	switch (indesc->type) {
	case INDESC_BUFFER:
	case INDESC_CLI:
		line = indesc->data;
		break;
	case INDESC_FILE:
		memset(buf, 0, sizeof(buf));
		lseek(indesc->fd, loc->line_offset, SEEK_SET);
		ret = read(indesc->fd, buf, sizeof(buf) - 1);
		if (ret > 0)
			*strchrnul(buf, '\n') = '\0';
		line = buf;
		break;
	case INDESC_INTERNAL:
	case INDESC_NETLINK:
		break;
	default:
		BUG("invalid input descriptor type %u\n", indesc->type);
	}

	if (indesc->type == INDESC_NETLINK) {
		fprintf(f, "%s: ", indesc->name);
		if (error_record_names[erec->type])
			fprintf(f, "%s: ", error_record_names[erec->type]);
		fprintf(f, "%s\n", erec->msg);
		for (l = 0; l < (int)erec->num_locations; l++) {
			loc = &erec->locations[l];
			netlink_dump_expr(loc->nle);
		}
		fprintf(f, "\n");
	} else {
		if (indesc->location.indesc != NULL) {
			const char *prefix = "In file included from";
			iloc = &indesc->location;
			for (tmp = iloc->indesc; tmp != NULL; tmp = iloc->indesc) {
				fprintf(f, "%s %s:%u:%u-%u:\n", prefix,
					tmp->name,
					iloc->first_line, iloc->first_column,
					iloc->last_column);
				prefix = "                 from";
				iloc = &tmp->location;
			}
		}
		if (indesc->name != NULL)
			fprintf(f, "%s:%u:%u-%u: ", indesc->name,
				loc->first_line, loc->first_column,
				loc->last_column);
		if (error_record_names[erec->type])
			fprintf(f, "%s: ", error_record_names[erec->type]);
		fprintf(f, "%s\n", erec->msg);

		if (indesc->type != INDESC_INTERNAL)
			fprintf(f, "%s\n", line);

		memset(buf, ' ', sizeof(buf));
		end = 0;
		for (l = erec->num_locations - 1; l >= 0; l--) {
			loc = &erec->locations[l];
			for (i = loc->first_column ? loc->first_column - 1 : 0;
			     i < loc->last_column; i++)
				buf[i] = l ? '~' : '^';
			end = max(end, loc->last_column);
		}
		buf[end] = '\0';
		fprintf(f, "%s", buf);
	}
	fprintf(f, "\n");
}

void erec_print_list(FILE *f, struct list_head *list)
{
	struct error_record *erec, *next;

	list_for_each_entry_safe(erec, next, list, list) {
		list_del(&erec->list);
		erec_print(f, erec);
		erec_destroy(erec);
	}
}
