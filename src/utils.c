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
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <nftables.h>
#include <utils.h>

void __noreturn __memory_allocation_error(const char *filename, uint32_t line)
{
	fprintf(stderr, "%s:%u: Memory allocation failure\n", filename, line);
	exit(NFT_EXIT_NOMEM);
}

void xfree(const void *ptr)
{
	free((void *)ptr);
}

void *xmalloc(size_t size)
{
	void *ptr;

	ptr = malloc(size);
	if (ptr == NULL)
		memory_allocation_error();
	return ptr;
}

void *xrealloc(void *ptr, size_t size)
{
	ptr = realloc(ptr, size);
	if (ptr == NULL && size != 0)
		memory_allocation_error();
	return ptr;
}

void *xzalloc(size_t size)
{
	void *ptr;

	ptr = xmalloc(size);
	memset(ptr, 0, size);
	return ptr;
}

char *xstrdup(const char *s)
{
	char *res;

	assert(s != NULL);
	res = strdup(s);
	if (res == NULL)
		memory_allocation_error();
	return res;
}
