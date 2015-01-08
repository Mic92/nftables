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
#include <datatype.h>
#include <utils.h>

void mpz_bitmask(mpz_t rop, unsigned int width)
{
	mpz_set_ui(rop, 0);
	mpz_setbit(rop, width);
	mpz_sub_ui(rop, rop, 1);
}

void mpz_init_bitmask(mpz_t rop, unsigned int width)
{
	mpz_init2(rop, width);
	mpz_bitmask(rop, width);
}

void mpz_prefixmask(mpz_t rop, unsigned int width, unsigned int prefix_len)
{
	mpz_bitmask(rop, prefix_len);
	mpz_lshift_ui(rop, width - prefix_len);
}

void mpz_lshift_ui(mpz_t rop, unsigned int n)
{
	mpz_mul_2exp(rop, rop, n);
}

void mpz_rshift_ui(mpz_t rop, unsigned int n)
{
	mpz_tdiv_q_2exp(rop, rop, n);
}

#define mpz_get_type(type, endian, op)					\
({									\
 	type ret = 0;							\
	size_t cnt;							\
	mpz_export(&ret, &cnt, MPZ_LSWF, sizeof(ret), endian, 0, op);	\
	assert(cnt <= 1);						\
 	ret;								\
 })

uint64_t mpz_get_uint64(const mpz_t op)
{
	return mpz_get_type(uint64_t, MPZ_HOST_ENDIAN, op);
}

uint32_t mpz_get_uint32(const mpz_t op)
{
	return mpz_get_type(uint32_t, MPZ_HOST_ENDIAN, op);
}

uint16_t mpz_get_uint16(const mpz_t op)
{
	return mpz_get_type(uint16_t, MPZ_HOST_ENDIAN, op);
}

uint8_t mpz_get_uint8(const mpz_t op)
{
	return mpz_get_type(uint8_t, MPZ_HOST_ENDIAN, op);
}

uint64_t mpz_get_be64(const mpz_t op)
{
	return mpz_get_type(uint64_t, MPZ_BIG_ENDIAN, op);
}

uint32_t mpz_get_be32(const mpz_t op)
{
	return mpz_get_type(uint32_t, MPZ_BIG_ENDIAN, op);
}

uint16_t mpz_get_be16(const mpz_t op)
{
	return mpz_get_type(uint16_t, MPZ_BIG_ENDIAN, op);
}

void *mpz_export_data(void *data, const mpz_t op,
		      enum byteorder byteorder,
		      unsigned int len)
{
	enum mpz_word_order order;
	enum mpz_byte_order endian;

	switch (byteorder) {
	case BYTEORDER_BIG_ENDIAN:
	default:
		order = MPZ_MSWF;
		endian = MPZ_BIG_ENDIAN;
		break;
	case BYTEORDER_HOST_ENDIAN:
		order = MPZ_HWO;
		endian = MPZ_HOST_ENDIAN;
		break;
	}

	memset(data, 0, len);
	mpz_export(data, NULL, order, len, endian, 0, op);
	return data;
}

void mpz_import_data(mpz_t rop, const void *data,
		     enum byteorder byteorder,
		     unsigned int len)
{
	enum mpz_word_order order;
	enum mpz_byte_order endian;

	switch (byteorder) {
	case BYTEORDER_BIG_ENDIAN:
	default:
		order  = MPZ_MSWF;
		endian = MPZ_BIG_ENDIAN;
		break;
	case BYTEORDER_HOST_ENDIAN:
		order  = MPZ_HWO;
		endian = MPZ_HOST_ENDIAN;
		break;
	}

	mpz_import(rop, len, order, 1, endian, 0, data);
}

void mpz_switch_byteorder(mpz_t rop, unsigned int len)
{
	char data[len];

	mpz_export_data(data, rop, BYTEORDER_BIG_ENDIAN, len);
	mpz_import_data(rop, data, BYTEORDER_HOST_ENDIAN, len);
}

#ifndef HAVE_LIBGMP
/* mini-gmp doesn't have a gmp_printf so we use our own minimal
 * variant here which is able to format a single mpz_t.
 */
int mpz_printf(const char *f, const mpz_t value)
{
	int n = 0;
	while (*f) {
		if (*f != '%') {
			if (fputc(*f, stdout) != *f)
				return -1;

			++n;
		} else {
			unsigned long prec = 0;
			int base;
			size_t len;
			char *str;
			bool ok;

			if (*++f == '.')
				prec = strtoul(++f, (char**)&f, 10);

			if (*f++ != 'Z')
				return -1;

			if (*f == 'u')
				base = 10;
			else if (*f == 'x')
				base = 16;
			else
				return -1;

			len = mpz_sizeinbase(value, base);
			while (prec-- > len) {
				if (fputc('0', stdout) != '0')
					return -1;

				++n;
			}

			str = mpz_get_str(NULL, base, value);
			ok = str && fwrite(str, 1, len, stdout) == len;
			free(str);

			if (!ok)
				return -1;

			n += len;
		}
		++f;
	}
	return n;
}
#endif

static void *gmp_xrealloc(void *ptr, size_t old_size, size_t new_size)
{
	return xrealloc(ptr, new_size);
}

static void __init gmp_init(void)
{
	mp_set_memory_functions(xmalloc, gmp_xrealloc, NULL);
}
