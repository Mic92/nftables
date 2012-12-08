#ifndef NFTABLES_UTILS_H
#define NFTABLES_UTILS_H

#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <list.h>
#include <gmp.h>

#define BITS_PER_BYTE	8

#ifdef DEBUG
#define pr_debug(fmt, arg...) gmp_printf(fmt, ##arg)
#else
#define pr_debug(fmt, arg...) ({ if (false) gmp_printf(fmt, ##arg); 0; })
#endif

#define __fmtstring(x, y)	__attribute__((format(printf, x, y)))
#if 0
#define __gmp_fmtstring(x, y)	__fmtstring(x, y)
#else
#define __gmp_fmtstring(x, y)
#endif

#define __init			__attribute__((constructor))
#define __exit			__attribute__((destructor))
#define __must_check		__attribute__((warn_unused_result))
#define __noreturn		__attribute__((__noreturn__))

#ifdef DEBUG
#define BUG(fmt, arg...)	({ fprintf(stderr, "BUG: " fmt, ##arg); assert(0); })
#else
#define BUG(fmt, arg...)	assert(0)
#endif

#define BUILD_BUG_ON(condition)	((void)sizeof(char[1 - 2*!!(condition)]))
#define BUILD_BUG_ON_ZERO(e)	(sizeof(char[1 - 2 * !!(e)]) - 1)

#define __must_be_array(a) \
	BUILD_BUG_ON_ZERO(__builtin_types_compatible_p(typeof(a), typeof(&a[0])))

#define container_of(ptr, type, member) ({			\
	typeof( ((type *)0)->member ) *__mptr = (ptr);		\
	(type *)( (char *)__mptr - offsetof(type,member) );})

#define field_sizeof(t, f)	(sizeof(((t *)NULL)->f))
#define array_size(arr)		(sizeof(arr) / sizeof((arr)[0]) + __must_be_array(arr))
#define div_round_up(n, d)	(((n) + (d) - 1) / (d))

#define min(x, y) ({				\
	typeof(x) _min1 = (x);			\
	typeof(y) _min2 = (y);			\
	(void) (&_min1 == &_min2);		\
	_min1 < _min2 ? _min1 : _min2; })

#define max(x, y) ({				\
	typeof(x) _max1 = (x);			\
	typeof(y) _max2 = (y);			\
	(void) (&_max1 == &_max2);		\
	_max1 > _max2 ? _max1 : _max2; })

extern void memory_allocation_error(void) __noreturn;

extern void xfree(const void *ptr);
extern void *xmalloc(size_t size);
extern void *xrealloc(void *ptr, size_t size);
extern void *xzalloc(size_t size);
extern char *xstrdup(const char *s);

#endif /* NFTABLES_UTILS_H */
