#ifndef _NFT_CLI_H_
#define _NFT_CLI_H_

#include <config.h>

struct parser_state;
#ifdef HAVE_LIBREADLINE
extern int cli_init(struct parser_state *state);
#else
static inline int cli_init(struct parser_state *state)
{
        return -1;
}
#endif
extern void cli_exit(void);
extern void cli_display(const char *fmt, va_list ap) __fmtstring(1, 0);

#endif
