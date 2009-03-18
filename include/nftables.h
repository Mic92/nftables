#ifndef _NFTABLES_H
#define _NFTABLES_H

#include <stdbool.h>
#include <stdarg.h>
#include <utils.h>

enum numeric_level {
	NUMERIC_NONE,
	NUMERIC_ADDR,
	NUMERIC_ALL,
};

#define INCLUDE_PATHS_MAX	16

extern unsigned int numeric_output;
extern const char *include_paths[INCLUDE_PATHS_MAX];

struct parser_state;
extern int cli_init(void *scanner, struct parser_state *state);
extern void cli_exit(void);
extern void cli_display(const char *fmt, va_list ap) __fmtstring(1, 0);

enum nftables_exit_codes {
	NFT_EXIT_SUCCESS	= 0,
	NFT_EXIT_FAILURE	= 1,
	NFT_EXIT_NOMEM		= 2,
};

struct input_descriptor;
struct location {
	const struct input_descriptor		*indesc;
	union {
		struct {
			off_t			token_offset;
			off_t			line_offset;

			unsigned int		first_line;
			unsigned int		last_line;
			unsigned int		first_column;
			unsigned int		last_column;
		};
		struct {
			struct nl_object	*nl_obj;
		};
	};
};

extern const struct location internal_location;

/**
 * enum input_descriptor_types
 *
 * @INDESC_INVALID:	invalid
 * @INDESC_INTERNAL:	dummy type for internally generated messages
 * @INDESC_BUFFER:	buffer (command line arguments)
 * @INDESC_FILE:	file
 * @INDESC_CLI:		command line interface
 * @INDESC_NETLINK:	received from netlink
 */
enum input_descriptor_types {
	INDESC_INVALID,
	INDESC_INTERNAL,
	INDESC_BUFFER,
	INDESC_FILE,
	INDESC_CLI,
	INDESC_NETLINK,
};

/**
 * struct input_descriptor
 *
 * @location:		location, used for include statements
 * @type:		input descriptor type
 * @name:		name describing the input
 * @union:		buffer or file descriptor, depending on type
 * @lineno:		current line number in the input
 * @column:		current column in the input
 * @token_offset:	offset of the current token to the beginning
 * @line_offset:	offset of the current line to the beginning
 */
struct input_descriptor {
	struct location			location;
	enum input_descriptor_types	type;
	const char			*name;
	union {
		const char		*data;
		int			fd;
	};
	unsigned int			lineno;
	unsigned int			column;
	off_t				token_offset;
	off_t				line_offset;
};

#endif /* _NFTABLES_H */
