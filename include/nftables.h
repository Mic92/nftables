#ifndef NFTABLES_NFTABLES_H
#define NFTABLES_NFTABLES_H

#include <stdbool.h>
#include <stdarg.h>
#include <utils.h>

enum numeric_level {
	NUMERIC_NONE,
	NUMERIC_ADDR,
	NUMERIC_PORT,
	NUMERIC_ALL,
};

enum debug_level {
	DEBUG_SCANNER		= 0x1,
	DEBUG_PARSER		= 0x2,
	DEBUG_EVALUATION	= 0x4,
	DEBUG_NETLINK		= 0x8,
	DEBUG_SEGTREE		= 0x10,
	DEBUG_MNL		= 0x20,
};

#define INCLUDE_PATHS_MAX	16

extern unsigned int numeric_output;
extern unsigned int handle_output;
extern unsigned int debug_level;
extern const char *include_paths[INCLUDE_PATHS_MAX];

struct parser_state;
extern int cli_init(struct parser_state *state);
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
			void			*nle;
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

int nft_run(void *scanner, struct parser_state *state, struct list_head *msgs);

#endif /* NFTABLES_NFTABLES_H */
