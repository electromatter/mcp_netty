#ifndef MCP_NETTY_FRAMER_H
#define MCP_NETTY_FRAMER_H

/* for ssize_t */
#include <sys/types.h>

struct mcp_parse;
struct netty_framer;
struct client_info;

struct netty_framer *netty_framer_new(void);
void netty_framer_free(struct netty_framer *framer);

int netty_set_frame_limit(struct netty_framer *framer, size_t size);
int netty_set_cipher(struct netty_framer *framer, const void *secret, size_t size);
int netty_set_threshold(struct netty_framer *framer, ssize_t threshold);
int netty_set_level(struct netty_framer *framer, int level);

void netty_start_frame(struct mcp_parse *frame, struct fbuf *src, struct netty_framer *framer);
int netty_pack_frame(struct fbuf *dest, const void *data, size_t size, struct netty_framer *framer);

#endif
