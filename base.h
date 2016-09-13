/* mcp_modern/base.h
 *
 * Copyright (c) 2016 Eric Chai <electromatter@gmail.com>
 * All rights reserved.
 *
 * This software may be modified and distributed under the terms
 * of the ISC license. See the LICENSE file for details.
 */

#ifndef MCP_MODERN_BASE_H
#define MCP_MODERN_BASE_H

#include <mcp_base/mcp.h>

enum mcm_mode {
	MCM_HANDSHAKE			= 0,
	MCM_STATUS			= 1,
	MCM_LOGIN			= 2,
};

enum mcm_id {
	/* Handshake server-bound */
	MCM_HANDSHAKE_START		= 0x00,

	/* Status server-bound */
	MCM_STATUS_REQUEST		= 0x00,

	/* Status client-bound */
	MCM_STATUS_RESPONSE		= 0x00,

	/* Status bidirectional */
	MCM_STATUS_PING			= 0x01,

	/* Login server-bound */
	MCM_LOGIN_START			= 0x00,
	MCM_LOGIN_RESPONSE		= 0x01,
	/* Login client-bound */
	MCM_LOGIN_DISCONNECT		= 0x00,
	MCM_LOGIN_REQUEST		= 0x01,
	MCM_LOGIN_SUCCESS		= 0x02,
	MCM_LOGIN_SET_COMPRESSION	= 0x03
};

/* Handshake server-bound */
struct mcm_handshake_start {
	enum mcm_id id;
	mcp_varint_t version;
	size_t hostname_length;
	const char *hostname;
	uint16_t port;
	mcp_varint_t next_state;
};

/* Status client-bound */
struct mcm_status_response {
	enum mcm_id id;
	size_t motd_length;
	const char *motd;
};

/* Status bidirectional */
struct mcm_status_ping {
	enum mcm_id id;
	uint64_t time;
};

/* Login server-bound */
struct mcm_login_start {
	enum mcm_id id;
	size_t name_length;
	const char *name;
};

struct mcm_login_response {
	enum mcm_id id;
	size_t shared_length;
	const void *shared;
	size_t verify_length;
	const void *verify;
};

/* Login client-bound */
struct mcm_login_disconnect {
	enum mcm_id id;
	size_t reason_length;
	const char *reason;
};

struct mcm_login_request {
	enum mcm_id id;
	size_t serverid_length;
	const char *serverid;
	size_t pubkey_length;
	const void *pubkey;
	size_t verify_length;
	const void *verify;
};

struct mcm_login_success {
	enum mcm_id id;
	size_t uuid_length;
	const char *uuid;
	size_t name_length;
	const char *name;
};

struct mcm_login_set_compression {
	enum mcm_id id;
	mcp_varint_t threshold;
};

/* Polymorphic types */
union mcm_any {
	enum mcm_id id;
	struct mcm_handshake_start handshake_start;
	struct mcm_status_response status_response;
	struct mcm_status_ping status_ping;
	struct mcm_login_start login_start;
	struct mcm_login_response login_response;
	struct mcm_login_disconnect login_disconnect;
	struct mcm_login_request login_request;
	struct mcm_login_success login_success;
	struct mcm_login_set_compression login_set_compression;
};

/* -*- DIRECT INTERFACE -*- */
void mcm_server_parse_handshake(union mcm_any *dest, enum mcm_id id, struct mcp_parse *src);

void mcm_server_parse_status(union mcm_any *dest, enum mcm_id id, struct mcp_parse *src);
int mcm_server_pack_status(struct fbuf *dest, const union mcm_any *src);

void mcm_server_parse_login(union mcm_any *dest, enum mcm_id id, struct mcp_parse *src);
int mcm_server_pack_login(struct fbuf *dest, const union mcm_any *src);

int mcm_client_pack_hanshake(struct fbuf *dest, const union mcm_any *src);

void mcm_client_parse_status(union mcm_any *dest, enum mcm_id id, struct mcp_parse *src);
int mcm_client_pack_status(struct fbuf *dest, const union mcm_any *src);

void mcm_client_parse_login(union mcm_any *dest, enum mcm_id id, struct mcp_parse *src);
int mcm_client_pack_login(struct fbuf *dest, const union mcm_any *src);

#endif
