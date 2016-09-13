/* mcp_modern/base/login.c
 *
 * Copyright (c) 2016 Eric Chai <electromatter@gmail.com>
 * All rights reserved.
 *
 * This software may be modified and distributed under the terms
 * of the ISC license. See the LICENSE file for details.
 */

#include "base.h"

#include <assert.h>

void mcm_server_parse_login(union mcm_any *dest, enum mcm_id id, struct mcp_parse *src)
{
	/* pass errors */
	if (!mcp_ok(src))
		return;

	dest->id = id;
	switch (id) {
	case MCM_LOGIN_START:
		dest->login_start.name = mcp_bytes(src, &dest->login_start.name_length);
		return;

	case MCM_LOGIN_RESPONSE:
		dest->login_response.shared =
				mcp_bytes(src, &dest->login_response.shared_length);
		dest->login_response.verify =
				mcp_bytes(src, &dest->login_response.verify_length);
		return;

	default:
		src->error = MCP_EINVAL;
		return;
	}
}

int mcm_server_pack_login(struct fbuf *dest, const union mcm_any *src)
{
	int ret = 0;

	switch (src->id) {
	case MCM_LOGIN_DISCONNECT:
		ret |= mcg_bytes(dest, src->login_disconnect.reason,
				src->login_disconnect.reason_length);
		return ret;

	case MCM_LOGIN_REQUEST:
		ret |= mcg_bytes(dest, src->login_request.serverid,
				src->login_request.serverid_length);
		ret |= mcg_bytes(dest, src->login_request.pubkey,
				src->login_request.pubkey_length);
		ret |= mcg_bytes(dest, src->login_request.verify,
				src->login_request.verify_length);
		return ret;

	case MCM_LOGIN_SUCCESS:
		ret |= mcg_bytes(dest, src->login_success.uuid,
				src->login_success.uuid_length);
		ret |= mcg_bytes(dest, src->login_success.name,
				src->login_success.name_length);
		return ret;

	case MCM_LOGIN_SET_COMPRESSION:
		ret |= mcg_varint(dest, src->login_set_compression.threshold);
		return ret;

	default:
		assert(0 && "Invalid packet id");
		return 1;
	}
}

void mcm_client_parse_login(union mcm_any *dest, enum mcm_id id, struct mcp_parse *src)
{
	/* pass errors */
	if (!mcp_ok(src))
		return;

	dest->id = id;
	switch (id) {
	case MCM_LOGIN_DISCONNECT:
		dest->login_disconnect.reason = mcp_bytes(src,
				&dest->login_disconnect.reason_length);
		return;

	case MCM_LOGIN_REQUEST:
		dest->login_request.serverid = mcp_bytes(src,
				&dest->login_request.serverid_length);
		dest->login_request.pubkey = mcp_bytes(src,
				&dest->login_request.pubkey_length);
		dest->login_request.verify = mcp_bytes(src,
				&dest->login_request.verify_length);
		return;

	case MCM_LOGIN_SUCCESS:
		dest->login_success.uuid = mcp_bytes(src,
				&dest->login_success.uuid_length);
		dest->login_success.name = mcp_bytes(src,
				&dest->login_success.name_length);
		return;

	case MCM_LOGIN_SET_COMPRESSION:
		dest->login_set_compression.threshold = mcp_varint(src);
		return;

	default:
		src->error = MCP_EINVAL;
		return;
	}
}

int mcm_client_pack_login(struct fbuf *dest, const union mcm_any *src)
{
	int ret = 0;

	switch (src->id) {
	case MCM_LOGIN_START:
		ret |= mcg_bytes(dest, src->login_start.name,
				src->login_start.name_length);
		return ret;

	case MCM_LOGIN_RESPONSE:
		ret |= mcg_bytes(dest, src->login_response.shared,
				src->login_response.shared_length);
		ret |= mcg_bytes(dest, src->login_response.verify,
				src->login_response.verify_length);
		return ret;

	default:
		assert(0 && "Invalid packet id");
		return 1;
	}
}

