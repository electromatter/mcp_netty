/* mcp_modern/base/status.c
 *
 * Copyright (c) 2016 Eric Chai <electromatter@gmail.com>
 * All rights reserved.
 *
 * This software may be modified and distributed under the terms
 * of the ISC license. See the LICENSE file for details.
 */

#include "base.h"

#include <assert.h>

void mcm_server_parse_status(union mcm_any *dest, enum mcm_id id, struct mcp_parse *src)
{
	/* pass errors */
	if (!mcp_ok(src))
		return;

	dest->id = id;
	switch (id) {
	case MCM_STATUS_REQUEST:
		return;

	case MCM_STATUS_PING:
		dest->status_ping.time = mcp_ulong(src);
		return;

	default:
		src->error = MCP_EINVAL;
		return;
	}
}

int mcm_server_pack_status(struct fbuf *dest, const union mcm_any *src)
{
	int err = 0;

	switch (src->id) {
	case MCM_STATUS_RESPONSE:
		err |= mcg_bytes(dest, src->status_response.motd, src->status_response.motd_length);
		return err;

	case MCM_STATUS_PING:
		err |= mcg_ulong(dest, src->status_ping.time);
		return err;

	default:
		assert(0 && "Invalid packet id");
		return 1;
	}
}

void mcm_client_parse_status(union mcm_any *dest, enum mcm_id id, struct mcp_parse *src)
{
	/* pass errors */
	if (!mcp_ok(src))
		return;

	dest->id = id;
	switch (id) {
	case MCM_STATUS_RESPONSE:
		dest->status_response.motd = mcp_bytes(src,
				&dest->status_response.motd_length);
		return;

	case MCM_STATUS_PING:
		dest->status_ping.time = mcp_ulong(src);
		return;

	default:
		src->error = MCP_EINVAL;
		return;
	}
}

int mcm_client_pack_status(struct fbuf *dest, const union mcm_any *src)
{
	int err = 0;
	switch (src->id) {
	case MCM_STATUS_REQUEST:
		return err;

	case MCM_STATUS_PING:
		err |= mcg_ulong(dest, src->status_ping.time);
		return err;

	default:
		assert(0 && "Invalid packet id");
		return 1;
	}
}
