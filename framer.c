#include <stdlib.h>
#include <string.h>

#include <zlib.h>

#include <mcp_base/mcp.h>
#include <mcp_base/fbuf.h>

#include <common/util.h>

#ifndef NETTY_NO_CIPHER
#include <common/aes.h>
#endif

#include "framer.h"

struct netty_framer {
	size_t frame_size, decomp_size;
	ssize_t threshold;
	z_stream inflate, deflate;
	struct fbuf decomp;

#ifndef NETTY_NO_CIPHER
	int has_cipher;
	struct aes_stream_key read_key, write_key;
#endif
};

struct netty_framer *netty_framer_new(void)
{
	struct netty_framer *framer = malloc(sizeof(*framer));
	if (framer == NULL)
		return NULL;

	framer->deflate.zalloc = Z_NULL;
	framer->deflate.zfree = Z_NULL;
	framer->deflate.opaque = Z_NULL;
	framer->deflate.avail_in = 0;
	framer->deflate.avail_out = 0;
	framer->deflate.next_in = Z_NULL;
	framer->deflate.next_out = Z_NULL;
	if (deflateInit(&framer->deflate, Z_DEFAULT_COMPRESSION) != Z_OK) {
		free(framer);
		return NULL;
	}

	framer->inflate.zalloc = Z_NULL;
	framer->inflate.zfree = Z_NULL;
	framer->inflate.opaque = Z_NULL;
	framer->inflate.avail_in = 0;
	framer->inflate.avail_out = 0;
	framer->inflate.next_in = Z_NULL;
	framer->inflate.next_out = Z_NULL;
	if (inflateInit(&framer->inflate) != Z_OK) {
		deflateEnd(&framer->deflate);
		free(framer);
		return NULL;
	}

	framer->threshold = -1;
	framer->frame_size = 0;
	framer->decomp_size = 0;
	fbuf_init(&framer->decomp, FBUF_MAX);

#ifndef NETTY_NO_CIPHER
	framer->has_cipher = 0;
#endif

	return framer;
}

void netty_framer_free(struct netty_framer *framer)
{
	if (framer == NULL)
		return;
	deflateEnd(&framer->deflate);
	inflateEnd(&framer->inflate);
	fbuf_free(&framer->decomp);
	free(framer);
}

int netty_set_frame_limit(struct netty_framer *framer, size_t size)
{
	if (framer->frame_size > size || (framer->frame_size > 0 && framer->decomp_size > size))
		return -1;
	if (fbuf_shrink(&framer->decomp, size))
		return -1;
	return 0;
}

#ifndef NETTY_NO_CIPHER
int netty_set_cipher(struct netty_framer *framer, const void *secret, size_t size)
{
	if (framer->frame_size > 0)
		return -1;

	if (framer->has_cipher)
		return -1;

	if (size != 16)
		return -1;

	aes_prepare_stream(&framer->read_key, secret, 128, secret);
	aes_prepare_stream(&framer->write_key, secret, 128, secret);

	framer->has_cipher = 1;
	return 0;
}
#endif

int netty_set_threshold(struct netty_framer *framer, ssize_t threshold)
{
	framer->threshold = threshold;
	return 0;
}

int netty_set_level(struct netty_framer *framer, int level)
{
	framer->deflate.avail_in = 0;
	framer->deflate.avail_out = 0;
	framer->deflate.next_in = Z_NULL;
	framer->deflate.next_out = Z_NULL;
	if (deflateParams(&framer->deflate, level, Z_DEFAULT_STRATEGY) != Z_OK)
		return -1;
	return 0;
}

static void netty_decomp_frame(struct mcp_parse *frame, struct fbuf *src, struct netty_framer *framer);
void netty_start_frame(struct mcp_parse *frame, struct fbuf *src, struct netty_framer *framer)
{
	struct mcp_parse header;
	size_t frame_size, decomp_size, off, inner_size;

#ifndef NETTY_NO_CIPHER
	size_t saved_offset, header_size;
	char saved_feedback[16], header_storage[20];
#endif

	/* we already have a header */
	if (framer->frame_size > 0)
		netty_decomp_frame(frame, src, framer);

#ifndef NETTY_NO_CIPHER
	/* save old cipher state */
	memcpy(saved_feedback, framer->read_key.feedback, sizeof(saved_feedback));
	saved_offset = framer->read_key.total_bytes;

	/* decrypt the max size of a header */
	if (framer->has_cipher) {
		header_size = sizeof(header_storage);
		if (fbuf_avail(src) < header_size)
			header_size = fbuf_avail(src);
		aes_decrypt_cfb8(header_storage, fbuf_ptr(src), header_size, &framer->read_key);
		mcp_start(&header, header_storage, header_size);
	} else {
#endif
		mcp_start_fbuf(&header, src);
#ifndef NETTY_NO_CIPHER
	}
#endif

	/* try to read the header */
	if (framer->threshold >= 0) {
		frame_size = mcp_varint(&header);
		off = mcp_consumed(&header);
		decomp_size = mcp_varint(&header);
	} else {
		frame_size = mcp_varint(&header);
		off = mcp_consumed(&header);
		decomp_size = 0;
	}

	/* check for errors and propigate up */
	if (!mcp_ok(&header)) {
		if (mcp_error(&header) != MCP_EAGAIN)
			header.error = MCP_EINVAL;
err_header:
		mcp_start(frame, NULL, 0);
		frame->error = mcp_error(&header);
#ifndef NETTY_NO_CIPHER
		memcpy(framer->read_key.feedback, saved_feedback, sizeof(saved_feedback));
		framer->read_key.total_bytes = saved_offset;
#endif
		return;
	}

	/* frame_size includes the size of decomp_size (if applicable) */
	if (mcp_consumed(&header) - off > frame_size) {
		header.error = MCP_EINVAL;
		goto err_header;
	}

	if (decomp_size == 0)
		inner_size = frame_size - (mcp_consumed(&header) - off);
	else
		inner_size = decomp_size;

	/* preallocate space for the packet */
	fbuf_clear(&framer->decomp);
	if (fbuf_wptr(&framer->decomp, inner_size) == NULL) {
		header.error = MCP_ENOMEM;
		goto err_header;
	}

#ifndef NETTY_NO_CIPHER
	/* fixup state in case we read past the header */
	memcpy(framer->read_key.feedback, saved_feedback, sizeof(saved_feedback));
	framer->read_key.total_bytes = saved_offset;
	if (framer->has_cipher)
		aes_decrypt_cfb8(header_storage, fbuf_ptr(src), mcp_consumed(&header), &framer->read_key);
#endif
	fbuf_consume(src, mcp_consumed(&header));

	framer->frame_size = frame_size - (mcp_consumed(&header) - off);
	framer->decomp_size = decomp_size;

	netty_decomp_frame(frame, src, framer);
}

static void netty_decomp_frame(struct mcp_parse *frame, struct fbuf *src_buf, struct netty_framer *framer)
{
	size_t size;
	unsigned char *src, *dest;
	int ret = Z_STREAM_END, flush = Z_NO_FLUSH;

	size = fbuf_avail(src_buf);
	if (framer->frame_size < size)
		size = framer->frame_size;

	src = (void *)fbuf_ptr(src_buf);
	dest = fbuf_wptr(&framer->decomp, size);
	if (dest == NULL)
		goto err_invalid;

#ifndef NETTY_NO_CIPHER
	/* do decryption */
	if (framer->has_cipher)
		aes_decrypt_cfb8(src, src, size, &framer->read_key);
#endif

	if (framer->decomp_size == 0) {
		/* frame not compressed */
		memcpy(dest, src, size);
		fbuf_produce(&framer->decomp, size);
	} else {
		/* inflate frame */
		framer->inflate.avail_in = size;
		framer->inflate.next_in = src;
		framer->inflate.avail_out = fbuf_wavail(&framer->decomp);
		framer->inflate.next_out = dest;

		if (framer->frame_size == size)
			flush = Z_FINISH;

		do {
			ret = inflate(&framer->inflate, flush);
			if (ret != Z_OK)
				break;
		} while (framer->inflate.avail_in > 0);

		fbuf_produce(&framer->decomp, fbuf_wavail(&framer->decomp) - framer->inflate.avail_out);

		if (ret < 0)
			goto err_invalid;
	}

	/* update state */
	fbuf_consume(src_buf, size);
	framer->frame_size -= size;
	if (framer->frame_size > 0) {
		mcp_start(frame, NULL, 0);
		frame->error = MCP_EAGAIN;
		return;
	}

	/* finished reading frame */
	if (flush == Z_FINISH)
		inflateReset(&framer->inflate);

	if (ret != Z_STREAM_END)
		goto err_invalid;

	mcp_start(frame, fbuf_ptr(&framer->decomp), fbuf_avail(&framer->decomp));
	return;

err_invalid:
	mcp_start(frame, NULL, 0);
	frame->error = MCP_EINVAL;
	return;
}

int netty_pack_frame(struct fbuf *dest, const void *data, size_t size, struct netty_framer *framer)
{
	tempbuf_frame frame;
	struct fbuf *temp;
	int ret = 0;

#ifndef NETTY_NO_CIPHER
	unsigned char *ptr;
	size_t old_avail = fbuf_avail(dest);
#endif

	if (framer->threshold < 0) {
		/* compression disabled */
		ret |= mcg_bytes(dest, data, size);
	} else if (size < (size_t)framer->threshold) {
		/* below threshold */
		ret |= mcg_varlong(dest, size + 1);
		ret |= mcg_byte(dest, 0);
		ret |= mcg_raw(dest, data, size);
	} else {
		/* compressed */
		frame = tempbuf_push();
		temp = tempbuf();

		/* prepend decompressed size */
		if (mcg_varlong(temp, size)) {
			tempbuf_pop(frame);
			return 1;
		}

		/* deflate */
		framer->deflate.avail_in = size;
		framer->deflate.next_in = (void *)data;
		framer->deflate.next_out = fbuf_wptr(temp, deflateBound(&framer->deflate, size));
		framer->deflate.avail_out = fbuf_wavail(temp);

		if (framer->deflate.next_out == NULL) {
			tempbuf_pop(frame);
			return 1;
		}

		do {
			ret = deflate(&framer->deflate, Z_FINISH);
		} while (ret == Z_OK);

		fbuf_produce(temp, fbuf_wavail(temp) - framer->deflate.avail_out);

		if (ret != Z_STREAM_END) {
			tempbuf_pop(frame);
			return 1;
		}

		deflateReset(&framer->deflate);

		/* write out to socket */
		ret = mcg_bytes(dest, fbuf_ptr(temp), fbuf_avail(temp));
		tempbuf_pop(frame);
	}

	if (ret)
		return 1;

#ifndef NETTY_NO_CIPHER
	/* do encryption */
	if (framer->has_cipher) {
		ptr = (void *)fbuf_ptr(dest);
		ptr += old_avail;
		aes_encrypt_cfb8(ptr, ptr, fbuf_avail(dest) - old_avail, &framer->write_key);
	}
#endif

	return 0;
}

