/*	--*- c -*--
 * Copyright (C) 2012 Enrico Scholz <enrico.scholz@sigma-chemnitz.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include "decompression.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <zlib.h>

#include "signature.h"
#include "util.h"

struct zlib_decompression_algorithm {
	struct decompression_algorithm	alg;
	struct z_stream_s		stream;

	struct iovec			buf_in;
	struct iovec			buf_out;
};
#define tozlib(_alg)	\
	container_of(_alg, struct zlib_decompression_algorithm, alg)

static void zlib_perror(struct z_stream_s const *zlib, int e, char const *op)
{
	int		old_errno = e == Z_ERRNO ? errno : 0;

	fprintf(stderr, "%s(): %s", op, zlib->msg);
	if (e == Z_ERRNO)
		fprintf(stderr, " (%s)\n", strerror(old_errno));
	else
		fprintf(stderr, "\n");
}

static bool 
zlib_decompress(int fd, struct z_stream_s *stream)
{
	void	*out_buf = stream->next_out;
	size_t	out_len  = stream->avail_out;
	int	rc = Z_OK;

	assert(stream->avail_in > 0);
	assert(stream->avail_out > 0);

	while (stream->avail_in > 0 && rc == Z_OK) {
		stream->next_out  = out_buf;
		stream->avail_out = out_len;

		rc = inflate(stream, Z_NO_FLUSH);
		if (rc != Z_OK && rc != Z_STREAM_END && rc != Z_BUF_ERROR) {
			zlib_perror(stream, rc, "inflate");
			break;
		}

		if (!write_all(fd, out_buf, out_len - stream->avail_out)) {
			rc = Z_ERRNO;
			break;
		}
	}

	if (rc < 0)
		return false;

	if (stream->avail_in > 0) {
		fprintf(stderr, "pending input in zlib-decompress\n");
		return false;
	}

	return true;
}
					
static bool
decompression_algorithm_gzip_splice(struct decompression_algorithm *alg,
				    int fd_in, int fd_out, size_t cnt_in)
{
	struct zlib_decompression_algorithm	*zlib = tozlib(alg);
	struct z_stream_s			*stream = &zlib->stream;

	while (cnt_in > 0) {
		size_t		len = MIN(cnt_in, zlib->buf_in.iov_len);
		ssize_t		l = read(fd_in, zlib->buf_in.iov_base, len);

		if (l == 0) {
			fprintf(stderr, "EOS while reading data\n");
			break;
		} else if (l < 0 && errno == EINTR) {
			continue;
		} else if (l < 0) {
			perror("read(<zlib-stream>)");
			break;
		}

		stream->next_in   = zlib->buf_in.iov_base;
		stream->avail_in  = l;

		stream->next_out  = zlib->buf_out.iov_base;
		stream->avail_out = zlib->buf_out.iov_len;

		if (!zlib_decompress(fd_out, stream))
			break;

		cnt_in -= l;
	}

	return cnt_in == 0;
}

static void
decompression_algorithm_gzip_free(struct decompression_algorithm *alg)
{
	struct zlib_decompression_algorithm	*zlib = tozlib(alg);

	deflateEnd(&zlib->stream);
	free(zlib);
}

struct decompression_algorithm *
decompression_algorithm_gzip_create(struct iovec *buf)
{
	struct zlib_decompression_algorithm	*zlib;
	int					rc;

	zlib = calloc(1, sizeof *zlib);
	if (!zlib) {
		perror("malloc(<zlib-decompression>)");
		return NULL;
	}

	rc = inflateInit(&zlib->stream);
	if (rc != Z_OK) {
		zlib_perror(&zlib->stream, rc, "inflateInit()");
		goto err;
	}

	zlib->buf_in.iov_base  = buf->iov_base;
	zlib->buf_in.iov_len   = buf->iov_len * 1 / 3;

	zlib->buf_out.iov_base = buf->iov_base + zlib->buf_in.iov_len;
	zlib->buf_out.iov_len  = buf->iov_len - zlib->buf_in.iov_len;

	zlib->alg.splice = decompression_algorithm_gzip_splice;
	zlib->alg.free   = decompression_algorithm_gzip_free;

	return &zlib->alg;

err:
	free(zlib);
	return NULL;
}
