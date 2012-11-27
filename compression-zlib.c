/*	--*- c -*--
 * Copyright (C) 2012 Enrico Scholz <enrico.scholz@informatik.tu-chemnitz.de>
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

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/param.h>

#include <zlib.h>

#include "util.h"
#include "compression.h"
#include "signature.h"

struct buffer {
	void		*data;
	size_t		cnt;
};

struct zlib_compression_algorithm {
	struct compression_algorithm	alg;
	struct z_stream_s		stream;

	struct buffer			buffer_out;
};
#define tozlib(_alg)	\
	container_of(_alg, struct zlib_compression_algorithm, alg)

static bool buffer_alloc(struct buffer *buf, size_t cnt)
{
	free(buf->data);
	buf->cnt  = 0;
	buf->data = calloc(1, cnt);
	if (!buf->data) {
		perror("calloc(<buffer>)");
		return false;
	}
	buf->cnt = cnt;

	return true;
}

static void buffer_free(struct buffer *buf)
{
	free(buf->data);
	buf->data = NULL;
	buf->cnt  = 0;
}

static void zlib_perror(struct z_stream_s const *zlib, int e, char const *op)
{
	int		old_errno = e == Z_ERRNO ? errno : 0;

	fprintf(stderr, "%s(): %s", op, zlib->msg);
	if (e == Z_ERRNO)
		fprintf(stderr, " (%s)\n", strerror(old_errno));
	else
		fprintf(stderr, "\n");
}

static bool compression_algorithm_zlib_init(struct zlib_compression_algorithm *zlib)
{
	if (zlib->buffer_out.data == NULL) {
		if (!buffer_alloc(&zlib->buffer_out, 1024*1024))
			goto err;

		zlib->stream.next_out  = zlib->buffer_out.data;
		zlib->stream.avail_out = 0;
	}

	return true;

err:
	buffer_free(&zlib->buffer_out);

	return false;
}

static void dump_stream(int fd, struct z_stream_s const *stream, char const *msg)
{
	if (0)
	dprintf(fd, "%s{in=[%p,%u,%lu], out=[%p,%u,%lu], msg=%s}\n", msg,
		stream->next_in, stream->avail_in, stream->total_in,
		stream->next_out, stream->avail_out, stream->total_out,
		stream->msg);
}

static ssize_t compression_algorithm_zlib_finish(struct compression_algorithm *alg)
{
	struct zlib_compression_algorithm	*zlib = tozlib(alg);
	struct z_stream_s			*stream = &zlib->stream;
	int					fd = zlib->alg.out_fd;
	int					rc = Z_OK;
	off_t					pos;
	bool					is_ok = false;

	if (!compression_algorithm_zlib_init(zlib))
		/* hack: resuse zlib error codes */
		rc = Z_STREAM_ERROR;

	while (rc == Z_OK) {
		ptrdiff_t	cnt;

		stream->avail_out = zlib->buffer_out.cnt;
		stream->next_out  = zlib->buffer_out.data;

		dump_stream(99, stream, "A");
		rc = deflate(stream, Z_FINISH);
		dump_stream(99, stream, "B");
		switch (rc) {
		case Z_OK:
		case Z_STREAM_END:
			cnt = (void *)stream->next_out - zlib->buffer_out.data;
			assert((size_t)cnt < zlib->buffer_out.cnt);

			if (!write_all(fd, zlib->buffer_out.data, cnt))
				/* hack: resuse zlib error codes */
				rc = Z_STREAM_ERROR;
			else
				is_ok = (rc == Z_STREAM_END);

			break;

		default:
			zlib_perror(stream, rc, "deflateFinish");
			break;
		}
	}

	rc = deflateEnd(stream);
	if (rc != Z_OK) {
		zlib_perror(stream, rc, "deflateEnd");
		is_ok = false;
	}

	if (!is_ok) {
		close(fd);
		zlib->alg.out_fd = -1;
		pos = -1;
	} else {
		pos = lseek(zlib->alg.out_fd, 0, SEEK_CUR);

		if (pos < 0) {
			perror("lseek(<SEEK_CUR>)");
			pos = -1;
		} else if (ftruncate(zlib->alg.out_fd, pos) < 0) {
			perror("ftruncate(<zlib>)");
			pos = -1;
		} else if (lseek(zlib->alg.out_fd, 0, SEEK_SET) < 0) {
			perror("lseek(<zlib-fd>)");
			pos = -1;
		}
	}

	return pos;
}

static bool compression_algorithm_zlib_update(struct compression_algorithm *alg,
					      struct signature_algorithm *sig,
					      void const *buf, size_t len)
{
	struct zlib_compression_algorithm	*zlib = tozlib(alg);
	struct z_stream_s			*stream = &zlib->stream;
	int					fd = zlib->alg.out_fd;
	int					rc;

	if (!compression_algorithm_zlib_init(zlib))
		return false;

	if (sig && !signature_update(sig, buf, len)) {
		fprintf(stderr, "zlib: failed to update signature\n");
		return false;
	}

	stream->avail_in  = len;
	stream->next_in   = (void *)buf;

	while (stream->avail_in > 0) {
		ptrdiff_t	cnt;

		stream->avail_out = zlib->buffer_out.cnt;
		stream->next_out  = zlib->buffer_out.data;

		dump_stream(99, stream, "C");
		rc = deflate(stream, Z_NO_FLUSH);
		dump_stream(99, stream, "D");
		if (rc != Z_OK) {
			zlib_perror(stream, rc, "deflate");
			break;
		}

		cnt = (void *)stream->next_out - zlib->buffer_out.data;

		assert((size_t)cnt < zlib->buffer_out.cnt);

		if (!write_all(fd, zlib->buffer_out.data, cnt))
			break;
	}

	return stream->avail_in == 0;
}

static void compression_algorithm_zlib_free(struct compression_algorithm *alg)
{
	struct zlib_compression_algorithm	*zlib = tozlib(alg);

	deflateEnd(&zlib->stream);
	buffer_free(&zlib->buffer_out);

	if (zlib->alg.out_fd != -1)
		close(zlib->alg.out_fd);

	free(zlib);
}

static bool compression_algorithm_zlib_reset(struct compression_algorithm *alg,
					     size_t sz_hint)
{
	struct zlib_compression_algorithm	*zlib = tozlib(alg);
	struct z_stream_s			*stream = &zlib->stream;
	FILE					*tmpf = NULL;
	int					rc;

	deflateEnd(&zlib->stream);
	buffer_free(&zlib->buffer_out);

	rc = deflateInit(stream, Z_BEST_COMPRESSION);
	if (rc != Z_OK) {
		zlib_perror(stream, rc, "deflateInit()");
		goto err;
	}

	if (zlib->alg.out_fd != -1) {
		close(zlib->alg.out_fd);
		zlib->alg.out_fd = -1;
	}

	tmpf = tmpfile();
	if (!tmpf) {
		perror("tmpfile(<zlib>)");
		goto err;
	}

	zlib->alg.out_fd = dup(fileno(tmpf));
	if (zlib->alg.out_fd == -1) {
		perror("dup(<zlib-tmpfile>)");
		goto err;
	}

	fclose(tmpf);
	tmpf = NULL;

	posix_fallocate(zlib->alg.out_fd, 0, sz_hint); /* ignore errors; it is
							* just a hint */

	return true;

err:
	deflateEnd(&zlib->stream);
	buffer_free(&zlib->buffer_out);

	/* zlib_fd does leak as it managed by zlib->gz */
	if (zlib->alg.out_fd != -1) {
		close(zlib->alg.out_fd);
		zlib->alg.out_fd = -1;
	}

	if (tmpf)
		fclose(tmpf);

	return false;
}

struct compression_algorithm *	compression_algorithm_gzip_create(void)
{
	struct zlib_compression_algorithm	*zlib;

	zlib = calloc(1, sizeof *zlib);
	if (!zlib) {
		perror("malloc(<zlib-compression>)");
		return NULL;
	}

	zlib->alg.reset  = compression_algorithm_zlib_reset;
	zlib->alg.finish = compression_algorithm_zlib_finish;
	zlib->alg.free   = compression_algorithm_zlib_free;
	zlib->alg.update = compression_algorithm_zlib_update;
	zlib->alg.out_fd = -1;

	return &zlib->alg;
}
