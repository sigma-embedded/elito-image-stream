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

#ifndef H_ENSC_STREAMGEN_DECOMPRESSION_H
#define H_ENSC_STREAMGEN_DECOMPRESSION_H

#include <stdbool.h>
#include <stdlib.h>

struct decompression_algorithm {
	bool	(*splice)(struct decompression_algorithm *alg,
			  int fd_in, int fd_out, size_t cnt_in);

	void	(*free)(struct decompression_algorithm *alg);
};

inline static void decompression_free(struct decompression_algorithm *alg)
{
	if (alg)
		alg->free(alg);
}

struct iovec;

#ifdef ENABLE_ZLIB
struct decompression_algorithm *decompression_algorithm_gzip_create(struct iovec *buf);
#else
inline static struct decompression_algorithm *
decompression_algorithm_gzip_create(struct iovec *buf)
{
	return NULL;
}
#endif

#ifdef ENABLE_XZ
struct decompression_algorithm *decompression_algorithm_xz_create(struct iovec *buf);
#else
inline static struct decompression_algorithm *
decompression_algorithm_xz_create(struct iovec *buf)
{
	return NULL;
}
#endif

#endif	/* H_ENSC_STREAMGEN_DECOMPRESSION_H */
