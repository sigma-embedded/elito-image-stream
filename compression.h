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

#ifndef H_ENSC_STREAMGEN_COMPRESSION_H
#define H_ENSC_STREAMGEN_COMPRESSION_H

#include <stdlib.h>
#include <stdbool.h>

struct signature_algorithm;
struct compression_algorithm {
	int		out_fd;

	bool		(*reset)(struct compression_algorithm *alg,
				 size_t sz_hint);

	void		(*free)(struct compression_algorithm *alg);

	bool		(*update)(struct compression_algorithm *alg,
				  struct signature_algorithm *sig,
				  void const *data, size_t len);

	bool		(*read)(struct compression_algorithm *alg,
				struct signature_algorithm *sig,
				int fd, size_t len);

	ssize_t		(*finish)(struct compression_algorithm *alg);
};

bool _compression_read(struct compression_algorithm *alg, 
		       struct signature_algorithm *sig,
		       int fd, size_t len);

inline static bool compression_read(struct compression_algorithm *alg,
				    struct signature_algorithm *sig,
				    int fd, size_t len)
{
	if (alg->read)
		return alg->read(alg, sig, fd, len);
	else
		return _compression_read(alg, sig, fd, len);
}

inline static ssize_t compression_update(struct compression_algorithm *alg,
					 struct signature_algorithm *sig,
					 void const *data, size_t len)
{
	return alg->update(alg, sig, data, len);
}

inline static ssize_t compression_finish(struct compression_algorithm *alg)
{
	return alg->finish(alg);
}

inline static bool compression_reset(struct compression_algorithm *alg,
				     size_t sz_hint)
{
	return alg->reset(alg, sz_hint);
}

inline static void compression_free(struct compression_algorithm *alg)
{
	if (alg)
		alg->free(alg);
}

#ifdef ENABLE_ZLIB
struct compression_algorithm *	compression_algorithm_gzip_create(void);
#else
inline static struct compression_algorithm *compression_algorithm_gzip_create(void)
{
	return NULL;
}
#endif

#ifdef ENABLE_XZ
struct compression_algorithm *	compression_algorithm_xz_create(void);
#else
inline struct compression_algorithm *compression_algorithm_xz_create(void)
{
	return NULL;
}
#endif

#endif	/* H_ENSC_STREAMGEN_COMPRESSION_H */
