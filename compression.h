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

struct compression_algorithm {
	int		out_fd;

	bool		(*reset)(struct compression_algorithm *alg);
	void		(*free)(struct compression_algorithm *alg);

	ssize_t		(*update)(struct compression_algorithm *alg,
				  void const *data, size_t len);
	ssize_t		(*pipein)(struct compression_algorithm *alg,
				  int fd, size_t len);

	ssize_t		(*finish)(struct compression_algorithm *alg);
};

struct compression_algorithm *	compression_algorithm_none_create(void);
struct compression_algorithm *	compression_algorithm_gzip_create(void);
struct compression_algorithm *	compression_algorithm_xz_create(void);

#endif	/* H_ENSC_STREAMGEN_COMPRESSION_H */
