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

#ifndef H_ENSC_STREAMGEN_SIGNATURE_H
#define H_ENSC_STREAMGEN_SIGNATURE_H

#include <stdlib.h>

struct signature_algorithm {
	int		(*reset)(struct signature_algorithm *alg);
	void		(*update)(struct signature_algorithm *alg,
				  void const *data, size_t len);
	size_t		(*length)(struct signature_algorithm const *alg);
	void		(*finish)(struct signature_algorithm *alg, void *dst);

	void		(*free)(struct signature_algorithm *alg);
};

struct signature_algorithm *	signature_algorithm_md5_create(void);
struct signature_algorithm *	signature_algorithm_sha1_create(void);
struct signature_algorithm *	signature_algorithm_sha256_create(void);
struct signature_algorithm *	signature_algorithm_sha512_create(void);
struct signature_algorithm *	signature_algorithm_gpg_create(void);


#endif	/* H_ENSC_STREAMGEN_SIGNATURE_H */
