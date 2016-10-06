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
#include <stdbool.h>

enum signature_setopt_result {
	SIGNATURE_SETOPT_SUCCESS = 23,
	SIGNATURE_SETOPT_NOOPT,
	SIGNATURE_SETOPT_ERROR
};
	
struct signature_algorithm {
	unsigned int	strength;

	bool		(*reset)(struct signature_algorithm *alg);
	bool		(*update)(struct signature_algorithm *alg,
				  void const *data, size_t len);
	bool		(*pipein)(struct signature_algorithm *alg,
				  int fd, size_t len);
	bool		(*begin)(struct signature_algorithm *alg, 
				 void const **dst, size_t *len);
	bool		(*finish)(struct signature_algorithm *alg, 
				  void const **dst, size_t *len);
	bool		(*verify)(struct signature_algorithm *alg,
				  void const *sig, size_t len);
	enum signature_setopt_result (*setopt)(struct signature_algorithm *alg,
					       char const *key, 
					       void const *val, size_t val_len);
	bool		(*setenv)(struct signature_algorithm *alg);
	void		(*free)(struct signature_algorithm *alg);
	bool		(*setstrength)(struct signature_algorithm *alg,
				       unsigned int strength);
};

inline static bool signature_reset(struct signature_algorithm *alg)
{
	return alg->reset(alg);
}

inline static bool signature_update(struct signature_algorithm *alg,
				    void const *data, size_t len)
{
	if (len == 0)
		return true;

	return alg->update(alg, data, len);
}

bool _signature_pipein(struct signature_algorithm *alg, int fd, size_t len);

inline static bool signature_pipein(struct signature_algorithm *alg,
				    int fd, size_t len)
{
	if (alg->pipein)
		return alg->pipein(alg, fd, len);
	else
		return _signature_pipein(alg, fd, len);
}

inline static bool signature_begin(struct signature_algorithm *alg, 
				   void const **dst, size_t *len)
{
	if (alg->begin) {
		return alg->begin(alg, dst, len);
	} else {
		*dst = NULL;
		*len = 0;
		return true;
	}
}

inline static bool signature_setenv(struct signature_algorithm *alg)
{
	if (alg->setenv)
		return alg->setenv(alg);
	else
		return true;
}

inline static bool signature_finish(struct signature_algorithm *alg, 
				    void const **dst, size_t *len)
{
	return alg->finish(alg, dst, len);
}

bool _signature_verify(struct signature_algorithm *alg, void const *sig, 
		       size_t len);

inline static bool signature_verify(struct signature_algorithm *alg, 
				    void const *sig, size_t len)
{
	if (alg->verify)
		return alg->verify(alg, sig, len);
	else
		return _signature_verify(alg, sig, len);
}

inline static enum signature_setopt_result
signature_setopt(struct signature_algorithm *alg,
		 char const *key, void const *val, size_t val_len)
{
	if (alg->setopt)
		return alg->setopt(alg, key, val, val_len);
	else
		return SIGNATURE_SETOPT_NOOPT;
}

inline static void signature_free(struct signature_algorithm *alg)
{
	if (alg)
		alg->free(alg);
}

inline static bool signature_setstrength(struct signature_algorithm *alg,
					 unsigned int strength)
{
	if (alg->setstrength)
		return alg->setstrength(alg, strength);
	else
		return strength <= alg->strength;
}


struct signature_algorithm *	signature_algorithm_none_create(void);
struct signature_algorithm *	signature_algorithm_md5_create(void);
struct signature_algorithm *	signature_algorithm_sha1_create(void);
struct signature_algorithm *	signature_algorithm_sha256_create(void);
struct signature_algorithm *	signature_algorithm_sha512_create(void);
struct signature_algorithm *	signature_algorithm_x509_create(void);
struct signature_algorithm *	signature_algorithm_gpg_create(void);


#endif	/* H_ENSC_STREAMGEN_SIGNATURE_H */
