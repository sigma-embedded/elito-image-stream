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

#include <stdlib.h>
#include <errno.h>
#include <stdio.h>

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#include "signature.h"

#if GNUTLS_VERSION_NUMBER >= 0x02090a
struct signature_gnutls_digest {
	struct signature_algorithm	alg;
	gnutls_hash_hd_t		dig;

	gnutls_digest_algorithm_t	digalg;
	size_t				digest_len;
	unsigned char			digest[];
};
#define togalg(_alg)	\
	container_of(_alg, struct signature_gnutls_digest, alg)


static bool signature_gnutls_reset(struct signature_algorithm *alg)
{
	struct signature_gnutls_digest	*galg = togalg(alg);

	gnutls_hash_deinit(galg->dig, galg->digest);
	if (gnutls_hash_init(&galg->dig, galg->digalg) < 0)
		abort();

	return true;
}

static bool signature_gnutls_update(struct signature_algorithm *alg,
				    void const *data, size_t len)
{
	struct signature_gnutls_digest	*galg = togalg(alg);

	if (gnutls_hash(galg->dig, data, len) < 0)
		return false;

	return true;
}

static bool signature_gnutls_finish(struct signature_algorithm *alg, 
				    void const **dst, size_t *dst_len)
{
	struct signature_gnutls_digest	*galg = togalg(alg);

	gnutls_hash_output(galg->dig, galg->digest);

	*dst     = galg->digest;
	*dst_len = galg->digest_len;

	return true;
}

static void signature_gnutls_free(struct signature_algorithm *alg)
{
	struct signature_gnutls_digest	*galg = togalg(alg);

	gnutls_hash_deinit(galg->dig, galg->digest);
	free(galg);
}

struct signature_algorithm *signature_gnutls_create(gnutls_digest_algorithm_t digalg)
{
	struct signature_gnutls_digest	*galg;
	size_t				digest_len = gnutls_hash_get_len(digalg);

	galg = calloc(1, sizeof *galg + digest_len);
	if (!galg) {
		perror("malloc(<gnutls-digest>)");
		goto err;
	}

	if (gnutls_hash_init(&galg->dig, digalg) < 0) {
		fprintf(stderr, "failed to create gnutls digest %d\n", digalg);
		goto err;
	}

	galg->digest_len = digest_len;
	galg->digalg = digalg;

	galg->alg.strength = 10;
	galg->alg.reset    = signature_gnutls_reset;
	galg->alg.update   = signature_gnutls_update;
	galg->alg.finish   = signature_gnutls_finish;
	galg->alg.free     = signature_gnutls_free;

	return &galg->alg;

err:
	if (galg) {
		if (digest_len > 0)
			gnutls_hash_deinit(galg->dig, galg->digest);

		free(galg);
	}

	return NULL;
}

struct signature_algorithm *	signature_algorithm_md5_create(void)
{
	return signature_gnutls_create(GNUTLS_DIG_MD5);
}

struct signature_algorithm *	signature_algorithm_sha1_create(void)
{
	return signature_gnutls_create(GNUTLS_DIG_SHA1);
}

struct signature_algorithm *	signature_algorithm_sha256_create(void)
{
	return signature_gnutls_create(GNUTLS_DIG_SHA256);
}

struct signature_algorithm *	signature_algorithm_sha512_create(void)
{
	return signature_gnutls_create(GNUTLS_DIG_SHA512);
}
#endif

static void __attribute__((__constructor__)) signature_algorithm_gnutls_init(void)
{
	gnutls_global_init();
}

static void __attribute__((__destructor__)) signature_algorithm_gnutls_deinit(void)
{
	gnutls_global_deinit();
}
