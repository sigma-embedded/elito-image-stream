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
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/abstract.h>

#include "stream.h"
#include "signature.h"

#define MAX_CRT_SIZE	(64 * 1024)

struct x509_crt_list {
	gnutls_x509_crt_t		*crt;
	size_t				num;
};

struct x509_crl_list {
	gnutls_x509_crl_t		*crl;
	size_t				num;
};

struct x509_gnutls {
	struct signature_algorithm	alg;
	struct signature_algorithm	*hash;

	gnutls_x509_privkey_t		key;
	gnutls_privkey_t		privkey;

	gnutls_x509_crt_t		crt;
	gnutls_pubkey_t			pubkey;
	void				*crt_buf;

	struct x509_crt_list		ca_list;
	struct x509_crl_list		crl_list;

	gnutls_datum_t			signature;
	gnutls_digest_algorithm_t	hash_alg;

	bool				skip_verify;
	bool				skip_purpose;
};
#define tox509(_alg)	\
	container_of(_alg, struct x509_gnutls, alg)

static bool x509_gnutls_mmap(char const *filename, gnutls_datum_t *dat)
{
	int		fd = open(filename, O_RDONLY);
	struct stat	st;

	if (!fd) {
		fprintf(stderr, "open(%s): %m\n", filename);
		return false;
	}

	if (fstat(fd, &st) < 0) {
		fprintf(stderr, "fstat(%s): %m\n", filename);
		close(fd);
		return false;
	}

	dat->data = mmap(NULL, st.st_size+1, PROT_READ|PROT_WRITE,
			 MAP_PRIVATE, fd, 0);
	close(fd);

	if (dat->data == MAP_FAILED) {
		fprintf(stderr, "mmap(%s): %m\n", filename);
		return false;
	}

	dat->data[st.st_size] = '\0';
	dat->size = st.st_size + 1;
	return true;
}

static void x509_perror(char const *op, int r)
{
	fprintf(stderr, "%s: %s\n", op, gnutls_strerror(r));
}

static bool x509_gnutls_load_crt_from_mem(gnutls_datum_t const *data,
					  gnutls_x509_crt_t *crt,
					  gnutls_pubkey_t *pubkey,
					  gnutls_x509_crt_fmt_t format)
{
	int		r;

	if (*crt) {
		gnutls_x509_crt_deinit(*crt);
		*crt = NULL;
	}

	if (pubkey && *pubkey) {
		gnutls_pubkey_deinit(*pubkey);
		*pubkey = NULL;
	}

	r = gnutls_x509_crt_init(crt);
	if (r < 0) {
		x509_perror("gnutls_x509_crt_init()", r);
		*crt = NULL;
		goto err;
	}

	r = gnutls_x509_crt_import(*crt, data, format);
	if (r < 0) {
		x509_perror("gnutls_x509_crt_import()", r);
		goto err;
	}

	if (pubkey) {
		r = gnutls_pubkey_init(pubkey);
		if (r < 0) {
			x509_perror("gnutls_pubkey_init()", r);
			*pubkey = NULL;
			goto err;
		}

		r = gnutls_pubkey_import_x509(*pubkey, *crt, 0);
		if (r < 0) {
			x509_perror("gnutls_pubkey_import_x509()", r);
			goto err;
		}
	}

	return true;

err:
	if (pubkey && *pubkey) {
		gnutls_pubkey_deinit(*pubkey);
		*pubkey = NULL;
	}

	if (*crt) {
		gnutls_x509_crt_deinit(*crt);
		*crt = NULL;
	}

	return false;

}
static bool x509_gnutls_load_crt(char const *filename,
				 gnutls_x509_crt_t *crt,
				 gnutls_pubkey_t *pubkey)
{
	gnutls_datum_t	data = { .data = NULL };
	bool		rc;

	if (!x509_gnutls_mmap(filename, &data))
		rc = false;
	else {
		rc = x509_gnutls_load_crt_from_mem(&data, crt, pubkey, 
						   GNUTLS_X509_FMT_PEM);
		munmap(data.data, data.size);
	}

	return rc;
}

static bool x509_gnutls_load_crl(char const *filename, gnutls_x509_crl_t *crl)
{
	int		r;
	gnutls_datum_t	data = { .data = NULL };

	if (*crl) {
		gnutls_x509_crl_deinit(*crl);
		*crl = NULL;
	}

	if (!x509_gnutls_mmap(filename, &data))
		goto err;

	r = gnutls_x509_crl_init(crl);
	if (r < 0) {
		x509_perror("gnutls_x509_crl_init()", r);
		*crl = NULL;
		goto err;
	}

	r = gnutls_x509_crl_import(*crl, &data, GNUTLS_X509_FMT_PEM);
	if (r < 0) {
		x509_perror("gnutls_x509_crl_import()", r);
		goto err;
	}

	munmap(data.data, data.size);
	data.data = NULL;

	return true;

err:
	if (*crl) {
		gnutls_x509_crl_deinit(*crl);
		*crl = NULL;
	}

	if (data.data)
		munmap(data.data, data.size);

	return false;
}

static bool x509_gnutls_load_key(char const *filename,
				 gnutls_x509_privkey_t *key,
				 gnutls_privkey_t *privkey)
{
	int		r;
	gnutls_datum_t	data = { .data = NULL };

	if (*key) {
		gnutls_x509_privkey_deinit(*key);
		*key = NULL;
	}

	if (privkey && *privkey) {
		gnutls_privkey_deinit(*privkey);
		*privkey = NULL;
	}

	if (!x509_gnutls_mmap(filename, &data))
		goto err;

	r = gnutls_x509_privkey_init(key);
	if (r < 0) {
		x509_perror("gnutls_x509_privkey_init()", r);
		*key = NULL;
		goto err;
	}

	r = gnutls_x509_privkey_import(*key, &data, GNUTLS_X509_FMT_PEM);
	if (r < 0) {
		x509_perror("gnutls_x509_privkey_import()", r);
		goto err;
	}

	munmap(data.data, data.size);
	data.data = NULL;

	if (privkey) {
		r = gnutls_privkey_init(privkey);
		if (r < 0) {
			x509_perror("gnutls_privkey_init()", r);
			*privkey = NULL;
			goto err;
		}

		r = gnutls_privkey_import_x509(*privkey, *key, 0);
		if (r < 0) {
			x509_perror("gnutls_privkey_import_x509()", r);
			goto err;
		}
	}

	return true;

err:
	if (privkey && *privkey) {
		gnutls_privkey_deinit(*privkey);
		*privkey = NULL;
	}

	if (*key) {
		gnutls_x509_privkey_deinit(*key);
		*key = NULL;
	}

	if (data.data)
		munmap(data.data, data.size);

	return false;
}

static bool x509_gnutls_add_to_crt_list(char const *filename,
					struct x509_crt_list *lst)
{
	bool			rc = false;
	gnutls_x509_crt_t	*new_list;
	gnutls_x509_crt_t	*crt;

	new_list = realloc(lst->crt, sizeof lst->crt[0] * (lst->num + 1));
	if (!new_list) {
		perror("realloc(<crt_list>)");
		goto out;
	}

	lst->crt = new_list;
	crt  = &lst->crt[lst->num];
	*crt = NULL;

	rc = x509_gnutls_load_crt(filename, crt, NULL);
	if (rc)
		lst->num += 1;

	rc = true;

out:
	return rc;
}

static bool x509_gnutls_add_to_crl_list(char const *filename,
					struct x509_crl_list *lst)
{
	bool			rc = false;
	gnutls_x509_crl_t	*new_list;
	gnutls_x509_crl_t	*crl;

	new_list = realloc(lst->crl, sizeof lst->crl[0] * (lst->num + 1));
	if (!new_list) {
		perror("realloc(<crl_list>)");
		goto out;
	}

	lst->crl = new_list;
	crl  = &lst->crl[lst->num];
	*crl = NULL;

	rc = x509_gnutls_load_crl(filename, crl);
	if (rc)
		lst->num += 1;

	rc = true;

out:
	return rc;
}

static bool x509_gnutls_add_crl(struct x509_gnutls *x509, char const *crl_file)
{
	return x509_gnutls_add_to_crl_list(crl_file, &x509->crl_list);
}

static bool x509_gnutls_add_ca(struct x509_gnutls *x509, char const *ca_file)
{
	return x509_gnutls_add_to_crt_list(ca_file, &x509->ca_list);
}

static bool x509_gnutls_set_crt(struct x509_gnutls *x509,
				char const *crt_file)
{
	return x509_gnutls_load_crt(crt_file, &x509->crt, &x509->pubkey);
}

static bool x509_gnutls_set_crt_bin(struct x509_gnutls *x509,
				    void const *buf, size_t size)
{
	gnutls_datum_t const	data = {
		.data = (void *)buf,
		.size = size,
	};

	return x509_gnutls_load_crt_from_mem(&data, &x509->crt, &x509->pubkey,
					     GNUTLS_X509_FMT_DER);
}

static bool x509_gnutls_set_key(struct x509_gnutls *x509,
				char const *pem_file)
{
	return x509_gnutls_load_key(pem_file, &x509->key, &x509->privkey);
}

static enum signature_setopt_result 
x509_gnutls_setopt(struct signature_algorithm *alg,
		   char const *key, void const *val, size_t val_len)
{
	struct x509_gnutls	*x509 = tox509(alg);
	bool			rc = false;

	if (strcmp(key, "key") == 0)
		rc = x509_gnutls_set_key(x509, val);
	else if (strcmp(key, "crt") == 0)
		rc = x509_gnutls_set_crt(x509, val);
	else if (strcmp(key, "pem") == 0)
		rc = (x509_gnutls_set_crt(x509, val) &&
		      x509_gnutls_set_key(x509, val));
	else if (strcmp(key, "ca") == 0)
		rc = x509_gnutls_add_ca(x509, val);
	else if (strcmp(key, "crl") == 0)
		rc = x509_gnutls_add_crl(x509, val);
	else if (strcmp(key, "info-bin") == 0)
		rc = x509_gnutls_set_crt_bin(x509, val, val_len);
	else if (strcmp(key, "skip-verify") == 0) {
		x509->skip_verify = true;
		rc = true;
	} else
		return SIGNATURE_SETOPT_NOOPT;


	return rc ? SIGNATURE_SETOPT_SUCCESS : SIGNATURE_SETOPT_ERROR;
}

static void x509_dump_cert(FILE *f, gnutls_x509_crt_t crt)
{
	gnutls_datum_t	txt;
	int		r;

	r = gnutls_x509_crt_print(crt, GNUTLS_CRT_PRINT_ONELINE, &txt);

	if (r != GNUTLS_E_SUCCESS) {
		txt.data = NULL;
		txt.size = 0;
	}

	fprintf(f, "%.*s", (int)txt.size, (char const *)txt.data);
	gnutls_free(txt.data);
}

static bool x509_gnutls_reset(struct signature_algorithm *alg)
{
	struct x509_gnutls		*x509 = tox509(alg);
	gnutls_digest_algorithm_t	hash_alg;
	unsigned int			hash_mand;

	unsigned int			verify_result;

	size_t				i;
	bool				is_critical = false;
	bool				kp_code_signing = false;

	int				r;


	signature_free(x509->hash);
	x509->hash = NULL;

	r = gnutls_pubkey_get_preferred_hash_algorithm(x509->pubkey,
						       &hash_alg,
						       &hash_mand);
	if (r < 0) {
		x509_perror("gnutls_pubkey_get_preferred_hash_algorithm()", r);
		goto err;
	}

	switch (hash_alg) {
	case GNUTLS_DIG_MD5:
		x509->hash = signature_algorithm_md5_create();
		break;

	case GNUTLS_DIG_SHA1:
		x509->hash = signature_algorithm_sha1_create();
		break;

	case GNUTLS_DIG_SHA256:
		x509->hash = signature_algorithm_sha256_create();
		break;

	case GNUTLS_DIG_SHA512:
		x509->hash = signature_algorithm_sha512_create();
		break;

	default:
		fprintf(stderr, "unsupported hahs algorithm %d\n", hash_alg);
		goto err;
	}

	if (!x509->hash) {
		fprintf(stderr, "failed to create hash algorithm %d\n", hash_alg);
		goto err;
	}

	x509->hash_alg = hash_alg;

	if (!signature_reset(x509->hash))
		goto err;

	r = gnutls_x509_crt_list_verify(&x509->crt, 1,
					x509->ca_list.crt, x509->ca_list.num,
					x509->crl_list.crl, x509->crl_list.num,
					GNUTLS_VERIFY_DISABLE_TRUSTED_TIME_CHECKS |
					GNUTLS_VERIFY_DISABLE_TIME_CHECKS |
					GNUTLS_VERIFY_ALLOW_X509_V1_CA_CRT,
					&verify_result);
	if (r < 0) {
		x509_perror("gnutls_x509_crt_list_verify()", r);
		goto err;
	}

	if (verify_result != 0 && !x509->skip_verify) {
		fprintf(stderr, "verification error 0x%04x\ncertificate: ",
			verify_result);
		x509_dump_cert(stderr, x509->crt);
		fprintf(stderr, "\n");

		goto err;
	}

	for (i = 0;; ++i) {
		char		buf[sizeof GNUTLS_KP_CODE_SIGNING];
		size_t		buf_len = sizeof buf;
		unsigned int	crit_flag;
		bool		matched;

		r = gnutls_x509_crt_get_key_purpose_oid(x509->crt, i,
							buf, &buf_len,
							&crit_flag);

		if (r == GNUTLS_E_SHORT_MEMORY_BUFFER)
			matched = false;
		else if (r == GNUTLS_E_SUCCESS)
			matched = (strcmp(buf, GNUTLS_KP_CODE_SIGNING) == 0);
		else if (r == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
			break;
		else {
			x509_perror("gnutls_x509_crt_get_key_purpose_oid()", r);
			goto err;
		}

		is_critical |= crit_flag;
		kp_code_signing |= matched;
	}

	if (!kp_code_signing && !x509->skip_purpose) {
		fprintf(stderr, 
			"certificate not usable for code signing\ncertificate: ");
		x509_dump_cert(stderr, x509->crt);
		fprintf(stderr, "\n");

		goto err;
	}

	return true;

err:
	return false;
}

static bool x509_gnutls_update(struct signature_algorithm *alg,
			       void const *data, size_t len)
{
	struct x509_gnutls	*x509 = tox509(alg);

	return signature_update(x509->hash, data, len);
}

static bool x509_gnutls_pipein(struct signature_algorithm *alg,
			       int fd, size_t len)
{
	struct x509_gnutls	*x509 = tox509(alg);

	return signature_pipein(x509->hash, fd, len);
}

static bool x509_gnutls_verify(struct signature_algorithm *alg,
			       void const *sig, size_t len)
{
	struct x509_gnutls	*x509 = tox509(alg);

	gnutls_datum_t		sig_dat;
	int			r;
	gnutls_datum_t		hash_dat;

	void const		*hash;
	size_t			hash_len;


	bool			rc = false;

	sig_dat.data = (void *)sig;
	sig_dat.size = len;

	if (!signature_finish(x509->hash, &hash, &hash_len))
		goto out;;

	hash_dat.data = (void *)hash;
	hash_dat.size = hash_len;

	r = gnutls_pubkey_verify_hash(x509->pubkey, 0, &hash_dat, &sig_dat);
	if (r < 0) {
		x509_perror("gnutls_pubkey_verify_hash()", r);
		goto out;;
	}

	rc = true;

out:
	return rc;

}

static bool x509_gnutls_begin(struct signature_algorithm *alg,
			      void const **dst, size_t *len)
{
	struct x509_gnutls	*x509 = tox509(alg);
	void			*crt_buf = NULL;
	size_t			crt_len = 0;
	int			r;

	r = gnutls_x509_crt_export(x509->crt, GNUTLS_X509_FMT_DER,
				   crt_buf, &crt_len);
	if (r != GNUTLS_E_SHORT_MEMORY_BUFFER) {
		x509_perror("gnutls_pubkey_export()", r);
		goto err;
	}

	crt_buf = calloc(1, crt_len);
	if (crt_buf == NULL) {
		perror("calloc(gnutls-sig)");
		goto err;
	}
		
	r = gnutls_x509_crt_export(x509->crt, GNUTLS_X509_FMT_DER,
				   crt_buf, &crt_len);
	if (r < 0) {
		x509_perror("gnutls_x509_crt_export()", r);
		goto err;
	}

	gnutls_free(x509->crt_buf);
	x509->crt_buf = crt_buf;

	*dst = crt_buf;
	*len = crt_len;

	return true;

err:
	gnutls_free(crt_buf);
	return false;

}

static bool x509_gnutls_finish(struct signature_algorithm *alg,
			       void const **dst, size_t *len)
{
	struct x509_gnutls	*x509 = tox509(alg);
	void const		*hash;
	size_t			hash_len;
	int			r;
	gnutls_datum_t		hash_dat;
	gnutls_datum_t		signature = { .data = NULL };

	if (!signature_finish(x509->hash, &hash, &hash_len))
		goto err;

	hash_dat.data = (void *)hash;
	hash_dat.size = hash_len;

	r = gnutls_privkey_sign_hash(x509->privkey, x509->hash_alg, 0,
				     &hash_dat, &signature);
	if (r < 0) {
		x509_perror("gnutls_privkey_sign_hash()", r);
		goto err;
	}

	r = gnutls_pubkey_verify_hash(x509->pubkey, 0, &hash_dat, &signature);
	if (r < 0) {
		x509_perror("gnutls_pubkey_verify_hash()", r);
		abort();
		goto err;
	}		

	gnutls_free(x509->signature.data);
	x509->signature.data = signature.data;
	x509->signature.size = signature.size;

	*dst = x509->signature.data;
	*len = x509->signature.size;

	return true;

err:
	gnutls_free(signature.data);
	return false;
}

static bool x509_gnutls_setstrength(struct signature_algorithm *alg,
				    unsigned int strength)
{
	struct x509_gnutls	*x509 = tox509(alg);

	x509->skip_purpose = strength < 100;
	x509->skip_verify  = strength <  20;

	return strength <= 100;
}

static void x509_gnutls_free(struct signature_algorithm *alg)
{
	struct x509_gnutls	*x509 = tox509(alg);

	gnutls_free(x509->signature.data);
	gnutls_free(x509->crt_buf);

	if (x509->pubkey)
		gnutls_pubkey_deinit(x509->pubkey);
	if (x509->crt)
		gnutls_x509_crt_deinit(x509->crt);
	if (x509->privkey)
		gnutls_privkey_deinit(x509->privkey);
	if (x509->key)
		gnutls_x509_privkey_deinit(x509->key);

	signature_free(x509->hash);
	free(x509);
}

struct signature_algorithm *	signature_algorithm_x509_create(void)
{
	struct x509_gnutls		*x509;

	x509 = calloc(1, sizeof *x509);
	if (!x509) {
		perror("calloc(<x509-gnutls>)");
		goto err;
	}

	x509->alg.strength = 100;
	x509->alg.reset    = x509_gnutls_reset;
	x509->alg.update   = x509_gnutls_update;
	x509->alg.pipein   = x509_gnutls_pipein;
	x509->alg.free     = x509_gnutls_free;
	x509->alg.begin    = x509_gnutls_begin;
	x509->alg.finish   = x509_gnutls_finish;
	x509->alg.verify   = x509_gnutls_verify;
	x509->alg.setopt   = x509_gnutls_setopt;
	x509->alg.setstrength = x509_gnutls_setstrength;

	return &x509->alg;

err:
	if (x509) {
		free(x509);
	}

	return NULL;
}

static void __attribute__((__constructor__)) signature_algorithm_x509_init(void)
{
	gnutls_global_init();
}

static void __attribute__((__destructor__)) signature_algorithm_x509_deinit(void)
{
	gnutls_global_deinit();
}
