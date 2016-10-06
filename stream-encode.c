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

#include "stream.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sysexits.h>

#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

#include <sys/stat.h>

#include "util.h"
#include "signature.h"
#include "compression.h"

#define CMD_HELP                0x1000
#define CMD_VERSION             0x1001

static struct option const		CMDLINE_OPTIONS[] = {
	{ "help",        no_argument,       0, CMD_HELP },
	{ "version",     no_argument,       0, CMD_VERSION },
	{ "hunk",        required_argument, 0, 'h' },
	{ "stream-version", required_argument, 0, 'V' },
	{ NULL, 0, 0, 0 }
};

static void show_help(void)
{
	printf("Usage: stream-encode [-V <version>]\n"
	       "            [--hunk|-h <type>[,<opts>]!<filename>]\n");
	exit(0);
}

static void show_version(void)
{
	/* \todo: implement me */
	exit(0);
}

struct hunk {
	unsigned int			type;
	enum stream_compression		compression;
	enum stream_signature		signature;
	char const			*filename;

	struct signature_algorithm *	sig_alg;
	struct compression_algorithm *	compress_alg;

	void const *			extra_salt;
	size_t				extra_salt_len;
};

static struct {
	char const		*id;
	enum stream_signature	signature;
	struct signature_algorithm *(*generator)(void);
} const			SIGNATURE_ALGORITHMS[] = {
	{ "none",   STREAM_SIGNATURE_NONE,   signature_algorithm_none_create },
	{ "md5",    STREAM_SIGNATURE_MD5,    signature_algorithm_md5_create },
	{ "sha1",   STREAM_SIGNATURE_SHA1,   signature_algorithm_sha1_create },
	{ "sha256", STREAM_SIGNATURE_SHA256, signature_algorithm_sha256_create },
	{ "sha512", STREAM_SIGNATURE_SHA512, signature_algorithm_sha512_create },
	{ "x509",   STREAM_SIGNATURE_X509,   signature_algorithm_x509_create },
//	{ "gpg",    STREAM_SIGNATURE_GPG },
};

static struct {
	char const		*id;
	enum stream_compression	compression;
	struct compression_algorithm *(*generator)(void);
} const			COMPRESSION_ALGORITHMS[] = {
	{ "copy",   STREAM_COMPRESS_NONE, NULL },
#ifdef ENABLE_ZLIB
	{ "gzip",   STREAM_COMPRESS_GZIP, compression_algorithm_gzip_create },
	{ "zlib",   STREAM_COMPRESS_GZIP, compression_algorithm_gzip_create },
#endif

#ifdef ENABLE_XZ
	{ "xz",     STREAM_COMPRESS_XZ,   compression_algorithm_xz_create },
#endif
};

static bool parse_signature(enum stream_signature *sig,
			    struct signature_algorithm **alg,
			    char const *str)
{
	struct signature_algorithm	*new_alg = NULL;
	enum stream_signature		new_sig = new_sig;
	size_t				i;

	for (i = 0; i < ARRAY_SIZE(SIGNATURE_ALGORITHMS) && new_alg == NULL; ++i) {
		if (strcmp(str, SIGNATURE_ALGORITHMS[i].id) != 0)
			continue;

		new_sig = SIGNATURE_ALGORITHMS[i].signature;
		new_alg = SIGNATURE_ALGORITHMS[i].generator();
	}

	if (new_alg) {
		signature_free(*alg);
		*alg = new_alg;
		*sig = new_sig;
	}

	return new_alg != NULL;
}

static bool parse_compression(enum stream_compression *cmp,
			      struct compression_algorithm **alg,
			      char const *str)
{
	struct compression_algorithm	*new_alg = NULL;
	enum stream_compression		new_cmp = new_cmp;
	size_t				i;


	for (i = 0; i < ARRAY_SIZE(COMPRESSION_ALGORITHMS) && new_alg == NULL; ++i) {
		if (strcmp(str, COMPRESSION_ALGORITHMS[i].id) != 0)
			continue;

		new_cmp = COMPRESSION_ALGORITHMS[i].compression;
		new_alg = COMPRESSION_ALGORITHMS[i].generator();
	}

	if (new_alg) {
		compression_free(*alg);
		*alg = new_alg;
		*cmp = new_cmp;
	}

	return new_alg != NULL;
}

static char const *parse_hunk_opts(struct hunk *hunk, char const *opt)
{
	char const	*next = strchr(opt, ',');
	char		*val;
	size_t		opt_len;
	char		*cur_opt;
	char const	*key;

	if (next == NULL)
		next = strchr(opt, '!');

	if (next == NULL)
		next = opt + strlen(opt);

	opt_len = next - opt;
	cur_opt = alloca(opt_len + 1);

	memcpy(cur_opt, opt, opt_len);
	cur_opt[opt_len] = '\0';

	val = strchr(cur_opt, '=');
	if (val)
		*val++ = '\0';

	assert(hunk->sig_alg != NULL);

	key = cur_opt;
	if (val == NULL && parse_signature(&hunk->signature,
					   &hunk->sig_alg, key))
		return next;

	if (val == NULL && parse_compression(&hunk->compression,
					     &hunk->compress_alg, key))
		return next;

	if (strcmp(key, "sig") == 0) {
		if (val == NULL ||
		    !parse_signature(&hunk->signature, &hunk->sig_alg, val)) {
			fprintf(stderr,
				"unsupported signature algorithm '%s'\n", val);
			return NULL;
		}

		return next;
	}

	if (strcmp(key, "pack") == 0 || strcmp(key, "compression") == 0) {
		if (val == NULL ||
		    !parse_compression(&hunk->compression, &hunk->compress_alg,
				       val)) {
			fprintf(stderr,
				"unsupported compression algorithm '%s'\n", val);
			return NULL;
		}

		return next;
	}

	assert(hunk->sig_alg != NULL);

	switch (signature_setopt(hunk->sig_alg, key, val, 0)) {
	case SIGNATURE_SETOPT_SUCCESS:
		return next;

	case SIGNATURE_SETOPT_NOOPT:
		fprintf(stderr, "unsupported option '%s' with value '%s'\n",
			key, val);
		return NULL;

	case SIGNATURE_SETOPT_ERROR:
		fprintf(stderr, "failed to set option '%s' with value '%s'\n",
			key, val);
		return NULL;

	default:
		abort();
	}
}

static bool register_hunk(char const *desc, struct hunk **hunks,
			  size_t *num_hunks, uint64_t *total_sz)
{
	char		*errptr;
	char const	*ptr;
	struct hunk	*new_hunks;
	struct stat	st;

	struct hunk	res = {
		.type = strtoul(desc, &errptr, 0),
		.compression = STREAM_COMPRESS_NONE,
		.signature = STREAM_SIGNATURE_NONE,
		.sig_alg = signature_algorithm_none_create(),
	};

	ptr = errptr;

	while (*ptr) {
		switch (*ptr) {
		case ',':
			ptr = parse_hunk_opts(&res, ptr+1);
			if (ptr == NULL)
				return false;

			break;

		case '!':
			res.filename = ptr + 1;
			ptr += strlen(ptr); /* -> points to terminating \0 */
			break;

		default:
			fprintf(stderr, "invalid hunk description '%s'\n", desc);
			return false;
		}
	}

	if (!res.filename) {
		fprintf(stderr, "missing filename in '%s'\n", desc);
		return false;
	}

	if (stat(res.filename, &st) >= 0) {
		/* ignore errors here; they will be catched in dump_hunk() */
		*total_sz += st.st_size;
	}

	new_hunks = realloc(*hunks, (*num_hunks+1) * sizeof *new_hunks);
	if (!new_hunks) {
		perror("realloc()");
		return false;
	}

	*hunks = new_hunks;
	(*hunks)[*num_hunks] = res;
	*num_hunks += 1;

	return true;
}

static bool	dump_hunk(int ofd, struct hunk const *hunk,
			  struct stream_header const *shdr)
{
	struct signature_algorithm	*sig_alg = hunk->sig_alg;
	struct compression_algorithm	*compress_alg = hunk->compress_alg;
	void const			*sig_buf;
	size_t				sig_len;

	struct stream_hunk_header	hdr = {
		.type		= htobe32(hunk->type),
		.sign_type	= hunk->signature,
		.compress_type	= hunk->compression,
		.fixed_sign_len	= ((hunk->signature == STREAM_SIGNATURE_NONE) ?
				   htobe32(0) : htobe32(~0u)),
	};
	struct stat			st;
	int				hfd;
	int				cfd = -1;
	bool				rc = false;

	(void)shdr;

	hfd = open(hunk->filename, O_RDONLY);
	if (hfd < 0) {
		fprintf(stderr, "open(): %m (0x%x|%s)\n",
			hunk->type, hunk->filename);
		return false;
	}

	/* this catches errors which were ignored in register_hunk */
	if (fstat(hfd, &st) < 0) {
		perror("stat()");
		goto out;
	}

	if (!signature_reset(sig_alg))
		goto out;

	if (!signature_begin(sig_alg, &sig_buf, &sig_len))
		goto out;

	hdr.decompress_len = htobe32(st.st_size);
	hdr.prefix_len = htobe32(sig_len);

	/* compress hunk */
	if (compress_alg == NULL) {
		hdr.hunk_len = htobe32(st.st_size);
		cfd = hfd;
	} else if (!compression_reset(compress_alg, st.st_size)) {
		fprintf(stderr, "failed to reset compression\n");
		goto out;
	} else if (!compression_read(compress_alg, sig_alg, hfd, st.st_size)) {
		fprintf(stderr, "failed to compress hunk\n");
		goto out;
	} else {
		ssize_t	clen = compression_finish(compress_alg);
		if (clen < 0) {
			fprintf(stderr, "compression failed\n");
			goto out;
		}

		hdr.hunk_len = htobe32(clen);
		cfd = compress_alg->out_fd;
	}

	write_all(ofd, &hdr, sizeof hdr);
	write_all(ofd, sig_buf, sig_len);

	for (;;) {
		unsigned char	buf[1024*1024];
		ssize_t		l = read(cfd, buf, sizeof buf);

		if (l == 0)
			break;
		if (l < 0 && errno == EINTR)
			continue;
		if (l < 0) {
			perror("read(<hunk>)");
			goto out;
		}

		/* compression pushes data into signature algorithm */
		if (compress_alg == NULL && !signature_update(sig_alg, buf, l))
			goto out;

		if (!write_all(ofd, buf, l))
			goto out;
	}

	if (!signature_update(sig_alg, hunk->extra_salt, hunk->extra_salt_len) ||
	    !signature_update(sig_alg, shdr->salt, sizeof shdr->salt) ||
	    !signature_update(sig_alg, &hdr,       sizeof hdr))
		goto out;

	if (!sig_alg->finish(sig_alg, &sig_buf, &sig_len))
		goto out;

	if (hunk->signature != STREAM_SIGNATURE_NONE) {
		be32_t		sig_len_be = htobe32(sig_len);
		if (!write_all(ofd, &sig_len_be, sizeof sig_len_be) ||
		    !write_all(ofd, sig_buf, sig_len))
			goto out;
	}

	rc = true;

out:
	close(hfd);
	return rc;
}

int main(int argc, char *argv[])
{
	struct hunk		*hunks = NULL;
	size_t			num_hunks = 0;
	size_t			i;
	int			rand_fd;
	uint64_t		total_sz = 0;
	unsigned int		stream_version = 1;

	union {
		struct stream_header_v1	v1;
	}			hdrX;

	struct stream_header	hdr = {
		.magic		= htobe32(STREAM_HEADER_MAGIC),
		.build_time	= htobe64(time(NULL)),
	};

	while (1) {
		int         c = getopt_long(argc, argv, "h:V:",
					    CMDLINE_OPTIONS, 0);

		if (c==-1)
			break;

		switch (c) {
		case CMD_HELP     :  show_help();
		case CMD_VERSION  :  show_version();
		case 'h' :
			if (!register_hunk(optarg, &hunks, &num_hunks, &total_sz))
				return EX_USAGE;
			break;

		case 'V':
			stream_version = atoi(optarg);
			break;

		default:
			fprintf(stderr, "Try --help for more information\n");
			return EX_USAGE;

		}
	}

	rand_fd = open("/dev/urandom", O_RDONLY);
	if (rand_fd < 0 ||
	    read(rand_fd, hdr.salt, sizeof hdr.salt) != sizeof hdr.salt) {
		perror("generating salt");
		return EX_OSERR;
	}
	close(rand_fd);

	hdr.version = htobe32(stream_version);

	switch (stream_version) {
	case 0:
		break;

	case 1:
		hdr.extra_header = htobe32(sizeof hdrX.v1);
		break;

	default:
		fprintf(stderr, "Unsupport stream version %u\n",
			stream_version);
		return EX_USAGE;
	}

	write_all(1, &hdr, sizeof hdr);

	switch (stream_version) {
	case 1:
		hdrX.v1.total_len = htobe64(total_sz);
		write_all(1, &hdrX.v1, sizeof hdrX.v1);
		break;

	default:
		break;
	}

	for (i = 0; i < num_hunks; ++i) {
		signature_setstrength(hunks[i].sig_alg, 0);

		if (!dump_hunk(1, &hunks[i], &hdr))
			return EX_DATAERR;

		signature_free(hunks[i].sig_alg);
		compression_free(hunks[i].compress_alg);
	}

	free(hunks);
}
