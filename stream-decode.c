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

#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sysexits.h>
#include <fcntl.h>

#include <getopt.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/wait.h>

#include "signature.h"

#define CMD_HELP                0x1000
#define CMD_VERSION             0x1001

#define CMD_CAFILE		0x2000
#define CMD_CRLFILE		0x2001

#define MAX_SIGNATURE_SIZE	(1 * 1024 * 1024)

#define PROCESS_SIZE	(1024*1024)

static struct option const		CMDLINE_OPTIONS[] = {
	{ "help",         no_argument,       0, CMD_HELP },
	{ "version",      no_argument,       0, CMD_VERSION },
	{ "execute",      required_argument, 0, 'x' },
	{ "verify",       no_argument, 	     0, 'v' },
	{ "min-strength", required_argument, 0, 'S' },
	{ "gpg-key",      required_argument, 0, 'G' },
	{ "ca",           required_argument, 0, CMD_CAFILE },
	{ "crl",          required_argument, 0, CMD_CRLFILE },
	{ NULL, 0, 0, 0 }
};

struct stream_data {
	int		fd;
	bool		is_eos;
};

struct filename_list {
	char const		**names;
	size_t			num;
};

struct signature_options {
	unsigned int		min_strength;
	struct filename_list	ca_files;
	struct filename_list	crl_files;
};

struct memory_block {
	struct stream_data	*stream;
	void const		*data;
	size_t			len;
};

struct memory_block_data {
	struct memory_block	mem;
	unsigned int		type;
	enum stream_compression	compression;
	size_t			len;
};

struct memory_block_signature {
	struct memory_block	pre;
	struct memory_block	mem;
	enum stream_signature	type;

	struct signature_options const	*opts;

	struct stream_header const	*shdr;
	struct stream_hunk_header const	*hhdr;
};

static void show_help(void)
{
	printf("Usage: stream-decode --execute|-x <prog>\n");
	exit(0);
}

static void show_version(void)
{
	/* \todo: implement me */
	exit(0);
}

static bool	stream_data_open(struct stream_data *s, int fd)
{
	s->fd = fd;
	s->is_eos = false;
	return fd >= 0;
}

static void	stream_data_close(struct stream_data *s)
{
	close(s->fd);
}

static bool	stream_data_read(struct stream_data *s, void *buf, size_t cnt,
				 bool ignore_eos)
{
	size_t		tlen = 0;

	while (cnt > 0) {
		ssize_t		l = read(s->fd, buf, cnt);

		if (l > 0) {
			cnt  -= l;
			buf  += l;
			tlen += l;
		} else if (l < 0) {
			perror("read()");
			break;
		} else {
			if (tlen > 0 || !ignore_eos)
				fprintf(stderr, "%s: EOS reached while reading\n",
					__func__);
			else
				cnt = 0;

			s->is_eos = true;
			break;
		}
	}

	return cnt == 0;
}

static bool set_signature_opts(struct signature_algorithm *sigalg,
			       struct signature_options const *opts)
{
	size_t		i;

	if (!signature_setstrength(sigalg, opts->min_strength)) {
		fprintf(stderr, "signature algorithm not strong enough (%u < %u)\n",
			sigalg->strength, opts->min_strength);
		return false;
	}

	for (i = 0; i < opts->ca_files.num; ++i) {
		switch (signature_setopt(sigalg, "ca", opts->ca_files.names[i], 0)) {
		case SIGNATURE_SETOPT_SUCCESS:
		case SIGNATURE_SETOPT_NOOPT:
			break;

		case SIGNATURE_SETOPT_ERROR:
			fprintf(stderr, "failed to setup CA file '%s'\n",
				opts->ca_files.names[i]);
			return false;
		}
	}

	for (i = 0; i < opts->crl_files.num; ++i) {
		switch (signature_setopt(sigalg, "crl", opts->crl_files.names[i], 0)) {
		case SIGNATURE_SETOPT_SUCCESS:
		case SIGNATURE_SETOPT_NOOPT:
			break;

		case SIGNATURE_SETOPT_ERROR:
			fprintf(stderr, "failed to setup CRL file '%s'\n",
				opts->crl_files.names[i]);
			return false;
		}
	}

	return true;
}

static struct signature_algorithm *
create_sigalg(struct memory_block_signature const *signature)
{
	struct signature_algorithm	*sigalg = NULL;

	if ((signature->type != STREAM_SIGNATURE_NONE && signature->mem.len != ~0u) ||
	    (signature->type == STREAM_SIGNATURE_NONE && signature->mem.len == ~0u)) {
		fprintf(stderr, "bad signature length %zu\n",
			signature->mem.len);
		return false;
	}

	switch (signature->type) {
	case STREAM_SIGNATURE_NONE:
		sigalg = signature_algorithm_none_create();
		break;

	case STREAM_SIGNATURE_SHA1:
		sigalg = signature_algorithm_sha1_create();
		break;

	case STREAM_SIGNATURE_SHA256:
		sigalg = signature_algorithm_sha256_create();
		break;

	case STREAM_SIGNATURE_X509:
		sigalg = signature_algorithm_x509_create();
		break;

	case STREAM_SIGNATURE_GPG:
		/* \todo: implement me */
		fprintf(stderr, "signature type %u not implemented yet\n",
			signature->type);
		return false;

	default:
		fprintf(stderr, "unknown signature type %u\n", signature->type);
		return false;
	}

	if (!sigalg) {
		fprintf(stderr, "failed to create signature algorithm %d\n",
			signature->type);
		return false;
	}

	if (!set_signature_opts(sigalg, signature->opts))
		goto err;

	if (signature->pre.len) {
		unsigned char	sig[MAX_SIGNATURE_SIZE];

		if (signature->pre.len > sizeof sig) {
			fprintf(stderr, "signature prefix too large (%zu)\n",
				signature->pre.len);
			goto err;
		}

		if (!stream_data_read(signature->pre.stream, &sig,
				      signature->pre.len, false)) {
			fprintf(stderr, "failed to read signature\n");
			goto err;
		}

		switch (signature_setopt(sigalg, "info-bin", sig, 
					 signature->pre.len)) {
		case SIGNATURE_SETOPT_SUCCESS:	
			break;
		case SIGNATURE_SETOPT_NOOPT:
			fprintf(stderr, "signature prefix not supported\n");
			goto err;
		case SIGNATURE_SETOPT_ERROR:
			fprintf(stderr, "failed to register signature prefix\n");
			goto err;
		}
	}

	if (!signature_reset(sigalg))
		goto err;

	return sigalg;

err:
	signature_free(sigalg);
	return NULL;
}

static bool	process_hunk(char const *program,
			     struct memory_block_data const *payload,
			     struct memory_block_signature const *signature)
{
	size_t				len;
	pid_t				pid = -1;
	int				pfds[2] = { -1, -1 };
	struct signature_algorithm	*sigalg = NULL;

	switch (payload->compression) {
	case STREAM_COMPRESS_NONE:
		if (payload->len != payload->mem.len) {
			fprintf(stderr,
				"compression len mismatch (%zu vs. %zu)\n",
				payload->len, payload->mem.len);
			return false;
		}
		break;

	case STREAM_COMPRESS_GZIP:
	case STREAM_COMPRESS_XZ:
		/* \todo: implement me */
		fprintf(stderr, "compression mode %u not implemented yet\n",
			payload->compression);
		return false;

	default:
		fprintf(stderr, "unknown compression mode %u\n",
			payload->compression);
		return false;
	}

	sigalg = create_sigalg(signature);
	if (!sigalg)
		goto err;

	if (pipe(pfds) < 0) {
		perror("pipe()");
		goto err;
	}

	if (!signature_update(sigalg, signature->shdr->salt,
			      sizeof signature->shdr->salt))
		goto err;

	pid = fork();
	if (pid < 0) {
		perror("fork()");
		goto err;
	}

	if (pid == 0) {
		char	size_str[sizeof(size_t)*3 + 2];
		char	type_str[sizeof(unsigned int)*3 + 2];

		if (!signature_setenv(sigalg)) {
			fprintf(stderr, "failed to export signature details\n");
			_exit(1);
		}

		close(pfds[1]);
		if (dup2(pfds[0], 0) < 0) {
			perror("dup2()");
			_exit(1);
		}

		if (pfds[0] != 0)
			close(pfds[0]);

		sprintf(size_str, "%zu", payload->len);
		sprintf(type_str, "%u", payload->type);

		execlp(program, program, type_str, size_str, NULL);
		perror("execlp()");
		_exit(1);
	}

	close(pfds[0]);
	pfds[0] = -1;
	for (len = 0; len < payload->mem.len && !payload->mem.stream->is_eos;) {
		ssize_t		l;

		/* \todo: implement decompressor */
		l = tee(payload->mem.stream->fd, pfds[1],
			payload->mem.len - len, SPLICE_F_MORE);
		if (l == 0)
			payload->mem.stream->is_eos = true;
		else if (l < 0 && errno == EINTR) {
			continue;
		} else if (l < 0) {
			perror("tee()");
			break;
		}

		if (!signature_pipein(sigalg, payload->mem.stream->fd, l))
			break;

		len += l;
	}
	close(pfds[1]);
	pfds[1] = -1;

	if (len != payload->mem.len) {
		fprintf(stderr, "failed to read all payload data (%zu < %zu)\n",
			len, payload->mem.len);
		goto err;
	}

	if (signature->mem.len) {
		be32_t		tmp;
		unsigned char	sig[MAX_SIGNATURE_SIZE];

		if (!stream_data_read(signature->mem.stream,
				      &tmp, sizeof tmp, false)) {
			fprintf(stderr, "failed to read signature length\n");
			goto err;
		}

		len = be32toh(tmp);
		if (len > sizeof sig) {
			fprintf(stderr, "signature too large (%zu)\n", len);
			goto err;
		}

		if (!stream_data_read(signature->mem.stream, &sig, len, false)) {
			fprintf(stderr, "failed to read signature\n");
			goto err;
		}

		if (!signature_verify(sigalg, sig, len)) {
			fprintf(stderr, "failed to verify signature\n");
			goto err;
		}
	}

	signature_free(sigalg);

	wait(NULL);
	/* \todo: evaluate exit code */

	return true;

err:
	if (pfds[0] != -1)
		close(pfds[0]);

	if (pfds[1] != -1)
		close(pfds[0]);

	signature_free(sigalg);

	if (pid != -1) {
		kill(pid, SIGTERM);
		waitpid(pid, NULL, 0);
	}

	return false;
}

static bool add_filename(struct filename_list *lst, char const *fname)
{
	char const	**new_names;

	new_names = realloc(lst->names, sizeof lst->names[0] * (lst->num + 1));
	if (!new_names) {
		perror("realloc(<filename-lst>)");
		return false;
	}

	new_names[lst->num] = fname;
	lst->names = new_names;
	lst->num  += 1;
	return true;
}

int main(int argc, char *argv[])
{
	struct stream_data	stream;
	struct stream_header	hdr;
	char const		*program = "/bin/false";
	struct signature_options sigopts = {
		.min_strength	=  0,
	};

	while (1) {
		int         c = getopt_long(argc, argv, "vx:S:",
					    CMDLINE_OPTIONS, NULL);

		if (c==-1)
			break;

		switch (c) {
		case CMD_HELP     :  show_help();
		case CMD_VERSION  :  show_version();
		case 'x' :  program = optarg; break;
		case 'v' :  sigopts.min_strength = 1; break;
		case 'S':   sigopts.min_strength = atoi(optarg); break;

		case CMD_CAFILE:
			if (!add_filename(&sigopts.ca_files, optarg))
				return EX_OSERR;
			break;

		case CMD_CRLFILE:
			if (!add_filename(&sigopts.crl_files, optarg))
				return EX_OSERR;
			break;

		default:
			fprintf(stderr, "Try --help for more information\n");
			return EX_USAGE;
		}
	}

	if (!stream_data_open(&stream, 0))
		return EX_OSERR;

	if (!stream_data_read(&stream, &hdr, sizeof hdr, false))
		return EX_DATAERR;

	if (be32toh(hdr.magic) != STREAM_HEADER_MAGIC) {
		fprintf(stderr, "bad stream magic\n");
		return EX_DATAERR;
	}

	for (;;) {
		struct stream_hunk_header	hhdr;
		struct memory_block_data	payload;
		struct memory_block_signature	signature;

		if (!stream_data_read(&stream, &hhdr, sizeof hhdr, true))
			return EX_DATAERR;

		if (stream.is_eos)
			break;

		payload.mem.stream   = &stream;
		payload.mem.len      = be32toh(hhdr.hunk_len);
		payload.mem.data     = NULL;
		payload.type         = be32toh(hhdr.type);
		payload.compression  = hhdr.compress_type;
		payload.len          = be32toh(hhdr.decompress_len);

		signature.opts       = &sigopts;
		signature.pre.stream = &stream;
		signature.pre.len    = be32toh(hhdr.prefix_len);
		signature.pre.data   = NULL;
		signature.mem.stream = &stream;
		signature.mem.len    = be32toh(hhdr.fixed_sign_len);
		signature.mem.data   = NULL;
		signature.type       = hhdr.sign_type;
		signature.shdr       = &hdr;
		signature.hhdr       = &hhdr;

		if (!process_hunk(program, &payload, &signature))
			return EX_DATAERR;
	}

	stream_data_close(&stream);

	free(sigopts.ca_files.names);
	free(sigopts.crl_files.names);
}
