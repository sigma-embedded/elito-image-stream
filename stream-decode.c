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

#include <getopt.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/wait.h>

#define CMD_HELP                0x1000
#define CMD_VERSION             0x1001


#define PROCESS_SIZE	(1024*1024)

static struct option const		CMDLINE_OPTIONS[] = {
	{ "help",        no_argument,       0, CMD_HELP },
	{ "version",     no_argument,       0, CMD_VERSION },
	{ "execute",     required_argument, 0, 'x' },
	{ "verify",      no_argument, 	    0, 'v' },
	{ "gpg-key",     required_argument, 0, 'G' },
	{ NULL, 0, 0, 0 }
};

struct stream_data {
	void const	*mem;
	size_t		len;
	size_t		pos;
};

struct memory_block {
	void const	*data;
	size_t		len;
};

struct memory_block_data {
	struct memory_block	mem;
	unsigned int		type;
	enum stream_compression	compression;
	size_t			len;
};

struct memory_block_signature {
	struct memory_block	mem;
	enum stream_signature	type;

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
	struct stat	st;

	if (fstat(fd, &st) < 0) {
		perror("fstat()");
		return false;
	}

	s->len = st.st_size;
	s->mem = mmap(NULL, s->len, PROT_READ, MAP_SHARED, fd, 0);
	s->pos = 0;

	return true;
}

static void	stream_data_close(struct stream_data *s)
{
	munmap((void *)s->mem, s->len);
	s->mem = NULL;
	s->len = 0;
}

static bool	stream_data_read(struct stream_data *s, void *buf, size_t cnt)
{
	if (cnt > s->len - s->pos) {
		fprintf(stderr, "%s: EOF reached while reading %zu bytes\n",
			__func__, cnt);
		return false;		/* EOF */
	}

	memcpy(buf, s->mem + s->pos, cnt);
	s->pos += cnt;

	return true;
}

static bool	stream_data_eof(struct stream_data const *s)
{
	return s->pos == s->len;
}


static void const	*stream_data_get(struct stream_data *s, size_t cnt)
{
	void const	*res;
	if (cnt > s->len - s->pos) {
		fprintf(stderr, "%s: EOF reached while reading %zu bytes\n",
			__func__, cnt);
		res = NULL;		/* EOF */
	} else {
		res = s->mem + s->pos;
		s->pos += cnt;
	}

	return res;
}

static bool	write_all(int fd, void const *buf, size_t len)
{
	while (len > 0) {
		ssize_t	l = write(fd, buf, len);

		if (l > 0) {
			buf += l;
			len -= l;
		} else if (l == 0) {
			fprintf(stderr, "null-write\n");
			break;
		} else if (errno == EINTR)
			continue;
		else {
			perror("write()");
			break;
		}
	}

	return len == 0;
}

static bool	process_hunk(char const *program,
			     struct memory_block_data const *payload,
			     struct memory_block_signature const *signature)
{
	size_t		len;
	pid_t		pid;
	int		pfds[2];

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


	switch (signature->type) {
	case STREAM_SIGNATURE_NONE:
		break;

	case STREAM_SIGNATURE_SHA1:
	case STREAM_SIGNATURE_SHA256:
	case STREAM_SIGNATURE_GPG:
		/* \todo: implement me */
		fprintf(stderr, "signature type %u not implemented yet\n",
			signature->type);
		return false;

	default:
		fprintf(stderr, "unknown signature type %u\n", signature->type);
		return false;
	}

	if (pipe(pfds) < 0) {
		perror("pipe()");
		return false;
	}

	pid = fork();
	if (pid < 0) {
		perror("fork()");
		close(pfds[0]);
		close(pfds[1]);
		return false;
	}

	if (pid == 0) {
		char	size_str[sizeof(size_t)*3 + 2];
		char	type_str[sizeof(unsigned int)*3 + 2];

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
	for (len = 0; len < payload->mem.len;) {
		unsigned char	buf[PROCESS_SIZE];
		size_t		tlen = MIN(payload->mem.len - len, sizeof buf);

		/* \todo: implement decompressor */
		memcpy(buf, payload->mem.data + len, tlen);
		/* \todo: feed buf into signature checker */

		if (!write_all(pfds[1], buf, tlen))
			break;

		len += tlen;
	}
	close(pfds[1]);

	/* \todo: verify signature */

	wait(NULL);
	/* \todo: evaluate exit code */

	return true;
}

int main(int argc, char *argv[])
{
	struct stream_data	stream;
	struct stream_header	hdr;
	char const		*program = "/bin/false";

	while (1) {
		int         c = getopt_long(argc, argv, "x:",
					    CMDLINE_OPTIONS, NULL);

		if (c==-1)
			break;

		switch (c) {
		case CMD_HELP     :  show_help();
		case CMD_VERSION  :  show_version();
		case 'x' :  program = optarg; break;
		case 'v' :  break;		/* \todo: implement verify */
		default:
			fprintf(stderr, "Try --help for more information\n");
			return EX_USAGE;
		}
	}

	if (!stream_data_open(&stream, 0))
		return EX_OSERR;

	close(0);

	if (!stream_data_read(&stream, &hdr, sizeof hdr))
		return EX_DATAERR;

	if (be32toh(hdr.magic) != STREAM_HEADER_MAGIC) {
		fprintf(stderr, "bad stream magic\n");
		return EX_DATAERR;
	}

	while (!stream_data_eof(&stream)) {
		struct stream_hunk_header	hhdr;
		struct memory_block_data	payload;
		struct memory_block_signature	signature;

		if (!stream_data_read(&stream, &hhdr, sizeof hhdr))
			return EX_DATAERR;

		payload.mem.len    = be32toh(hhdr.hunk_len);
		signature.mem.len  = be32toh(hhdr.sign_len);
		payload.mem.data   = stream_data_get(&stream, payload.mem.len);
		signature.mem.data = stream_data_get(&stream, signature.mem.len);

		if (!payload.mem.data || !signature.mem.data)
			return EX_DATAERR;

		payload.type = be32toh(hhdr.type);
		payload.compression = hhdr.compress_type;
		payload.len = be32toh(hhdr.decompress_len);

		signature.type = hhdr.sign_type;
		signature.shdr = &hdr;
		signature.hhdr = &hhdr;

		if (!process_hunk(program, &payload, &signature))
			return EX_DATAERR;
	}

	stream_data_close(&stream);
}
