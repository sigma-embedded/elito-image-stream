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
#include <sysexits.h>

#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/stat.h>

#define CMD_HELP                0x1000
#define CMD_VERSION             0x1001

static struct option const		CMDLINE_OPTIONS[] = {
	{ "help",        no_argument,       0, CMD_HELP },
	{ "version",     no_argument,       0, CMD_VERSION },
	{ "hunk",        required_argument, 0, 'h' },
	{ NULL, 0, 0, 0 }
};

static void show_help(void)
{
	printf("Usage: stream-encode [--hunk|-h <type>[,<opts>]=<filename>]\n");
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
	char const			*filename;
};

static bool register_hunk(char const *desc, struct hunk **hunks,
			  size_t *num_hunks)
{
	char		*errptr;
	struct hunk	res = {};
	struct hunk	*new_hunks;

	res.type = strtoul(desc, &errptr, 0);
	res.compression = STREAM_COMPRESS_NONE;

	switch (*errptr) {
	case ',':
		/* \todo: implement me */
		fprintf(stderr, "opts-parsing not implemented yet\n");
		return false;

	case '=':
		res.filename = errptr + 1;
		break;

	default:
		fprintf(stderr, "invalid hunk description '%s'\n", desc);
		return false;
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

static bool	dump_hunk(int ofd, struct hunk const *hunk,
			  struct stream_header const *shdr)
{
	struct stream_hunk_header	hdr = {
		.type	=  htobe32(hunk->type),
		.sign_type = STREAM_SIGNATURE_NONE,
		.compress_type = STREAM_COMPRESS_NONE,
		.sign_len = htobe32(0),
	};
	struct stat			st;
	int				hfd;
	bool				rc = false;

	(void)shdr;

	hfd = open(hunk->filename, O_RDONLY);
	if (hfd < 0) {
		perror("open(<hunk>)");
		return false;
	}

	if (fstat(hfd, &st) < 0) {
		perror("stat()");
		goto out;
	}

	hdr.hunk_len = htobe32(st.st_size);
	hdr.decompress_len = htobe32(st.st_size);

	write_all(ofd, &hdr, sizeof hdr);
	for (;;) {
		unsigned char	buf[1024*1024];
		ssize_t		l = read(hfd, buf, sizeof buf);

		if (l == 0)
			break;
		if (l < 0 && errno == EINTR)
			continue;
		if (l < 0) {
			perror("read(<hunk>)");
			goto out;
		}

		if (!write_all(ofd, buf, l))
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

	struct stream_header	hdr = {
		.magic = htobe32(STREAM_HEADER_MAGIC),
		.version = 0,
	};

	while (1) {
		int         c = getopt_long(argc, argv, "h:",
					    CMDLINE_OPTIONS, 0);

		if (c==-1)
			break;

		switch (c) {
		case CMD_HELP     :  show_help();
		case CMD_VERSION  :  show_version();
		case 'h' :
			if (!register_hunk(optarg, &hunks, &num_hunks))
				return EX_USAGE;
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

	write_all(1, &hdr, sizeof hdr);
	for (i = 0; i < num_hunks; ++i) {
		if (!dump_hunk(1, &hunks[i], &hdr))
			return EX_DATAERR;
	}
}
