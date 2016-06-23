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
#include <assert.h>
#include <inttypes.h>
#include <netinet/ip.h>

#include <getopt.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/wait.h>

#include "signature.h"
#include "decompression.h"

#include "notify.h"

#define CMD_HELP                0x1000
#define CMD_VERSION             0x1001

#define CMD_CAFILE		0x2000
#define CMD_CRLFILE		0x2001
#define CMD_NOTIFY_PORT		0x2002

#define MAX_SIGNATURE_SIZE	(1 * 1024 * 1024)

#define SIZE_UNSET		(~((size_t)0))

#define PROCESS_SIZE	(1024*1024)

static struct option const		CMDLINE_OPTIONS[] = {
	{ "help",         no_argument,       0, CMD_HELP },
	{ "version",      no_argument,       0, CMD_VERSION },
	{ "execute",      required_argument, 0, 'x' },
	{ "verify",       no_argument,	     0, 'v' },
	{ "min-strength", required_argument, 0, 'S' },
	{ "gpg-key",      required_argument, 0, 'G' },
	{ "ca",           required_argument, 0, CMD_CAFILE },
	{ "crl",          required_argument, 0, CMD_CRLFILE },
	{ "notify-port",  required_argument, 0, CMD_NOTIFY_PORT },
	{ NULL, 0, 0, 0 }
};

struct notify_info {
	int		fd;
	socklen_t	dst_len;

	union {
		struct sockaddr			addr;
		struct sockaddr_storage		_st;
		struct sockaddr_in		ip4;
	}		dst;

	size_t		cur_pos;
};

struct stream_data {
	int		fd;
	bool		is_eos;
	size_t		total_len;
	struct notify_info	notify;
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

static bool notification_send(struct notify_info *notify,
			      void const *msg, size_t msg_len)
{
	ssize_t		l;

	if (notify->fd == -1)
		l = msg_len;
	else
		l = sendto(notify->fd, msg, msg_len, MSG_NOSIGNAL,
			   &notify->dst.addr, notify->dst_len);

	if (l < 0) {
		perror("sendto(<notify>)");
		return false;
	}


	/* we send a datagram and do not want to cope with fragmentation */
	return (size_t)l == msg_len;
}

static bool notification_signal_exit(struct notify_info *notify,
				     unsigned int code)
{
	struct notify_msg_exit		msg = {
		.op		= 'E',
		.code		= htobe32(code),
	};

	return notification_send(notify, &msg, sizeof msg);
}

static bool notification_send_length(struct notify_info *notify, size_t len)
{
	struct notify_msg_length	msg = {
		.op		= 'L',
		.length		= htobe64(len),
	};

	return notification_send(notify, &msg, sizeof msg);
}

static bool notification_handle_read(struct notify_info *notify, size_t cnt)
{
	struct notify_msg_read		msg = {
		.op		= 'R',
		.count		= htobe64(notify->cur_pos + cnt),
	};

	notify->cur_pos += cnt;

	return notification_send(notify, &msg, sizeof msg);
}

static bool notification_init(struct notify_info *notify, int port)
{
	int const	ONE = 1;
	int		fd;
	int		rc;

	if (port == -1) {
		notify->fd = -1;
		return true;
	}

	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		perror("socket(<notification>)");
		return false;
	}

	rc = setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &ONE, sizeof ONE);
	if (rc < 0) {
		perror("setsockopt(SO_BROADCAST)");
		goto err;
	}

	notify->fd   = fd;

	/* assume IPv4 for now; change for IPv6 when needed */
	notify->dst.ip4 = (struct sockaddr_in) {
		.sin_family	= AF_INET,
		.sin_port	= htons(port),
		.sin_addr	= { INADDR_BROADCAST },
	};
	notify->dst_len = sizeof notify->dst.ip4;
	notify->cur_pos = 0;

	if (!notification_send(notify, "S", 1))
		/* when first datagram fails, next one will probably fail
		 * too */
		goto err;

	return true;

err:
	close(fd);
	notify->fd   = -1;

	return false;
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

static unsigned char		g_decompress_buffer[1024*1024];

static struct decompression_algorithm *
create_decompress(struct memory_block_data const *payload)
{
	struct decompression_algorithm	*alg = NULL;
	struct iovec			decomp_vec = {
		.iov_base = g_decompress_buffer,
		.iov_len  = sizeof g_decompress_buffer,
	};

	switch (payload->compression) {
	case STREAM_COMPRESS_NONE:
		if (payload->len != payload->mem.len) {
			fprintf(stderr,
				"compression len mismatch (%zu vs. %zu)\n",
				payload->len, payload->mem.len);
			return false;
		}

		return NULL;

	case STREAM_COMPRESS_GZIP:
		alg = decompression_algorithm_gzip_create(&decomp_vec);
		break;

	case STREAM_COMPRESS_XZ:
		alg = decompression_algorithm_xz_create(&decomp_vec);
		break;

	default:
		fprintf(stderr, "unknown compression mode %u\n",
			payload->compression);
		return false;
	}

	if (!alg) {
		fprintf(stderr, "failed to create decompression algorithm %d\n",
			payload->compression);
		return false;
	}

	return alg;
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

	case STREAM_SIGNATURE_MD5:
		sigalg = signature_algorithm_md5_create();
		break;

	case STREAM_SIGNATURE_SHA1:
		sigalg = signature_algorithm_sha1_create();
		break;

	case STREAM_SIGNATURE_SHA256:
		sigalg = signature_algorithm_sha256_create();
		break;

	case STREAM_SIGNATURE_SHA512:
		sigalg = signature_algorithm_sha512_create();
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

static bool	finish_stream(char const *program,
			      struct memory_block_data const *payload,
			      struct signature_algorithm *sigalg)
{
	pid_t		pid = -1;
	int		status;

	pid = fork();
	if (pid < 0) {
		perror("fork()");
		goto err;
	}

	if (pid == 0) {
		int		fd_null;
		char		size_str[sizeof(size_t)*3 + 2];
		char		type_str[sizeof(unsigned int)*3 + 2];

		if (!signature_setenv(sigalg)) {
			fprintf(stderr, "failed to export signature details\n");
			_exit(1);
		}

		close(0);
		fd_null = open("/dev/null", O_RDONLY|O_NOCTTY);
		if (fd_null < 0) {
			perror("open(/dev/null)");
			goto err;
		} else if (fd_null != 0) {
			fprintf(stderr, "failed to redirect stdin\n");
			goto err;
		}

		sprintf(size_str, "%zu", payload->len);
		sprintf(type_str, "%u", payload->type);

		execlp(program, program, "finish", type_str, size_str, NULL);
		perror("execlp()");
		_exit(1);
	}

	if (TEMP_FAILURE_RETRY(waitpid(pid, &status, 0)) < 0) {
		perror("waitpid()");
		goto err;
	}

	pid = -1;

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		fprintf(stderr, "program failed with %d\n", status);
		goto err;
	}

	return true;

err:
	if (pid != -1) {
		kill(pid, SIGTERM);
		waitpid(pid, NULL, 0);
	}

	return false;
}

static bool stage_transaction(char const *program, char const *stage)
{
	pid_t		pid = -1;
	int		status;

	pid = fork();
	if (pid < 0) {
		perror("fork()");
		goto err;
	}

	if (pid == 0) {
		int		fd_null;

		close(0);
		fd_null = open("/dev/null", O_RDONLY|O_NOCTTY);
		if (fd_null < 0) {
			perror("open(/dev/null)");
			goto err;
		} else if (fd_null != 0) {
			fprintf(stderr, "failed to redirect stdin\n");
			goto err;
		}

		execlp(program, program, stage, "0", "0", NULL);
		perror("execlp()");
		_exit(1);
	}

	if (TEMP_FAILURE_RETRY(waitpid(pid, &status, 0)) < 0) {
		perror("waitpid()");
		goto err;
	}

	pid = -1;

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		fprintf(stderr, "program failed with %d\n", status);
		goto err;
	}

	return true;

err:
	if (pid != -1) {
		kill(pid, SIGTERM);
		waitpid(pid, NULL, 0);
	}

	return false;
}

struct decompressor {
	struct decompression_algorithm	*alg;
	int				fd_in;
	int				fd_out;
	size_t				count_in;
	pid_t				pid;
};

static bool decompressor_wait(struct decompressor *decomp)
{
	int			status;
	int			rc;
	unsigned int		cnt = 20; /* 2 seconds */

	if (decomp->pid == -1)
		return true;

	close(decomp->fd_out);

	do {
		rc = waitpid(decomp->pid, &status, WNOHANG);
		if (rc == 0)
			usleep(100000);
	} while (rc == 0 && cnt-- > 0);

	if (rc == 0) {
		kill(decomp->pid, SIGTERM);
		usleep(100000);
		kill(decomp->pid, SIGKILL);

		rc = waitpid(decomp->pid, &status, 0);
	}

	if (rc < 0) {
		perror("waitpid(<decompressor>)");
		goto err;
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status)) {
		fprintf(stderr, "decompressor failed with %d\n", status);
		goto err;
	}

	decomp->pid = -1;
	return true;

err:
	decomp->pid = -1;
	return false;
}

static bool decompressor_run(struct decompressor *decomp,
			     struct decompression_algorithm *alg,
			     int fd, size_t count_in)
{
	int		pfds[2];

	decomp->alg = alg;
	decomp->pid = -1;
	decomp->count_in = count_in;

	if (alg == NULL) {
		decomp->fd_out = fd;
		decomp->fd_in  = -1;
		return true;
	}

	if (pipe2(pfds, O_CLOEXEC) < 0) {
		perror("pipe2(<decomp>)");
		goto err;
	}

	decomp->fd_in  = fd;
	decomp->fd_out = pfds[0];

	decomp->pid = fork();
	if (decomp->pid == -1) {
		perror("fork(<decomp>)");
		goto err;
	}

	if (decomp->pid == 0) {
		close(pfds[0]);

		if (!alg->splice(alg, fd, pfds[1], count_in)) {
			fprintf(stderr, "failed to uncompress data");
			_exit(1);
		}

		_exit(0);
	}

	close(pfds[1]);
	return true;

err:
	if (pfds[1] != -1)
		close(pfds[1]);

	if (pfds[0] != -1)
		close(pfds[0]);

	assert(decomp->pid == -1);
	decomp->alg = NULL;
	return false;
}

static bool	send_stream(char const *program,
			    struct memory_block_data const *payload,
			    struct signature_algorithm *sigalg,
			    struct decompression_algorithm *decompalg)
{
	struct decompressor		decomp = { .pid = -1 };
	size_t				len;
	pid_t				pid = -1;
	int				pfds[2] = { -1, -1 };
	int				status;

	if (pipe(pfds) < 0) {
		perror("pipe(<pfds>)");
		goto err;
	}

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

		execlp(program, program, "stream", type_str, size_str, NULL);
		perror("execlp()");
		_exit(1);
	}

	close(pfds[0]);
	pfds[0] = -1;

	if (!decompressor_run(&decomp, decompalg,
			      payload->mem.stream->fd, payload->mem.len)) {
		fprintf(stderr, "failed to start decompressor\n");
		goto err;
	}

	for (len = 0; len < payload->len && !payload->mem.stream->is_eos;) {
		ssize_t		l;

		/* \todo: implement decompressor */
		l = tee(decomp.fd_out, pfds[1],
			payload->len - len, SPLICE_F_MORE);
		if (l == 0)
			payload->mem.stream->is_eos = true;
		else if (l < 0 && errno == EINTR) {
			continue;
		} else if (l < 0) {
			perror("tee()");
			break;
		}

		if (!signature_pipein(sigalg, decomp.fd_out, l))
			break;

		len += l;
	}
	close(pfds[1]);
	pfds[1] = -1;

	if (!decompressor_wait(&decomp))
		goto err;

	if (len != payload->len) {
		fprintf(stderr, "failed to read all payload data (%zu < %zu)\n",
			len, payload->len);
		goto err;
	}

	if (waitpid(pid, &status, 0) < 0) {
		perror("waitpid()");
		goto err;
	}

	pid = -1;

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		fprintf(stderr, "program failed with %d\n", status);
		goto err;
	}

	return true;

err:
	if (pfds[0] != -1)
		close(pfds[0]);

	if (pfds[1] != -1)
		close(pfds[0]);

	if (pid != -1) {
		kill(pid, SIGTERM);
		waitpid(pid, NULL, 0);
	}

	decompressor_wait(&decomp);

	return false;
}

static bool	verify_signature(struct memory_block_signature const *signature,
				 struct signature_algorithm	*sigalg)
{
	be32_t		tmp;
	size_t		len;
	unsigned char	sig[MAX_SIGNATURE_SIZE];

	if (!stream_data_read(signature->mem.stream,
			      &tmp, sizeof tmp, false)) {
		fprintf(stderr, "failed to read signature length\n");
		return false;
	}

	len = be32toh(tmp);
	if (len > sizeof sig) {
		fprintf(stderr, "signature too large (%zu)\n", len);
		return false;
	}

	if (!stream_data_read(signature->mem.stream, &sig, len, false)) {
		fprintf(stderr, "failed to read signature\n");
		return false;
	}

	if (!signature_verify(sigalg, sig, len)) {
		fprintf(stderr, "failed to verify signature\n");
		return false;
	}

	return true;
}

static bool	process_hunk(char const *program,
			     struct memory_block_data const *payload,
			     struct memory_block_signature const *signature)
{
	struct signature_algorithm	*sigalg = NULL;
	struct decompression_algorithm	*decompalg = NULL;


	sigalg = create_sigalg(signature);
	if (!sigalg)
		goto err;

	decompalg = create_decompress(payload);
	if (!decompalg && payload->compression != STREAM_COMPRESS_NONE)
		goto err;

	if (!send_stream(program, payload, sigalg, decompalg))
		goto err;

	if (!signature_update(sigalg, signature->shdr->salt,
			      sizeof signature->shdr->salt) ||
	    !signature_update(sigalg, signature->hhdr,
			      sizeof *signature->hhdr))
		goto err;

	if (signature->mem.len && !verify_signature(signature, sigalg))
		goto err;

	if (!finish_stream(program, payload, sigalg))
		goto err;

	signature_free(sigalg);

	return true;

err:
	decompression_free(decompalg);
	signature_free(sigalg);

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

static bool read_hdr_ext(struct stream_data *stream, unsigned int version,
			 size_t len)
{
	union {
		struct stream_header_v1		v1;
	}			hdr;

	switch (version) {
	case 0:
		/* version 0 streams do not have this field */
		len = 0;
		break;

	default:
		/* read extra header as far as possible; we will catch errors
		 * later */
		if (!stream_data_read(stream, &hdr, MIN(len, sizeof hdr), false))
			return false;

		break;
	}

	/* consume the extra header information of future versions; it is
	 * assumed that they do not contain important information and are
	 * e.g. for statistic purposes only.  There must be set senseful
	 * default values */
	if (len > sizeof hdr) {
		size_t		sz = len - sizeof hdr;

		while (sz > 0) {
			char	buf[64];

			if (!stream_data_read(stream, buf, MIN(sizeof buf, sz),
					      false))
				return false;

			sz -= sizeof buf;
		}
	}

	switch (version) {
	case 0:
		stream->total_len = SIZE_UNSET;
		break;

	default:
	case 1:
		if (len < sizeof hdr.v1)
			return false;

		stream->total_len = be64toh(hdr.v1.total_len);
		break;
	}

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
	char			build_time[8*3 + 2];
	int			notify_port = -1;

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

		case CMD_NOTIFY_PORT:
			notify_port = atoi(optarg);
			break;

		default:
			fprintf(stderr, "Try --help for more information\n");
			return EX_USAGE;
		}
	}

	if (!notification_init(&stream.notify, notify_port))
		return EX_OSERR;

	if (!stream_data_open(&stream, 0))
		return EX_OSERR;

	if (!stream_data_read(&stream, &hdr, sizeof hdr, false))
		return EX_DATAERR;

	if (be32toh(hdr.magic) != STREAM_HEADER_MAGIC) {
		fprintf(stderr, "bad stream magic\n");
		return EX_DATAERR;
	}

	if (!read_hdr_ext(&stream, be32toh(hdr.version),
			  be32toh(hdr.extra_header)))
		return EX_DATAERR;

	sprintf(build_time, "%" PRIu64, be64toh(hdr.build_time));
	setenv("STREAM_BUILD_TIME", build_time, 1);

	if (!stage_transaction(program, "start"))
		return EX_OSERR;

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

	if (!stage_transaction(program, "end"))
		return EX_OSERR;
}
