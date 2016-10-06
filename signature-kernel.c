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

#include "signature.h"

#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

#include <sys/socket.h>
#include <linux/if_alg.h>

#include "util.h"

struct signature_kernel_algorithm {
	struct signature_algorithm	alg;
	int				fd_sock;
	int				fd_alg;

	size_t				digest_len;
	unsigned char			digest[];
};
#define tokalg(_alg)	\
	container_of(_alg, struct signature_kernel_algorithm, alg)

static bool signature_kernel_reset(struct signature_algorithm *alg)
{
	struct signature_kernel_algorithm	*kalg = tokalg(alg);
	int	fd = accept4(kalg->fd_sock, NULL, 0, O_CLOEXEC);

	if (fd < 0) {
		perror("accept4(AF_ALG)");
		return false;
	}

	close(kalg->fd_alg);
	kalg->fd_alg = fd;

	return true;
}

static bool signature_kernel_update(struct signature_algorithm *alg,
				    void const *data, size_t len)
{
	struct signature_kernel_algorithm	*kalg = tokalg(alg);

	while (len > 0) {
		ssize_t		l = send(kalg->fd_alg, data, len, MSG_MORE);

		if (l > 0) {
			len  -= l;
			data += l;
		} else if (l == 0) {
			fprintf(stderr, "failed to write data into AF_ALG\n");
			break;
		} else if (errno == EINTR) {
			continue;
		} else {
			perror("write(<AF_ALG>)");
			break;
		}
	}

	return len == 0;
}

static bool signature_kernel_pipein(struct signature_algorithm *alg,
				   int fd, size_t len)
{
	struct signature_kernel_algorithm	*kalg = tokalg(alg);

	while (len > 0) {
		ssize_t		l = splice(fd, NULL, kalg->fd_alg, NULL, len,
					   SPLICE_F_MOVE|SPLICE_F_MORE);

		if (l > 0) {
			len  -= l;
		} else if (l == 0) {
			fprintf(stderr, "failed to splice data into AF_ALG\n");
			break;
		} else if (errno == EINTR) {
			continue;
		} else {
			perror("splice(<AF_ALG>)");
			break;
		}
	}

	return len == 0;
}

static bool signature_kernel_finish(struct signature_algorithm *alg, 
				    void const **dst, size_t *dst_len)
{
	struct signature_kernel_algorithm	*kalg = tokalg(alg);
	size_t					len = (kalg->digest_len+7)/8;
	void					*ptr = kalg->digest;

	while (len > 0) {
		ssize_t	l = read(kalg->fd_alg, ptr, len);

		if (l > 0) {
			len -= l;
			ptr += l;
		} else if (l == 0) {
			fprintf(stderr, "eos while reading digest\n");
			break;
		} else if (errno == EINTR) {
			continue;
		} else {
			perror("read(<AF_ALG>)");
			break;
		}
	}

	if (len != 0)
		return false;

	*dst     = kalg->digest;
	*dst_len = (kalg->digest_len+7)/8;

	return true;
}

static void signature_kernel_free(struct signature_algorithm *alg)
{
	struct signature_kernel_algorithm	*kalg = tokalg(alg);

	close(kalg->fd_alg);
	close(kalg->fd_sock);
	free(kalg);
}

struct signature_algorithm *	signature_kernel_create(char const *hname,
							size_t digest_len)
{
	struct signature_kernel_algorithm	*kalg;
	struct sockaddr_alg			sa = {
		.salg_family = AF_ALG,
		.salg_type = "hash",
	};

	strncpy((char *)sa.salg_name, hname, sizeof sa.salg_name - 1);
	sa.salg_name[sizeof sa.salg_name - 1] = '\0';

	kalg = calloc(1, sizeof *kalg + (digest_len+7) / 8);
	if (!kalg) {
		perror("malloc(<kernel-alg>)");
		goto err;
	}
	kalg->fd_sock = -1;
	kalg->fd_alg = -1;
	kalg->digest_len = digest_len;

	kalg->fd_sock = socket(AF_ALG, SOCK_SEQPACKET | O_CLOEXEC, 0);
	if (kalg->fd_sock < 0) {
		perror("socket(AF_ALG)");
		goto err;
	}

	if (bind(kalg->fd_sock, (void *)&sa, sizeof sa) < 0) {
		perror("bind(AF_ALG)");
		goto err;
	}

	kalg->fd_alg = accept4(kalg->fd_sock, NULL, 0, O_CLOEXEC);
	if (kalg->fd_alg < 0) {
		perror("accept(AF_ALG)");
		goto err;
	}

	kalg->alg.strength = 10;
	kalg->alg.reset    = signature_kernel_reset;
	kalg->alg.update   = signature_kernel_update;
	kalg->alg.pipein   = signature_kernel_pipein;
	kalg->alg.finish   = signature_kernel_finish;
	kalg->alg.free     = signature_kernel_free;

	return &kalg->alg;

err:
	if (kalg) {
		if (kalg->fd_alg != -1)
			close(kalg->fd_alg);

		if (kalg->fd_sock != -1)
			close(kalg->fd_sock);

		free(kalg);
	}

	return NULL;
}

struct signature_algorithm *	signature_algorithm_md5_create(void)
{
	return signature_kernel_create("md5", 128);
}

struct signature_algorithm *	signature_algorithm_sha1_create(void)
{
	return signature_kernel_create("sha1", 160);
}

struct signature_algorithm *	signature_algorithm_sha256_create(void)
{
	return signature_kernel_create("sha256", 256);
}

struct signature_algorithm *	signature_algorithm_sha512_create(void)
{
	return signature_kernel_create("sha512", 512);
}
