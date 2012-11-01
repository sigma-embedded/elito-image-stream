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

#include "signature.h"

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

static int g_fd_devnull = -1;

static bool signature_none_reset(struct signature_algorithm *a)
{
	return true;
}

static bool signature_none_update(struct signature_algorithm *alg,
				  void const *data, size_t len)
{
	return true;
}

static bool signature_none_pipein(struct signature_algorithm *alg,
				  int fd, size_t len)
{
	while (len > 0) {
		ssize_t		l = splice(fd, NULL, g_fd_devnull, NULL, len,
					   SPLICE_F_MOVE|SPLICE_F_MORE);

		if (l == 0)
			break;
		else if (l < 0) {
			perror("splice()");
			break;
		} else
			len -= l;
	}

	return len == 0;
}

static bool signature_none_finish(struct signature_algorithm *alg,
				  void const **dst, size_t *dst_len)
{	
	*dst = NULL;
	*dst_len = 0;

	return true;
}

static void signature_none_free(struct signature_algorithm *alg)
{
}

static struct signature_algorithm	signature_none = {
	.strength	=  0,
	.reset		=  signature_none_reset,
	.update		=  signature_none_update,
	.pipein		=  signature_none_pipein,
	.finish		=  signature_none_finish,
	.free		=  signature_none_free,
};

static void signature_none_cleanup(void)
{
	close(g_fd_devnull);
}

struct signature_algorithm *signature_algorithm_none_create(void)
{
	if (g_fd_devnull == -1) {
		g_fd_devnull = open("/dev/null", O_WRONLY|O_CLOEXEC);

		if (g_fd_devnull == -1) {
			perror("open(<dev/null>)");
			return NULL;
		}

		atexit(signature_none_cleanup);
	}

	return &signature_none;
}
