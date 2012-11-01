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

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

bool _signature_pipein(struct signature_algorithm *alg, int fd, size_t len)
{
	while (len > 0) {
		unsigned char	buf[4096];
		size_t		tlen = len > sizeof buf ? sizeof buf : len;
		ssize_t		l = read(fd, buf, tlen);

		if (l > 0) {
			len  -= l;
		} else if (l == 0) {
			fprintf(stderr, "failed to read piped sig data\n");
			break;
		} else if (errno == EINTR) {
			continue;
		} else {
			perror("read(<signature-pipe>)");
			break;
		}

		alg->update(alg, buf, tlen);
	}
	
	return len == 0;
}

bool _signature_verify(struct signature_algorithm *alg, void const *sig, 
		       size_t len)
{
	void const	*exp;
	size_t		exp_len;

	if (!alg->finish(alg, &exp, &exp_len))
		return false;

	if (len != exp_len) {
		fprintf(stderr, "unexpected sig len (%zu vs. %zu)\n", 
			len, exp_len);
		return false;
	}

	if (memcmp(sig, exp, len) != 0) {
		fprintf(stderr, "signature mismatch\n");
		return false;
	}

	return true;
}
