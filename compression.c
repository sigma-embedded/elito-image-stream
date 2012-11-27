/*	--*- c -*--
 * Copyright (C) 2012 Enrico Scholz <enrico.scholz@informatik.tu-chemnitz.de>
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

#include "compression.h"

#include <errno.h>
#include <stdio.h>
#include <unistd.h>

bool _compression_read(struct compression_algorithm *alg, 
		       struct signature_algorithm *sig,
		       int fd, size_t len)
{
	while (len > 0) {
		unsigned char	buf[64 * 1024];
		size_t		tlen = len > sizeof buf ? sizeof buf : len;
		ssize_t		l = read(fd, buf, tlen);

		if (l > 0) {
			len  -= l;
		} else if (l == 0) {
			fprintf(stderr, "EOF on uncompressed data\n");
			break;
		} else if (errno == EINTR) {
			continue;
		} else {
			perror("read(<compress>)");
			break;
		}

		if (!alg->update(alg, sig, buf, tlen))
			break;
	}
	
	return len == 0;
}
