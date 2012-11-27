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

#include "util.h"

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

bool write_all(int fd, void const *buf, size_t len)
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

