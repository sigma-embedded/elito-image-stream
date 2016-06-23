/*	--*- c -*--
 * Copyright (C) 2016 Enrico Scholz <enrico.scholz@sigma-chemnitz.de>
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

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sysexits.h>
#include <netinet/ip.h>

typedef uint64_t	be64_t;
typedef uint32_t	be32_t;
typedef uint16_t	be16_t;
typedef uint8_t		be8_t;

#include "notify.h"

int main(int argc, char *argv[])
{
	int const		ONE = 1;
	int			fd;
	struct sockaddr_in	ip4 = {
		.sin_family	= AF_INET,
		.sin_port	= htons(atoi(argv[1])),
		.sin_addr	= { htonl(INADDR_LOOPBACK) },
	};
	int			rc;

	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		perror("socket(<notification>)");
		return EX_OSERR;
	}

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &ONE, sizeof ONE);

	rc = bind(fd, (void const *)&ip4, sizeof ip4);
	if (rc < 0) {
		perror("bind()");
		return EX_OSERR;
	}

	for (;;) {
		union {
			unsigned char	code;

			struct notify_msg_start		start;
			struct notify_msg_length	length;
			struct notify_msg_read		read;
			struct notify_msg_substart	substart;
			struct notify_msg_subwait	subwait;
			struct notify_msg_subexit	subexit;
			struct notify_msg_exit		exit;
		}		msg;

		ssize_t			l;

		l = recv(fd, &msg, sizeof msg, 0);

		switch (msg.code) {
		case 'S':
			printf("start\n");
			break;

		case 'L':
			printf("length = %llu\n",
			       (unsigned long long)(be64toh(msg.length.length)));
			break;

		case 'R':
			printf("read = %llu\n",
			       (unsigned long long)(be64toh(msg.read.count)));
			break;

		case 's':
			printf("substart\n");
			break;

		case 'w':
			printf("subwait\n");
			break;

		case 'e':
			printf("subexit (%s)\n",
			       msg.subexit.failed ? "failed" : "ok");
			break;

		case 'E':
			printf("exit (%u)\n",
			       (unsigned int)(be32toh(msg.exit.code)));
			break;

		default:
			printf("??? (%x)\n", msg.code);
			break;
		}
	}
}
