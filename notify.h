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

#ifndef H_ENSC_STREAMGEN_NOTIFY_H
#define H_ENSC_STREAMGEN_NOTIFY_H

#ifndef __packed
#  define __packed	__attribute__((__packed__))
#endif

struct notify_msg_start {
	uint8_t		op;		/* 'S' */
} __packed;

struct notify_msg_length {
	uint8_t		op;		/* 'L' */
	be64_t		length;
} __packed;

struct notify_msg_read {
	uint8_t		op;		/* 'R' */
	be64_t		count;
} __packed;

struct notify_msg_substart {
	uint8_t		op;		/* 's' */
} __packed;

struct notify_msg_subwait {
	uint8_t		op;		/* 'w' */
} __packed;

struct notify_msg_subexit {
	uint8_t		op;		/* 'e' */
	uint8_t		failed;
} __packed;

struct notify_msg_exit {
	uint8_t		op;		/* 'E' */
	be32_t		code;
} __packed;

#endif	/* H_ENSC_STREAMGEN_NOTIFY_H */
