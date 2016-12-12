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

/* sent exactly once when starting to read the stream */
struct notify_msg_start {
	uint8_t		op;		/* 'S' */
} __packed;

/* sent optionally after 'S' and tells that a boolean flag ('is_flag' is true)
 * or a keyval parameter has been sent */
struct notify_msg_param {
	uint8_t		op;		/* 'P' */
	uint8_t		is_flag;
} __packed;

/* sent exactly once immediately after 'S' or 'P' and tells number of
 * uncompressed octets */
struct notify_msg_length {
	uint8_t		op;		/* 'L' */
	be64_t		length;
} __packed;

/* reports total number of read octets; sent everytime when a block of
 * uncompressed data has been read; */
struct notify_msg_read {
	uint8_t		op;		/* 'R' */
	be64_t		count;
} __packed;

/* signals start of a component; in usually case (no errors) it will be
 * followed by an arbitrary number of 'R' events, one 'w' event and an 'e'
 * event. */
struct notify_msg_substart {
	uint8_t		op;		/* 's' */
} __packed;

/* signals that all data of a component has been read and that there will be
 * waited for processing them; will be followed by 'e' without any 'R'
 * events */
struct notify_msg_subwait {
	uint8_t		op;		/* 'w' */
} __packed;

/* signals that a component has been processed completely */
struct notify_msg_subexit {
	uint8_t		op;		/* 'e' */
	uint8_t		failed;
} __packed;

/* signals that stream has been processed completely or that processing will
 * be terminated due to an error */
struct notify_msg_exit {
	uint8_t		op;		/* 'E' */
	be32_t		code;
} __packed;

#endif	/* H_ENSC_STREAMGEN_NOTIFY_H */
