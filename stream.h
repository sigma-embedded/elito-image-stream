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

#ifndef H_ENSC_STREAMGEN_STREAM_H
#define H_ENSC_STREAMGEN_STREAM_H

#include <stdint.h>

#define __packed	__attribute__((__packed__))

typedef uint32_t	be32_t;
typedef uint8_t		be8_t;

#define STREAM_HEADER_MAGIC	0xdeadaffeU

enum stream_signature {
	STREAM_SIGNATURE_NONE,
	STREAM_SIGNATURE_MD5,
	STREAM_SIGNATURE_SHA1,
	STREAM_SIGNATURE_SHA256,
	STREAM_SIGNATURE_SHA512,
	STREAM_SIGNATURE_GPG,
	STREAM_SIGNATURE_X509,
};

enum stream_compression {
	STREAM_COMPRESS_NONE,
	STREAM_COMPRESS_GZIP,
	STREAM_COMPRESS_XZ
};

struct stream_header {
	be32_t		magic;
	be32_t		version;
	be8_t		salt[8];
	be32_t		_unused0;
	be32_t		_unused1;
	be32_t		_unused2;
	be32_t		_unused3;
} __packed;;

struct stream_hunk_header {
	be32_t		type;
	be8_t		sign_type;
	be8_t		compress_type;
	be8_t		_unused0;
	be8_t		_unused1;
	be32_t		hunk_len;
	be32_t		decompress_len;
	be32_t		fixed_sign_len;
	be32_t		prefix_len;

	be32_t		_unused3;
	be32_t		_unused4;
} __packed;

#endif	/* H_ENSC_STREAMGEN_STREAM_H */
