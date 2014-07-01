/******************************************************************************

	hardhat - read and write databases optimized for filename-like keys
	Copyright (c) 2011,2012,2014 Wessel Dankers <wsl@fruit.je>

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program. If not, see <http://www.gnu.org/licenses/>.

******************************************************************************/

#include "config.h"

#include <stdio.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "maker.h"
#include "hashtable.h"
#include "layout.h"
#include "reader.h"
#include "murmur3.h"

#define export __attribute__((visibility("default")))

#define u16read(buf) u16(*(uint16_t *)(buf))
#define u32read(buf) u32(*(uint32_t *)(buf))
#define u64read(buf) u64(*(uint64_t *)(buf))

#define CURSOR_NONE (UINT32_MAX)

static const hardhat_cursor_t hardhat_cursor_0 = {.cur = CURSOR_NONE};

#define u16(x) (x)
#define u32(x) (x)
#define u64(x) (x)

#define HHE(n) (n##_ne)
#include "readerimpl.h"

#undef u16
#undef u32
#undef u64

#ifdef HAVE_BUILTIN_BSWAP16
#define u16(x) __builtin_bswap16(x)
#else
static uint16_t u16(uint16_t x) {
	return (x << 8) | (x >> 8);
}
#endif

#ifdef HAVE_BUILTIN_BSWAP32
#define u32(x) __builtin_bswap32(x)
#else
static uint32_t u32(uint32_t x) {
	x = ((x & UINT32_C(0x00FF00FF)) << 8) | ((x & UINT32_C(0xFF00FF00)) >> 8);
	return (x << 16) | (x >> 16);
}
#endif

#ifdef HAVE_BUILTIN_BSWAP64
#define u64(x) __builtin_bswap64(x)
#else
static uint64_t u64(uint64_t x) {
	x = ((x & UINT64_C(0x00FF00FF00FF00FF)) << 8) | ((x & UINT64_C(0xFF00FF00FF00FF00)) >> 8);
	x = ((x & UINT64_C(0x0000FFFF0000FFFF)) << 16) | ((x & UINT64_C(0xFFFF0000FFFF0000)) >> 16);
	return (x << 32) | (x >> 32);
}
#endif

#undef HHE
#define HHE(n) (n##_oe)
#include "readerimpl.h"

export void *hardhat_open(const char *filename) {
	void *buf;
	int fd, err;
	struct stat st;
	struct hardhat_superblock *sb;

	fd = open(filename, O_RDONLY|O_NOCTTY|O_LARGEFILE);
	if(fd == -1)
		return NULL;

	if(fstat(fd, &st) == -1) {
		close(fd);
		return NULL;
	}

	if(st.st_size < (off_t)sizeof *sb) {
		close(fd);
		errno = EPROTO;
		return NULL;
	}

	buf = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	err = errno;
	close(fd);
	if(buf == MAP_FAILED) {
		errno = err;
		return NULL;
	}

	sb = buf;
	if(!memcmp(sb->magic, HARDHAT_MAGIC, sizeof sb->magic)
		&& ((sb->byteorder == UINT64_C(0x0123456789ABCDEF) && hhc_validate_ne(sb, &st))
			|| (sb->byteorder == UINT64_C(0xEFCDAB8967452301) && hhc_validate_oe(sb, &st))))
		return buf;

	munmap(buf, (size_t)st.st_size);
	errno = EPROTO;
	return NULL;
}
	
export void hardhat_precache(void *buf, bool data) {
	struct hardhat_superblock *sb;

	if(!buf)
		return;
	sb = buf;

	if(sb->byteorder == 0x0123456789ABCDEF)
		hardhat_precache_ne(buf, data);
	else
		hardhat_precache_oe(buf, data);
}

export void hardhat_close(void *buf) {
	struct hardhat_superblock *sb;

	if(!buf)
		return;
	sb = buf;

	if(sb->byteorder == 0x0123456789ABCDEF)
		hardhat_close_ne(buf);
	else
		hardhat_close_oe(buf);
}

export hardhat_cursor_t *hardhat_cursor(const void *hardhat, const void *prefix, uint16_t prefixlen) {
	hardhat_cursor_t *c;

	if(!hardhat || memcmp(hardhat, HARDHAT_MAGIC, strlen(HARDHAT_MAGIC))) {
		errno = EINVAL;
		return NULL;
	}

	c = malloc(sizeof *c + prefixlen);
	if(!c)
		return NULL;
	*c = hardhat_cursor_0;

	c->prefixlen = prefixlen = (uint16_t)hardhat_normalize(c->prefix, prefix, prefixlen);
	c->hardhat = hardhat;

	if(((const struct hardhat_superblock *)hardhat)->byteorder == 0x0123456789ABCDEF)
		hhc_hash_find_ne(c);
	else
		hhc_hash_find_oe(c);

	if(prefixlen)
		c->prefix[prefixlen++] = '/';
	c->prefixlen = prefixlen;

	return c;
}

export void hardhat_cursor_free(hardhat_cursor_t *c) {
	free(c);
}

export bool hardhat_fetch(hardhat_cursor_t *c, bool recursive) {
	const struct hardhat_superblock *sb;
	if(!c)
		return false;

	sb = c->hardhat;

	return sb->byteorder == 0x0123456789ABCDEF
		? hardhat_fetch_ne(c, recursive)
		: hardhat_fetch_oe(c, recursive);
}
