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
#error wtf
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

/*
static uint16_t hh_swab16(const struct hardhat_superblock *sb, uint16_t x) {
	return sb->byteorder == 0x0123456789ABCDEF ? x : u16(x);
}
*/

static uint32_t hh_swab32(const struct hardhat_superblock *sb, uint32_t x) {
	return sb->byteorder == 0x0123456789ABCDEF ? x : u32(x);
}

static uint64_t hh_swab64(const struct hardhat_superblock *sb, uint64_t x) {
	return sb->byteorder == 0x0123456789ABCDEF ? x : u64(x);
}

static uint32_t hhc_calchash(const struct hardhat_superblock *sb, const uint8_t *key, size_t len) {
	uint32_t hash;

	switch(u32(sb->version)) {
		case 1:
			return calchash_fnv1a(key, len);
		case 2:
			murmurhash3_32(key, len, u32(sb->hashseed), &hash);
			return hash;
		default:
			abort();
	}
}

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
	if(memcmp(sb->magic, HARDHAT_MAGIC, sizeof sb->magic)
//	|| (sb->byteorder != UINT64_C(0x0123456789ABCDEF) && sb->byteorder != UINT64_C(0xEFCDAB8967452301))
	|| (sb->byteorder != UINT64_C(0xEFCDAB8967452301))
	|| (off_t)hh_swab64(sb, sb->filesize) != st.st_size
	|| hh_swab32(sb, sb->version) < UINT32_C(1)
	|| hh_swab32(sb, sb->version) > UINT32_C(2)
	|| hhc_calchash(sb, (const void *)sb, sizeof *sb - 4) != hh_swab32(sb, sb->checksum)) {
		// FIXME: check if data/hash/directory/prefix start/end don't overlap and fit in filesize
		munmap(buf, (size_t)st.st_size);
		errno = EPROTO;
		return NULL;
	}

	return buf;
}
	
export void hardhat_precache(void *buf, bool data) {
	struct hardhat_superblock *sb;

	if(!buf)
		return;

	sb = buf;

	if(data) {
		madvise(buf, u64(sb->filesize), MADV_WILLNEED);
	} else {
		madvise((uint8_t *)buf + u64(sb->hash_start), u64(sb->hash_end) - u64(sb->hash_start), MADV_WILLNEED);
		madvise((uint8_t *)buf + u64(sb->directory_start), u64(sb->directory_end) - u64(sb->directory_start), MADV_WILLNEED);
	}
}

export void hardhat_close(void *buf) {
	struct hardhat_superblock *sb;

	if(!buf)
		return;

	sb = buf;
	munmap(buf, (size_t)u64(sb->filesize));
}

#define u16read(buf) u16(*(uint16_t *)(buf))
#define u32read(buf) u32(*(uint32_t *)(buf))
#define u64read(buf) u64(*(uint64_t *)(buf))

#define CURSOR_NONE (UINT32_MAX)

static const hardhat_cursor_t hardhat_cursor_0 = {.cur = CURSOR_NONE};

#if 0
static uint32_t hhc_find(hardhat_cursor_t *c, bool recursive) {
	const struct hardhat_superblock *sb;
	uint32_t recnum, lower, upper, cur;
	const uint64_t *directory;
	const char *rec, *buf;
	uint16_t keylen;
	int d;

	sb = c->hardhat;
	buf = c->hardhat;

	recnum = u32(sb->entries);
	lower = 0;
	upper = recnum;
	directory = (const uint64_t *)(buf + u64(sb->directory_start));

	if(!upper)
		return CURSOR_NONE;

	for(;;) {
		cur = (uint32_t)(((uint64_t)lower + (uint64_t)upper) / UINT64_C(2));
		rec = buf + u64(directory[cur]);
		d = hardhat_cmp(rec + 6, u16read(rec + 4), c->prefix, c->prefixlen);
		if(d < 0)
			lower = cur + 1;
		else if(d > 0)
			upper = cur;
		if(!d || lower == upper) {
			if(d <= 0) {
				cur++;
				if(cur >= recnum)
					return CURSOR_NONE;
				rec = buf + u64(directory[cur]);
			}
			keylen = u16read(rec + 4);
			if(keylen < c->prefixlen
			|| memcmp(rec + 6, c->prefix, c->prefixlen)
			|| (recursive && memchr(rec + 6 + c->prefixlen, '/', (size_t)(keylen - c->prefixlen))))
				return CURSOR_NONE;
			return cur;
		}
	}
}
#endif

static void hhc_hash_find(hardhat_cursor_t *c) {
	const struct hashentry *he, *ht;
	const struct hardhat_superblock *sb;
	uint32_t i, hp, hash, recnum, upper, lower, upper_hash, lower_hash;
	uint16_t len, keylen;
	const uint64_t *directory;
	const uint8_t *rec, *buf;
	const void *str;

	sb = c->hardhat;
	recnum = u32(sb->entries);
	if(!recnum)
		return;

	str = c->prefix;
	len = c->prefixlen;
	hash = hhc_calchash(sb, str, len);
	buf = c->hardhat;

	ht = (const struct hashentry *)(buf + u64(sb->hash_start));
	directory = (const uint64_t *)(buf + u64(sb->directory_start));

	lower = 0;
	upper = recnum;
	lower_hash = 0;
	upper_hash = UINT32_MAX;

	for(;;) {
		hp = lower + (uint32_t)((uint64_t)(hash - lower_hash) * (uint64_t)(upper - lower) / (uint64_t)(upper_hash - lower_hash));
		he = ht + hp;
		if(u32(he->hash) < hash) {
			lower = hp + 1;
			lower_hash = u32(he->hash);
		} else if(u32(he->hash) > hash) {
			upper = hp;
			upper_hash = u32(he->hash);
		} else {
			break;
		}
		if(lower == upper)
			return;
	}

	for(i = hp + 1; i < recnum; i++) {
		he = ht + i;
		if(u32(he->hash) > hash)
			break;
		// FIXME: check if he->data < recnum
		rec = buf + u64(directory[u32(he->data)]);
		keylen = u16read(rec + 4);
		// FIXME: check if keylen + datalen + 6 <= data_end
		if(keylen == len && !memcmp(rec + 6, str, len)) {
			c->cur = u32(he->data);
			c->key = rec + 6;
			c->keylen = keylen;
			c->data = rec + 6 + keylen;
			c->datalen = u32read(rec);
		}
	}

	for(i = hp; i < recnum; i--) {
		he = ht + i;
		if(u32(he->hash) < hash)
			break;
		// FIXME: check if he->data < recnum
		rec = buf + u64(directory[u32(he->data)]);
		keylen = u16read(rec + 4);
		// FIXME: check if keylen + datalen + 6 <= data_end
		if(keylen == len && !memcmp(rec + 6, str, len)) {
			c->cur = u32(he->data);
			c->key = rec + 6;
			c->keylen = keylen;
			c->data = rec + 6 + keylen;
			c->datalen = u32read(rec);
		}
	}
}

static uint32_t hhc_prefix_find(const void *hardhat, const void *str, uint16_t len) {
	const struct hashentry *he, *ht;
	const struct hardhat_superblock *sb;
	uint32_t i, hp, hash, hashnum, recnum, upper, lower, upper_hash, lower_hash;
	uint16_t keylen;
	const uint64_t *directory;
	const uint8_t *rec, *buf;

	sb = hardhat;
	recnum = u32(sb->entries);
	hashnum = u32(sb->prefixes);

	if(!recnum)
		return CURSOR_NONE;

	buf = hardhat;
	directory = (const uint64_t *)(buf + u64(sb->directory_start));

	if(!len) {
		// special treatment for '' to prevent it from being
		// returned as the first entry for itself
		rec = buf + u64(directory[0]);
		return u16read(rec + 4)
			? 0 // the first is not "", so use that
			: recnum > 1
				? 1 // the first is "", so return the next one
				: CURSOR_NONE; // the database only contains ""
	}

	if(!hashnum)
		return CURSOR_NONE;

	hash = hhc_calchash(sb, str, len);
	ht = (const struct hashentry *)(buf + u64(sb->prefix_start));

	lower = 0;
	upper = hashnum;
	lower_hash = 0;
	upper_hash = UINT32_MAX;

	for(;;) {
		hp = lower + (uint32_t)((uint64_t)(hash - lower_hash) * (uint64_t)(upper - lower) / (uint64_t)(upper_hash - lower_hash));
		he = ht + hp;

		if(u32(he->hash) < hash) {
			lower = hp + 1;
			lower_hash = u32(he->hash);
		} else if(u32(he->hash) > hash) {
			upper = hp;
			upper_hash = u32(he->hash);
		} else {
			break;
		}
		if(lower == upper)
			return CURSOR_NONE;
	}

	for(i = hp + 1; i < hashnum; i++) {
		he = ht + i;
		if(u32(he->hash) > hash)
			break;

		// FIXME
		rec = buf + u64(directory[u32(he->data)]);
		keylen = u16read(rec + 4);
		if(keylen < len || memcmp(rec + 6, str, len))
			continue;

		if(u32(he->data)) {
			// FIXME
			rec = buf + u64(directory[u32(he->data) - 1]);
			keylen = u16read(rec + 4);
			if(keylen >= len && !memcmp(rec + 6, str, len))
				continue;
		}

		return u32(he->data);
	}

	for(i = hp; i < hashnum; i--) {
		he = ht + i;
		if(u32(he->hash) < hash)
			break;

		rec = buf + u64(directory[u32(he->data)]);
		keylen = u16read(rec + 4);
		if(keylen < len || memcmp(rec + 6, str, len))
			continue;

		if(u32(he->data)) {
			rec = buf + u64(directory[u32(he->data) - 1]);
			keylen = u16read(rec + 4);
			if(keylen >= len && !memcmp(rec + 6, str, len))
				continue;
		}

		return u32(he->data);
	}

	return CURSOR_NONE;
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

	hhc_hash_find(c);

	if(prefixlen)
		c->prefix[prefixlen++] = '/';
	c->prefixlen = prefixlen;

	return c;
}

export bool hardhat_fetch(hardhat_cursor_t *c, bool recursive) {
	const struct hardhat_superblock *sb;
	uint32_t cur;
	const uint64_t *directory;
	const char *rec, *buf;
	uint16_t keylen;

	if(!c)
		return false;

	cur = c->cur;
	sb = c->hardhat;
	buf = c->hardhat;
	directory = (const uint64_t *)(buf + u64(sb->directory_start));

	if(c->started)
		cur++;
	else
		cur = hhc_prefix_find(buf, c->prefix, c->prefixlen);

	if(cur < sb->entries) {
		rec = buf + u64(directory[cur]);
		keylen = u16read(rec + 4);
		if(keylen < c->prefixlen
		|| memcmp(rec + 6, c->prefix, c->prefixlen)
		|| (!recursive && memchr(rec + 6 + c->prefixlen, '/', (size_t)(keylen - c->prefixlen))))
			cur = CURSOR_NONE;
	} else {
		cur = CURSOR_NONE;
	}

	c->cur = cur;
	if(cur == CURSOR_NONE) {
		c->key = NULL;
		c->data = NULL;
		c->keylen = 0;
		c->datalen = 0;
		return c->started = false;
	}

	rec = buf + u64(directory[cur]);
	c->key = rec + 6;
	c->keylen = u16read(rec + 4);
	c->data = rec + 6 + c->keylen;
	c->datalen = u32read(rec);
	return c->started = true;
}

export void hardhat_cursor_free(hardhat_cursor_t *c) {
	free(c);
}
