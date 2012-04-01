/******************************************************************************

	hardhat - read and write databases optimized for filename-like keys
	Copyright (c) 2011,2012 Wessel Dankers <wsl@fruit.je>

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

#define export __attribute__((visibility("default")))

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
	|| (off_t)sb->filesize != st.st_size
	|| sb->byteorder != UINT64_C(0x0123456789ABCDEF)
	|| sb->version != UINT32_C(1)
	|| calchash((const void *)sb, sizeof *sb - 4) != sb->checksum) {
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
		madvise(buf, sb->filesize, MADV_WILLNEED);
	} else {
		madvise((uint8_t *)buf + sb->hash_start, sb->hash_end - sb->hash_start, MADV_WILLNEED);
		madvise((uint8_t *)buf + sb->directory_start, sb->directory_end - sb->directory_start, MADV_WILLNEED);
	}
}

export void hardhat_close(void *buf) {
	struct hardhat_superblock *sb;

	if(!buf)
		return;

	sb = buf;
	munmap(buf, (size_t)sb->filesize);
}

#define u16read(buf) (*(uint16_t *)(buf))
#define u32read(buf) (*(uint32_t *)(buf))
#define u64read(buf) (*(uint64_t *)(buf))

#define CURSOR_NONE (UINT32_MAX)

static const hardhat_cursor_t hardhat_cursor_0 = {.cur = CURSOR_NONE};

__attribute__((unused))
static uint32_t hhc_find(hardhat_cursor_t *c, bool recursive) {
	const struct hardhat_superblock *sb;
	uint32_t lower, upper, cur;
	const uint64_t *directory;
	const char *rec, *buf;
	uint16_t keylen;
	int d;

	sb = c->hardhat;
	buf = c->hardhat;
	lower = 0;
	upper = sb->entries;
	directory = (const uint64_t *)(buf + sb->directory_start);

	if(!upper)
		return CURSOR_NONE;

	for(;;) {
		cur = (uint32_t)(((uint64_t)lower + (uint64_t)upper) / UINT64_C(2));
		rec = buf + directory[cur];
		d = hardhat_cmp(rec + 6, u16read(rec + 4), c->prefix, c->prefixlen);
		if(d < 0)
			lower = cur + 1;
		else if(d > 0)
			upper = cur;
		if(!d || lower == upper) {
			if(d <= 0) {
				cur++;
				if(cur >= sb->entries)
					return CURSOR_NONE;
				rec = buf + directory[cur];
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

static void hhm_hash_find(hardhat_cursor_t *c) {
	const struct hashentry *he, *ht;
	const struct hardhat_superblock *sb;
	uint32_t i, hp, hash, recnum, upper, lower, upper_hash, lower_hash;
	uint16_t len, keylen;
	const uint64_t *directory;
	const uint8_t *rec, *buf;
	const void *str;

	sb = c->hardhat;
	recnum = sb->entries;
	if(!recnum)
		return;

	str = c->prefix;
	len = c->prefixlen;
	hash = calchash(str, len);
	buf = c->hardhat;

	ht = (const struct hashentry *)(buf + sb->hash_start);
	directory = (const uint64_t *)(buf + sb->directory_start);

	lower = 0;
	upper = recnum;
	lower_hash = 0;
	upper_hash = UINT32_MAX;

	for(;;) {
		hp = lower + (uint32_t)((uint64_t)(hash - lower_hash) * (uint64_t)(upper - lower) / (uint64_t)(upper_hash - lower_hash));
		he = ht + hp;
		if(he->hash < hash) {
			lower = hp + 1;
			lower_hash = he->hash;
		} else if(he->hash > hash) {
			upper = hp;
			upper_hash = he->hash;
		} else {
			break;
		}
		if(lower == upper)
			return;
	}

	for(i = hp + 1; i < recnum; i++) {
		he = ht + i;
		if(he->hash > hash)
			break;
		rec = buf + directory[he->data];
		keylen = u16read(rec + 4);
		if(keylen == len && !memcmp(rec + 6, str, len)) {
			c->cur = he->data;
			c->key = rec + 6;
			c->keylen = keylen;
			c->data = rec + 6 + keylen;
			c->datalen = u32read(rec);
		}
	}

	for(i = hp; i < recnum; i--) {
		he = ht + i;
		if(he->hash < hash)
			break;
		rec = buf + directory[he->data];
		keylen = u16read(rec + 4);
		if(keylen == len && !memcmp(rec + 6, str, len)) {
			c->cur = he->data;
			c->key = rec + 6;
			c->keylen = keylen;
			c->data = rec + 6 + keylen;
			c->datalen = u32read(rec);
		}
	}
}

static uint32_t hhm_prefix_find(const void *hardhat, const void *str, uint16_t len) {
	const struct hashentry *he, *ht;
	const struct hardhat_superblock *sb;
	uint32_t i, hp, hash, hashnum, recnum, upper, lower, upper_hash, lower_hash;
	uint16_t keylen;
	const uint64_t *directory;
	const uint8_t *rec, *buf;

	sb = hardhat;
	recnum = sb->entries;
	hashnum = sb->prefixes;

	if(!recnum)
		return CURSOR_NONE;
	if(!len)
		return 0;
	if(!hashnum)
		return CURSOR_NONE;

	hash = calchash(str, len);
	buf = hardhat;

	ht = (const struct hashentry *)(buf + sb->prefix_start);
	directory = (const uint64_t *)(buf + sb->directory_start);

	lower = 0;
	upper = hashnum;
	lower_hash = 0;
	upper_hash = UINT32_MAX;

	for(;;) {
		hp = lower + (uint32_t)((uint64_t)(hash - lower_hash) * (uint64_t)(upper - lower) / (uint64_t)(upper_hash - lower_hash));
		he = ht + hp;

		if(he->hash < hash) {
			lower = hp + 1;
			lower_hash = he->hash;
		} else if(he->hash > hash) {
			upper = hp;
			upper_hash = he->hash;
		} else {
			break;
		}
		if(lower == upper)
			return CURSOR_NONE;
	}

	for(i = hp + 1; i < hashnum; i++) {
		he = ht + i;
		if(he->hash > hash)
			break;

		rec = buf + directory[he->data];
		keylen = u16read(rec + 4);
		if(keylen < len || memcmp(rec + 6, str, len))
			continue;

		if(he->data) {
			rec = buf + directory[he->data - 1];
			keylen = u16read(rec + 4);
			if(keylen >= len && !memcmp(rec + 6, str, len))
				continue;
		}

		return he->data;
	}

	for(i = hp; i < hashnum; i--) {
		he = ht + i;
		if(he->hash < hash)
			break;

		rec = buf + directory[he->data];
		keylen = u16read(rec + 4);
		if(keylen < len || memcmp(rec + 6, str, len))
			continue;

		if(he->data) {
			rec = buf + directory[he->data - 1];
			keylen = u16read(rec + 4);
			if(keylen >= len && !memcmp(rec + 6, str, len))
				continue;
		}

		return he->data;
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

	hhm_hash_find(c);

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
	directory = (const uint64_t *)(buf + sb->directory_start);

	if(c->started)
		cur++;
	else
		cur = hhm_prefix_find(buf, c->prefix, c->prefixlen);

	if(cur < sb->entries) {
		rec = buf + directory[cur];
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

	rec = buf + directory[cur];
	c->key = rec + 6;
	c->keylen = u16read(rec + 4);
	c->data = rec + 6 + c->keylen;
	c->datalen = u32read(rec);
	return c->started = true;
}

export void hardhat_cursor_free(hardhat_cursor_t *c) {
	free(c);
}
