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

	buf = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_SHARED, fd, 0);
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

static int hhr_cmp(const void *a, size_t al, const void *b, size_t bl) {
	size_t l;
	int d;

	l = al < bl ? al : bl;
	d = memcmp(a, b, l);
	if(d)
		return d;
	return al < bl ? -1 : al > bl ? 1 : 0;
}

#define CURSOR_NONE (UINT32_MAX)

static const hardhat_cursor_t hardhat_cursor_0 = {
	.cur = CURSOR_NONE
};

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
		d = hhr_cmp(rec + 6, u16read(rec + 4), c->prefix, c->prefixlen);
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
	uint16_t prefixlen, keylen;
	const uint64_t *directory;
	const uint8_t *rec, *buf;

	sb = c->hardhat;
	recnum = sb->entries;

	if(!recnum)
		return;

	prefixlen = c->prefixlen;
	hash = calchash(c->prefix, (size_t)prefixlen);
	buf = c->hardhat;

	ht = (const struct hashentry *)(buf + sb->hash_start);
	hp = (uint32_t)((uint64_t)hash * (uint64_t)recnum / (uint64_t)UINT32_MAX);
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
		if(keylen == prefixlen && !memcmp(rec + 6, c->prefix, prefixlen)) {
			c->key = rec + 6;
			c->keylen = keylen;
			c->data = rec + 6 + keylen;
			c->datalen = u32read(rec);
			return;
		}
	}

	for(i = hp; i < recnum; i--) {
		he = ht + i;
		if(he->hash < hash)
			break;
		rec = buf + directory[he->data];
		keylen = u16read(rec + 4);
		if(keylen == prefixlen && !memcmp(rec + 6, c->prefix, prefixlen)) {
			c->key = rec + 6;
			c->keylen = keylen;
			c->data = rec + 6 + keylen;
			c->datalen = u32read(rec);
			return;
		}
	}
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

	cur = c->cur;
	sb = c->hardhat;
	buf = c->hardhat;
	directory = (const uint64_t *)(buf + sb->directory_start);

	if(cur == CURSOR_NONE) {
		cur = hhc_find(c, recursive);
	} else {
		cur++;
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
	}

	if(cur == CURSOR_NONE) {
		c->cur = cur;
		c->key = NULL;
		c->data = NULL;
		c->keylen = 0;
		c->datalen = 0;
		return false;
	}

	rec = buf + directory[cur];
	c->cur = cur;
	c->key = rec + 6;
	c->keylen = u16read(rec + 4);
	c->data = rec + 6 + c->keylen;
	c->datalen = u32read(rec);
	return true;
}

export void hardhat_cursor_free(hardhat_cursor_t *c) {
	free(c);
}
