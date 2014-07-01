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

static uint32_t HHE(hhc_calchash)(const struct hardhat_superblock *sb, const uint8_t *key, size_t len) {
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

static bool HHE(hhc_validate)(const struct hardhat_superblock *sb, const struct stat *st) {
	// FIXME: check if data/hash/directory/prefix start/end don't overlap and fit in filesize
	return (off_t)u64(sb->filesize) == st->st_size
		&& u32(sb->version) >= UINT32_C(1)
		&& u32(sb->version) <= UINT32_C(2)
		&& HHE(hhc_calchash)(sb, (const void *)sb, sizeof *sb - 4) == u32(sb->checksum);
}

static void HHE(hardhat_precache)(void *buf, bool data) {
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

static void HHE(hardhat_close)(void *buf) {
	struct hardhat_superblock *sb;

	if(!buf)
		return;

	sb = buf;
	munmap(buf, (size_t)u64(sb->filesize));
}

#if 0
static uint32_t HHE(hhc_find)(hardhat_cursor_t *c, bool recursive) {
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

static void HHE(hhc_hash_find)(hardhat_cursor_t *c) {
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
	hash = HHE(hhc_calchash)(sb, str, len);
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

static uint32_t HHE(hhc_prefix_find)(const void *hardhat, const void *str, uint16_t len) {
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

	hash = HHE(hhc_calchash)(sb, str, len);
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

static bool HHE(hardhat_fetch)(hardhat_cursor_t *c, bool recursive) {
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
		cur = HHE(hhc_prefix_find)(buf, c->prefix, c->prefixlen);

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
