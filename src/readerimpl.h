/******************************************************************************

	hardhat - read and write databases optimized for filename-like keys
	Copyright (c) 2011,2012,2014,2015 Wessel Dankers <wsl@fruit.je>

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

/* This file is compiled twice: first with HHE(), u16(), u32() and u64() set
** up for native endian access, then again with those set up for other endian
** byte order. */

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
	uint64_t sections[8];

	if(memcmp(sb->magic, HARDHAT_MAGIC, sizeof sb->magic))
		return false;

	if(u64(sb->byteorder) != UINT64_C(0x0123456789ABCDEF))
		return false;

	if((off_t)u64(sb->filesize) != st->st_size)
		return false;

	if(u32(sb->version) < UINT32_C(1) || u32(sb->version) > UINT32_C(2))
		return false;

	if(HHE(hhc_calchash)(sb, (const void *)sb, sizeof *sb - 4) != u32(sb->checksum))
		return false;

	if(u64(sb->data_start) % sizeof(uint32_t))
		return false;
	if(u64(sb->hash_start) % sizeof(uint32_t))
		return false;
	if(u64(sb->directory_start) % sizeof(uint64_t))
		return false;
	if(u64(sb->prefix_start) % sizeof(uint32_t))
		return false;

	if(u64(sb->data_start) < sizeof *sb)
		return false;
	if(u64(sb->hash_start) < sizeof *sb)
		return false;
	if(u64(sb->directory_start) < sizeof *sb)
		return false;
	if(u64(sb->prefix_start) < sizeof *sb)
		return false;

	if(u64(sb->data_end) > (uint64_t)st->st_size)
		return false;
	if(u64(sb->hash_end) > (uint64_t)st->st_size)
		return false;
	if(u64(sb->directory_end) > (uint64_t)st->st_size)
		return false;
	if(u64(sb->prefix_end) > (uint64_t)st->st_size)
		return false;

	if(u64(sb->data_end) < u64(sb->data_start))
		return false;
	if(u64(sb->hash_end) < u64(sb->hash_start))
		return false;
	if(u64(sb->directory_end) < u64(sb->directory_start))
		return false;
	if(u64(sb->prefix_end) < u64(sb->prefix_start))
		return false;

	if(u64(sb->directory_end) - u64(sb->directory_start) < (uint64_t)u32(sb->entries) * (uint64_t)sizeof(uint64_t))
		return false;
	if(u64(sb->hash_end) - u64(sb->hash_start) < (uint64_t)u32(sb->entries) * (uint64_t)(2 * sizeof(uint32_t)))
		return false;
	if(u64(sb->prefix_end) - u64(sb->prefix_start) < (uint64_t)u32(sb->prefixes) * (uint64_t)(2 * sizeof(uint32_t)))
		return false;

	sections[0] = u64(sb->data_start);
	sections[1] = u64(sb->data_end);
	sections[2] = u64(sb->hash_start);
	sections[3] = u64(sb->hash_end);
	sections[4] = u64(sb->directory_start);
	sections[5] = u64(sb->directory_end);
	sections[6] = u64(sb->prefix_start);
	sections[7] = u64(sb->prefix_end);

	qsort(sections, sizeof sections / (sizeof *sections * 2), sizeof *sections * 2, sectioncmp);

	if(sections[1] > sections[2])
		return false;
	if(sections[3] > sections[4])
		return false;
	if(sections[5] > sections[6])
		return false;

	return true;
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
		madvise((uint8_t *)buf + u64(sb->prefix_start), u64(sb->prefix_end) - u64(sb->prefix_start), MADV_WILLNEED);
	}
}

static void HHE(hardhat_close)(void *buf) {
	struct hardhat_superblock *sb;

	if(!buf)
		return;

	sb = buf;
	munmap(buf, (size_t)u64(sb->filesize));
}

static void HHE(hhc_hash_find)(hardhat_cursor_t *c) {
	const struct hashentry *he, *ht;
	const struct hardhat_superblock *sb;
	uint64_t off, reclen, data_start, data_end;
	uint32_t u, hp, hash, he_hash, he_data, datalen, recnum, upper, lower, upper_hash, lower_hash;
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

	/* binary search for the hash value */
	for(;;) {
		hp = lower + (uint32_t)((uint64_t)(hash - lower_hash) * (uint64_t)(upper - lower) / (uint64_t)(upper_hash - lower_hash));
		he = ht + hp;
		he_hash = u32(he->hash);
		if(he_hash < hash) {
			lower = hp + 1;
			lower_hash = he_hash;
		} else if(he_hash > hash) {
			upper = hp;
			upper_hash = he_hash;
		} else {
			break;
		}
		if(lower == upper)
			return;
	}

	data_start = u64(sb->data_start);
	data_end = u64(sb->data_end);

	/* There may be multiple keys with the correct hash value.
	** We need to search up and down to find the real key by
	** comparing key values. */

	/* search upward to find the real value */
	for(u = hp; u < recnum; u++) {
		he = ht + u;
		he_hash = u32(he->hash);
		if(he_hash != hash)
			break;
		he_data = u32(he->data);
		if(he_data >= recnum)
			return;
		off = u64(directory[he_data]);
		reclen = 6;
		if(off < data_start || off + reclen < off || off + reclen > data_end || off % sizeof(uint32_t))
			return;
		rec = buf + off;
		keylen = u16read(rec + 4);
		reclen += keylen;
		if(off + reclen < off || off + reclen > data_end)
			return;
		if(keylen == len && !memcmp(rec + 6, str, len)) {
			datalen = u32read(rec);
			reclen += datalen;
			if(off + reclen < off || off + reclen > data_end)
				return;
			c->cur = he_data;
			c->key = rec + 6;
			c->keylen = keylen;
			c->data = rec + 6 + keylen;
			c->datalen = datalen;
			return;
		}
	}

	/* search downward to find the real value */
	for(u = hp - 1; u < recnum; u--) {
		he = ht + u;
		he_hash = u32(he->hash);
		if(he_hash != hash)
			break;
		he_data = u32(he->data);
		if(he_data >= recnum)
			return;
		off = u64(directory[he_data]);
		reclen = 6;
		if(off < data_start || off + reclen < off || off + reclen > data_end || off % sizeof(uint32_t))
			return;
		rec = buf + off;
		keylen = u16read(rec + 4);
		reclen += keylen;
		if(off + reclen < off || off + reclen > data_end)
			return;
		if(keylen == len && !memcmp(rec + 6, str, len)) {
			datalen = u32read(rec);
			reclen += datalen;
			if(off + reclen < off || off + reclen > data_end)
				return;
			c->cur = he_data;
			c->key = rec + 6;
			c->keylen = keylen;
			c->data = rec + 6 + keylen;
			c->datalen = datalen;
			return;
		}
	}

}

static uint32_t HHE(hhc_prefix_find)(const void *hardhat, const void *str, uint16_t len) {
	const struct hashentry *he, *ht;
	const struct hardhat_superblock *sb;
	uint64_t off, reclen, data_start, data_end;
	uint32_t u, hp, hash, he_hash, he_data, hashnum, recnum, upper, lower, upper_hash, lower_hash;
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

	data_start = u64(sb->data_start);
	data_end = u64(sb->data_end);

	if(!len) {
		// special treatment for '' to prevent it from being
		// returned as the first entry for itself
		off = u64(directory[0]);
		reclen = 6;
		if(off < data_start || off + reclen < off || off + reclen > data_end || off % sizeof(uint32_t))
			return CURSOR_NONE;
		rec = buf + off;
		keylen = u16read(rec + 4);
		if(keylen) {
			// check 0
			reclen += keylen + u32read(rec);
			if(off + reclen < off || off + reclen > data_end)
				return CURSOR_NONE;
			return 0;
		} else if(recnum > 1) {
			// the first is "", so return the next one
			// check 1
			off = u64(directory[1]);
			if(off < data_start || off + reclen < off || off + reclen > data_end || off % sizeof(uint32_t))
				return CURSOR_NONE;
			rec = buf + off;
			reclen += u16read(rec + 4) + u32read(rec);
			if(off + reclen < off || off + reclen > data_end)
				return CURSOR_NONE;
			return 1;
		} else {
			return CURSOR_NONE;
		}
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

		he_hash = u32(he->hash);
		if(he_hash < hash) {
			lower = hp + 1;
			lower_hash = he_hash;
		} else if(he_hash > hash) {
			upper = hp;
			upper_hash = he_hash;
		} else {
			break;
		}
		if(lower == upper)
			return CURSOR_NONE;
	}

	for(u = hp; u < hashnum; u++) {
		he = ht + u;
		he_hash = u32(he->hash);
		if(he_hash != hash)
			break;
		he_data = u32(he->data);
		if(he_data >= recnum)
			return CURSOR_NONE;
        off = u64(directory[he_data]);
        reclen = 6;
        if(off < data_start || off + reclen < off || off + reclen > data_end || off % sizeof(uint32_t))
            return CURSOR_NONE;
        rec = buf + off;
        keylen = u16read(rec + 4);
        reclen += keylen;
		if(off + reclen < off || off + reclen > data_end)
            return CURSOR_NONE;
		if(keylen < len || memcmp(rec + 6, str, len))
			continue;
		reclen += u32read(rec);
		if(off + reclen < off || off + reclen > data_end)
			return CURSOR_NONE;
		if(he_data) {
			/* check if the prefix we found is actually the first one */
			off = u64(directory[he_data - 1]);
			reclen = 6;
			if(off < data_start || off + reclen < off || off + reclen > data_end || off % sizeof(uint32_t))
				return CURSOR_NONE;
			rec = buf + off;
			keylen = u16read(rec + 4);
			reclen += keylen;
			if(off + reclen < off || off + reclen > data_end)
				return CURSOR_NONE;
			if(keylen >= len && !memcmp(rec + 6, str, len))
				continue;
		}
		return he_data;
	}

	for(u = hp - 1; u < hashnum; u--) {
		he = ht + u;
		he_hash = u32(he->hash);
		if(he_hash != hash)
			break;
		he_data = u32(he->data);
		if(he_data >= recnum)
			return CURSOR_NONE;
        off = u64(directory[he_data]);
        reclen = 6;
        if(off < data_start || off + reclen < off || off + reclen > data_end || off % sizeof(uint32_t))
            return CURSOR_NONE;
        rec = buf + off;
        keylen = u16read(rec + 4);
        reclen += keylen;
		if(off + reclen < off || off + reclen > data_end)
            return CURSOR_NONE;
		if(keylen < len || memcmp(rec + 6, str, len))
			continue;
		reclen += u32read(rec);
		if(off + reclen < off || off + reclen > data_end)
			return CURSOR_NONE;
		if(he_data) {
			/* check if the prefix we found is actually the first one */
			off = u64(directory[he_data - 1]);
			reclen = 6;
			if(off < data_start || off + reclen < off || off + reclen > data_end || off % sizeof(uint32_t))
				return CURSOR_NONE;
			rec = buf + off;
			keylen = u16read(rec + 4);
			reclen += keylen;
			if(off + reclen < off || off + reclen > data_end)
				return CURSOR_NONE;
			if(keylen >= len && !memcmp(rec + 6, str, len))
				continue;
		}
		return he_data;
	}

	return CURSOR_NONE;
}

static bool HHE(hardhat_fetch)(hardhat_cursor_t *c, bool recursive) {
	const struct hardhat_superblock *sb;
	uint64_t off, reclen, data_start, data_end;
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

	if(c->started) {
		cur++;
		if(cur < u32(sb->entries)) {
			data_start = u64(sb->data_start);
			data_end = u64(sb->data_end);
			off = u64(directory[cur]);
			reclen = 6;
			if(off < data_start || off + reclen < off || off + reclen > data_end || off % sizeof(uint32_t)) {
				cur = CURSOR_NONE;
			} else {
				rec = buf + off;
				keylen = u16read(rec + 4);
				reclen += keylen + u32read(rec);
				if(off + reclen < off || off + reclen > data_end) {
					cur = CURSOR_NONE;
				} else if(keylen < c->prefixlen
					|| memcmp(rec + 6, c->prefix, c->prefixlen)
					|| (!recursive && memchr(rec + 6 + c->prefixlen, '/', (size_t)(keylen - c->prefixlen)))) {
						cur = CURSOR_NONE;
				}
			}
		} else {
			cur = CURSOR_NONE;
		}
	} else {
		/* hhc_prefix_find() validates the entry for us */
		cur = HHE(hhc_prefix_find)(buf, c->prefix, c->prefixlen);
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
