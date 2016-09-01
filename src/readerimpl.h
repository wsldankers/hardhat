/******************************************************************************

	hardhat - read and write databases optimized for filename-like keys
	Copyright (c) 2011,2012,2014-2016 Wessel Dankers <wsl@fruit.je>

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

static uint32_t HHE(hhc_calchash)(hardhat_t *hardhat, const uint8_t *key, size_t len) {
	uint32_t hash;

	switch(u32(hardhat->version)) {
		case 1:
			return calchash_fnv1a(key, len);
		case 2:
		case 3:
		case 4:
			murmurhash3_32(key, len, u32(hardhat->hashseed), &hash);
			return hash;
		default:
			abort();
	}
}

static bool HHE(hhc_validate)(hardhat_t *hardhat, const struct stat *st) {
	uint64_t sections[8];

	if(memcmp(hardhat->magic, HARDHAT_MAGIC, sizeof hardhat->magic))
		return false;

	if(u64(hardhat->byteorder) != UINT64_C(0x0123456789ABCDEF))
		return false;

	if((off_t)u64(hardhat->filesize) != st->st_size)
		return false;

	if(!u32(hardhat->version)) {
		return false;
	} else if(u32(hardhat->version) <= UINT32_C(3)) {
		if(st->st_size < (off_t)sizeof(struct oldhardhat))
			return false;
		if(HHE(hhc_calchash)(hardhat, (const void *)hardhat, sizeof(struct oldhardhat) - 4)
				!= u32(((struct oldhardhat *)hardhat)->checksum))
			return false;
	} else if(u32(hardhat->version) <= UINT32_C(4)) {
		if(HHE(hhc_calchash)(hardhat, (const void *)hardhat, sizeof *hardhat - 4)
				!= u32(hardhat->checksum))
			return false;
	} else {
		return false;
	}

	if(u64(hardhat->data_start) % sizeof(uint32_t))
		return false;
	if(u64(hardhat->hash_start) % sizeof(uint32_t))
		return false;
	if(u64(hardhat->directory_start) % sizeof(uint64_t))
		return false;
	if(u64(hardhat->prefix_start) % sizeof(uint32_t))
		return false;

	if(u64(hardhat->data_start) < sizeof *hardhat)
		return false;
	if(u64(hardhat->hash_start) < sizeof *hardhat)
		return false;
	if(u64(hardhat->directory_start) < sizeof *hardhat)
		return false;
	if(u64(hardhat->prefix_start) < sizeof *hardhat)
		return false;

	if(u64(hardhat->data_end) > (uint64_t)st->st_size)
		return false;
	if(u64(hardhat->hash_end) > (uint64_t)st->st_size)
		return false;
	if(u64(hardhat->directory_end) > (uint64_t)st->st_size)
		return false;
	if(u64(hardhat->prefix_end) > (uint64_t)st->st_size)
		return false;

	if(u64(hardhat->data_end) < u64(hardhat->data_start))
		return false;
	if(u64(hardhat->hash_end) < u64(hardhat->hash_start))
		return false;
	if(u64(hardhat->directory_end) < u64(hardhat->directory_start))
		return false;
	if(u64(hardhat->prefix_end) < u64(hardhat->prefix_start))
		return false;

	if(u64(hardhat->directory_end) - u64(hardhat->directory_start) < (uint64_t)u32(hardhat->entries) * (uint64_t)sizeof(uint64_t))
		return false;
	if(u64(hardhat->hash_end) - u64(hardhat->hash_start) < (uint64_t)u32(hardhat->entries) * (uint64_t)(2 * sizeof(uint32_t)))
		return false;
	if(u64(hardhat->prefix_end) - u64(hardhat->prefix_start) < (uint64_t)u32(hardhat->prefixes) * (uint64_t)(2 * sizeof(uint32_t)))
		return false;

	sections[0] = u64(hardhat->data_start);
	sections[1] = u64(hardhat->data_end);
	sections[2] = u64(hardhat->hash_start);
	sections[3] = u64(hardhat->hash_end);
	sections[4] = u64(hardhat->directory_start);
	sections[5] = u64(hardhat->directory_end);
	sections[6] = u64(hardhat->prefix_start);
	sections[7] = u64(hardhat->prefix_end);

	qsort(sections, sizeof sections / (sizeof *sections * 2), sizeof *sections * 2, sectioncmp);

	if(sections[1] > sections[2])
		return false;
	if(sections[3] > sections[4])
		return false;
	if(sections[5] > sections[6])
		return false;

	return true;
}

static void HHE(hardhat_precache)(hardhat_t *hardhat, bool data) {
	union {
		uint8_t *u8ptr;
		hardhat_t *hardhat;
	} cc;

	if(!hardhat)
		return;

	cc.hardhat = hardhat;

	if(data) {
		madvise(cc.u8ptr, u64(hardhat->filesize), MADV_WILLNEED);
	} else {
		madvise(cc.u8ptr + u64(hardhat->hash_start), u64(hardhat->hash_end) - u64(hardhat->hash_start), MADV_WILLNEED);
		madvise(cc.u8ptr + u64(hardhat->directory_start), u64(hardhat->directory_end) - u64(hardhat->directory_start), MADV_WILLNEED);
		madvise(cc.u8ptr + u64(hardhat->prefix_start), u64(hardhat->prefix_end) - u64(hardhat->prefix_start), MADV_WILLNEED);
	}
}

static void HHE(hardhat_close)(hardhat_t *hardhat) {
	union {
		uint8_t *u8ptr;
		hardhat_t *hardhat;
	} cc;

	if(!hardhat)
		return;

	cc.hardhat = hardhat;

	munmap(cc.u8ptr, (size_t)u64(hardhat->filesize));
}

static void HHE(hardhat_debug_dump)(hardhat_t *hardhat) {
	const struct hashentry *he, *ht;
	uint32_t u;
	const uint64_t *directory;
	const uint8_t *rec, *buf;

	buf = (const uint8_t *)hardhat;
	directory = (const uint64_t *)(buf + u64(hardhat->directory_start));

	puts("main hash:");
	ht = (const struct hashentry *)(buf + u64(hardhat->hash_start));
	for(u = 0; u < u32(hardhat->entries); u++) {
		he = ht + u;
		rec = buf + u64(directory[u32(he->data)]);
		printf("\thash: 0x%08"PRIx32", data: %"PRId32", key: '", u32(he->hash), u32(he->data));
		fwrite(rec + 6, 1, u16read(rec + 4), stdout);
		puts("'");
	}

	puts("prefix hash:");
	ht = (const struct hashentry *)(buf + u64(hardhat->prefix_start));
	for(u = 0; u < u32(hardhat->prefixes); u++) {
		he = ht + u;
		rec = buf + u64(directory[u32(he->data)]);
		printf("\thash: 0x%08"PRIx32", data: %"PRId32", key: '", u32(he->hash), u32(he->data));
		fwrite(rec + 6, 1, u16read(rec + 4), stdout);
		puts("'");
	}

}

static void HHE(hhc_hash_find)(hardhat_cursor_t *c) {
	const struct hashentry *he, *ht;
	const struct hardhat *hardhat;
	uint64_t off, reclen, data_start, data_end;
	uint32_t u, hp, hash, he_hash, he_data, datalen, recnum, upper, lower, upper_hash, lower_hash;
	uint16_t len, keylen;
	const uint64_t *directory;
	const uint8_t *rec, *buf;
	const void *str;
	unsigned int tries = 0;
	int r;

	hardhat = c->hardhat;
	recnum = u32(hardhat->entries);
	if(!recnum)
		return;

	str = c->prefix;
	len = c->prefixlen;
	hash = HHE(hhc_calchash)(hardhat, str, len);
	buf = (const uint8_t *)c->hardhat;

	ht = (const struct hashentry *)(buf + u64(hardhat->hash_start));
	directory = (const uint64_t *)(buf + u64(hardhat->directory_start));

	data_start = u64(hardhat->data_start);
	data_end = u64(hardhat->data_end);

	lower = 0;
	upper = recnum;
	lower_hash = 0;
	upper_hash = UINT32_MAX;

	/* binary search for the hash value */
	for(;;) {
		hp = tries++ < 10
			? lower + (uint32_t)((uint64_t)(hash - lower_hash) * (uint64_t)(upper - lower) / ((uint64_t)(upper_hash - lower_hash) + UINT64_C(1)))
			: lower + (upper - lower) / 2;
		he = ht + hp;
//		fprintf(stderr, "%s:%d tries=%u lower=%"PRIu32" upper=%"PRIu32" hp=%"PRIu32" hash=0x%08"PRIx32" lower_hash=0x%08"PRIx32" upper_hash=0x%08"PRIx32"\n", __FILE__, __LINE__, tries, lower, upper, hp, hash, lower_hash, upper_hash);
		he_hash = u32(he->hash);
		if(he_hash == hash) {
			if(u32(hardhat->version) < 3)
				break;
			he_data = u32(he->data);
			if(he_data >= recnum)
				return;
			off = u64(directory[he_data]);
			reclen = 6;
			if(off < data_start || off + reclen < off || off + reclen > data_end || off % 4)
				return;
			rec = buf + off;
			keylen = u16read(rec + 4);
			reclen += keylen;
			if(off + reclen < off || off + reclen > data_end)
				return;
			if(keylen < len) {
				/* found key is shorter than the reference key */
				r = memcmp(rec + 6, str, keylen);
				if(r > 0) {
					/* found key is shorter but lexicographically bigger */
					upper = hp;
					upper_hash = he_hash;
				} else {
					/* found key is sorted before the reference key either because
					** it is shorter or lexicographically smaller or both. */
					lower = hp + 1;
					lower_hash = he_hash;
				}
			} else {
				r = memcmp(rec + 6, str, len);
				if(keylen == len && !r) {
					datalen = u32read(rec);
					if(reclen + datalen < reclen)
						return;
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
				if(r < 0) {
					/* found key is lexicographically smaller */
					lower = hp + 1;
					lower_hash = he_hash;
				} else {
					/* found key is sorted after the reference key because it is
					** either longer or lexicographically larger or both. */
					upper = hp;
					upper_hash = he_hash;
				}
			}
		} else if(he_hash < hash) {
			lower = hp + 1;
			lower_hash = he_hash;
		} else {
			upper = hp;
			upper_hash = he_hash;
		}
		if(lower == upper || (lower_hash == upper_hash && lower_hash != hash))
			return;
	}

	/* There may be multiple keys with the correct hash value.
	** In older database versions, the keys were not sorted, so
	** we need to search up and down to find the real key by
	** comparing key values one by one. */

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
		if(off < data_start || off + reclen < off || off + reclen > data_end || off % 4)
			return;
		rec = buf + off;
		keylen = u16read(rec + 4);
		reclen += keylen;
		if(off + reclen < off || off + reclen > data_end)
			return;
		if(keylen == len && !memcmp(rec + 6, str, len)) {
			datalen = u32read(rec);
			if(reclen + datalen < reclen)
				return;
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
		if(off < data_start || off + reclen < off || off + reclen > data_end || off % 4)
			return;
		rec = buf + off;
		keylen = u16read(rec + 4);
		reclen += keylen;
		if(off + reclen < off || off + reclen > data_end)
			return;
		if(keylen == len && !memcmp(rec + 6, str, len)) {
			datalen = u32read(rec);
			if(reclen + datalen < reclen)
				return;
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

static uint32_t HHE(hhc_prefix_find)(hardhat_t *hardhat, const void *str, uint16_t len) {
	const struct hashentry *he, *ht;
	uint64_t off, reclen, data_start, data_end;
	uint32_t u, datalen, hp, hash, he_hash, he_data, hashnum, recnum, upper, lower, upper_hash, lower_hash;
	uint16_t keylen;
	const uint64_t *directory;
	const uint8_t *rec, *buf;
	int r;
	unsigned int tries = 0;

	recnum = u32(hardhat->entries);
	hashnum = u32(hardhat->prefixes);

	if(!recnum)
		return CURSOR_NONE;

	buf = (const uint8_t *)hardhat;
	directory = (const uint64_t *)(buf + u64(hardhat->directory_start));

	data_start = u64(hardhat->data_start);
	data_end = u64(hardhat->data_end);

	if(!len) {
		// special treatment for '' to prevent it from being
		// returned as the first entry for itself
		off = u64(directory[0]);
		reclen = 6;
		if(off < data_start || off + reclen < off || off + reclen > data_end || off % 4)
			return CURSOR_NONE;
		rec = buf + off;
		keylen = u16read(rec + 4);
		if(keylen) {
			// check 0
			reclen += keylen;
			datalen = u32read(rec);
			if(reclen + datalen < reclen)
				return;
			reclen += datalen;
			if(off + reclen < off || off + reclen > data_end)
				return CURSOR_NONE;
			return 0;
		} else if(recnum > 1) {
			// the first is "", so return the next one
			// check 1
			off = u64(directory[1]);
			if(off < data_start || off + reclen < off || off + reclen > data_end || off % 4)
				return CURSOR_NONE;
			rec = buf + off;
			reclen += u16read(rec + 4);
			datalen = u32read(rec);
			if(reclen + datalen < reclen)
				return;
			reclen += datalen;
			if(off + reclen < off || off + reclen > data_end)
				return CURSOR_NONE;
			return 1;
		} else {
			return CURSOR_NONE;
		}
	}

	if(!hashnum)
		return CURSOR_NONE;

	hash = HHE(hhc_calchash)(hardhat, str, len);
	ht = (const struct hashentry *)(buf + u64(hardhat->prefix_start));

	lower = 0;
	upper = hashnum;
	lower_hash = 0;
	upper_hash = UINT32_MAX;

	for(;;) {
		hp = tries++ < 10
			? lower + (uint32_t)((uint64_t)(hash - lower_hash) * (uint64_t)(upper - lower) / ((uint64_t)(upper_hash - lower_hash) + UINT64_C(1)))
			: lower + (upper - lower) / 2;
		he = ht + hp;
//		fprintf(stderr, "%s:%d tries=%u lower=%"PRIu32" upper=%"PRIu32" hp=%"PRIu32" hash=0x%08"PRIx32" lower_hash=0x%08"PRIx32" upper_hash=0x%08"PRIx32"\n", __FILE__, __LINE__, tries, lower, upper, hp, hash, lower_hash, upper_hash);

		he_hash = u32(he->hash);
		if(he_hash == hash) {
			if(u32(hardhat->version) < 3)
				break;
			he_data = u32(he->data);
			if(he_data >= recnum)
				return CURSOR_NONE;
			off = u64(directory[he_data]);
			reclen = 6;
			if(off < data_start || off + reclen < off || off + reclen > data_end || off % 4)
				return CURSOR_NONE;
			rec = buf + off;
			keylen = u16read(rec + 4);
			reclen += keylen;
			if(off + reclen < off || off + reclen > data_end)
				return CURSOR_NONE;
			if(keylen < len) {
				/* found key is shorter than the reference key */
				r = memcmp(rec + 6, str, keylen);
				if(r > 0) {
					/* found key is shorter but lexicographically bigger */
					upper = hp;
					upper_hash = he_hash;
				} else {
					/* found key is sorted before the reference key either because
					** it is shorter or lexicographically smaller or both. */
					lower = hp + 1;
					lower_hash = he_hash;
				}
			} else {
				r = memcmp(rec + 6, str, len);
				if(!r) {
					datalen = u32read(rec);
					if(reclen + datalen < reclen)
						return CURSOR_NONE;
					reclen += datalen;
					if(off + reclen < off || off + reclen > data_end)
						return CURSOR_NONE;

					if(!he_data)
						return he_data;

					/* check if the prefix we found is actually the first one */
					off = u64(directory[he_data - 1]);
					reclen = 6;
					if(off < data_start || off + reclen < off || off + reclen > data_end || off % 4)
						return CURSOR_NONE;
					rec = buf + off;
					keylen = u16read(rec + 4);
					reclen += keylen;
					if(off + reclen < off || off + reclen > data_end)
						return CURSOR_NONE;
					if(keylen < len || memcmp(rec + 6, str, len))
						return he_data;
					/* bummer, it isn't the first one. proceed as usual */
				}
				if(r < 0) {
					/* found key is lexicographically smaller */
					lower = hp + 1;
					lower_hash = he_hash;
				} else {
					/* found key is sorted after the reference key because it is
					** either longer or lexicographically larger or both. */
					upper = hp;
					upper_hash = he_hash;
				}
			}
		} else if(he_hash < hash) {
			lower = hp + 1;
			lower_hash = he_hash;
		} else {
			upper = hp;
			upper_hash = he_hash;
		}
		if(lower == upper || (lower_hash == upper_hash && lower_hash != hash))
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
        if(off < data_start || off + reclen < off || off + reclen > data_end || off % 4)
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
			if(off < data_start || off + reclen < off || off + reclen > data_end || off % 4)
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
        if(off < data_start || off + reclen < off || off + reclen > data_end || off % 4)
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
			if(off < data_start || off + reclen < off || off + reclen > data_end || off % 4)
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
	const struct hardhat *hardhat;
	uint64_t off, reclen, data_start, data_end;
	uint32_t cur;
	const uint64_t *directory;
	const uint8_t *rec, *buf;
	uint16_t keylen;

	if(!c)
		return false;

	cur = c->cur;
	hardhat = c->hardhat;
	buf = (const uint8_t *)c->hardhat;
	directory = (const uint64_t *)(buf + u64(hardhat->directory_start));

	if(c->started) {
		cur++;
		if(cur < u32(hardhat->entries)) {
			data_start = u64(hardhat->data_start);
			data_end = u64(hardhat->data_end);
			off = u64(directory[cur]);
			reclen = 6;
			if(off < data_start || off + reclen < off || off + reclen > data_end || off % 4) {
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
		cur = HHE(hhc_prefix_find)(hardhat, c->prefix, c->prefixlen);
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
