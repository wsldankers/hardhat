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
#include <time.h>
#include <sys/mman.h>
#if defined(HAVE___FPURGE) && defined(HAVE_STDIO_EXT_H)
#include <stdio_ext.h>
#endif

#include "maker.h"
#include "hashtable.h"
#include "layout.h"

/******************************************************************************

	Module to create a hardhat table. Uses an unholy combination of
	buffered I/O and low-level mmap() to get the job done. Caveat developer.

******************************************************************************/

#define export __attribute__((visibility("default")))

struct hardhat_maker {
	/* Output file handle */
	FILE *db;
	/* Database file name */
	char *filename;
	/* Buffer used to manipulate key values (normalization, etc) */
	uint8_t *keybuf;
	/* Window into the already written data, used to detect duplicates */
	uint8_t *window;
	/* Size of window */
	size_t windowsize;
	/* Size of container for added records */
	size_t recbufsize;
	/* Offset of first unused space in output file */
	off_t off;
	/* Offset of added records */
	uint64_t *recbuf;
	/* Number of added records */
	uint32_t recnum;
	/* Hashtable of added records, used to detect duplicates */
	struct hashtable *hashtable;
	/* Indicates what went wrong in case of failure */
	char *error;
	/* If this boolean is set, database creation has failed and
		cannot be restarted or continued. */
	bool failed:1;
	/* Entries have been added, so the alignment is fixed now */
	bool started:1;
	/* Database is completed and cannot be modified anymore */
	bool finished:1;
	/* The superblock, as it will be created at the end */
	struct hardhat superblock;
};

/* The only case in which it is impossible to allocate the
	error dynamically */
static char enomem[] = "Out of memory";

#define HARDHAT_DEFAULT_ALIGNMENT (3)
#define HARDHAT_DEFAULT_BLOCKSIZE (12)

/* struct defaults */
static const hardhat_maker_t hardhat_maker_0 = {
	.recbufsize = 65536,
	.window = MAP_FAILED,
};

#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif

/* Return the error (if any) or an empty string (but never NULL) */
export const char *hardhat_maker_error(hardhat_maker_t *hhm) {
	return hhm
		? hhm->error
			? hhm->error
			: ""
		: strerror(errno);
}

/* Returns true if this database failed in a way that can't be
	recovered from */
export bool hardhat_maker_fatal(hardhat_maker_t *hhm) {
	return hhm ? hhm->failed : true;
}

/* normalize a path:

	- remove repeated slashes
	- remove leading/trailing slashes
	- remove occurrences of .
	- resolve occurrences of ..
*/
__attribute__((optimize(3)))
export size_t hardhat_normalize(void *to, const void *from, size_t size) {
	uint8_t *dst, *cur, *end;
	const uint8_t *src, *sep, *nul;
	size_t len;

	dst = to;
	src = from;

	nul = src + size;
	cur = dst;
	do {
		sep = memchr(src, '/', (size_t)(nul - src));
		if(!sep)
			sep = nul;
		len = (size_t)(sep - src);
		if(!len) {
			// do nothing
		} else if(len == 1 && *src == '.') {
			// do nothing
		} else if(len == 2 && src[0] == '.' && src[1] == '.') {
			end = memrchr(dst, '/', (size_t)(cur - dst));
			cur = end ? end : dst;
		} else {
			if(cur > dst)
				*cur++ = '/';
			memmove(cur, src, len);
			cur += len;
		}
		src = sep + 1;
	} while(sep < nul);

	return (size_t)(cur - dst);
}

/* compare two paths:

	- equal path components are skipped
	- if only one of the paths has no more slashes left, that path "wins"
	- otherwise the remaining components of each path are compared in
	  lexicographic order

	Example sorting:

	x
	x/a
	x/b
	x/a/1
	x/a/2
	x/b/1
*/
__attribute__((optimize(3)))
export int hardhat_cmp(const void *a, size_t al, const void *b, size_t bl) {
	const uint8_t *as, *bs, *ap, *bp;
	uint8_t ac = 0, bc = 0;
	size_t l;

	as = a;
	bs = b;

	l = al < bl ? al : bl;

	while(l) {
		ac = *as;
		bc = *bs;
		if(ac != bc)
			break;
		as++;
		bs++;
		l--;
	}

	if(al < bl) {
		bl -= al - l;
		al = l;
	} else {
		al -= bl - l;
		bl = l;
	}

	if(!al)
		return bl ? -1 : 0;
	if(!bl)
		return 1;

	if(ac == '/')
		return 1;
	else if(bc == '/')
		return -1;

	ap = memchr(as, '/', al);
	bp = memchr(bs, '/', bl);
	if(ap) {
		if(!bp)
			return 1;
	} else {
		if(bp)
			return -1;
	}

	return ac < bc ? -1 : 1;
}

/* Convenience macros to fetch aligned n-bit values */
#define u16read(buf) (*(uint16_t *)(buf))
#define u32read(buf) (*(uint32_t *)(buf))
#define u64read(buf) (*(uint64_t *)(buf))

/* Allocate and set an error message, using printf semantics */
static void hhm_set_error(hardhat_maker_t *hhm, const char *fmt, ...) {
	int r;
	va_list ap;

	if(!hhm)
		return;

	if(hhm->error != enomem)
		free(hhm->error);
	hhm->error = malloc(4096);
	if(hhm->error) {
		va_start(ap, fmt);
		r = vsnprintf(hhm->error, 4096, fmt, ap);
		va_end(ap);
		if(r < 0)
			strncpy(hhm->error, fmt, 4095);
		hhm->error[4095] = '\0';
	} else {
		hhm->error = enomem;
	}
}

static uint32_t makeseed(void) {
	struct timespec ts[8];
	int clocks = 0;
	if(!clock_gettime(CLOCK_REALTIME, ts + clocks))
		clocks++;
	if(!clock_gettime(CLOCK_MONOTONIC, ts + clocks))
		clocks++;
#ifdef CLOCK_PROCESS_CPUTIME_ID
	if(!clock_gettime(CLOCK_PROCESS_CPUTIME_ID, ts + clocks))
		clocks++;
#endif
#ifdef CLOCK_THREAD_CPUTIME_ID
	if(!clock_gettime(CLOCK_THREAD_CPUTIME_ID, ts + clocks))
		clocks++;
#endif
#ifdef CLOCK_MONOTONIC_RAW
	if(!clock_gettime(CLOCK_MONOTONIC_RAW, ts + clocks))
		clocks++;
#endif
#ifdef CLOCK_REALTIME_COARSE
	if(!clock_gettime(CLOCK_REALTIME_COARSE, ts + clocks))
		clocks++;
#endif
#ifdef CLOCK_MONOTONIC_COARSE
	if(!clock_gettime(CLOCK_MONOTONIC_COARSE, ts + clocks))
		clocks++;
#endif
#ifdef CLOCK_BOOTTIME
	if(!clock_gettime(CLOCK_BOOTTIME, ts + clocks))
		clocks++;
#endif
	return calchash_murmur3((const void *)ts, sizeof *ts * clocks, getpid());
}

/* Allocate and initialize a hardhat_maker_t structure.
	Returns NULL on failure, with errno set to the problem. */
export hardhat_maker_t *hardhat_maker_new(const char *filename) {
	hardhat_maker_t *hhm;
	int err, fd;

	if(!filename) {
		errno = EINVAL;
		return NULL;
	}

	hhm = malloc(sizeof *hhm);
	if(!hhm)
		return NULL;

	*hhm = hardhat_maker_0;

	hhm->superblock.hashseed = makeseed();
	hhm->superblock.alignment = HARDHAT_DEFAULT_ALIGNMENT;
	hhm->superblock.blocksize = HARDHAT_DEFAULT_BLOCKSIZE;

	hhm->filename = strdup(filename);
	if(!hhm->filename) {
		err = errno;
		hardhat_maker_free(hhm);
		errno = err;
		return NULL;
	}

	hhm->keybuf = malloc(65536);
	if(!hhm->keybuf) {
		err = errno;
		hardhat_maker_free(hhm);
		errno = err;
		return NULL;
	}

	fd = open(filename, O_RDWR|O_CREAT|O_LARGEFILE|O_NOCTTY, 0666);
	if(fd == -1) {
		err = errno;
		hardhat_maker_free(hhm);
		errno = err;
		return NULL;
	}

	hhm->db = fdopen(fd, "r+");
	if(!hhm->db) {
		err = errno;
		close(fd);
		hardhat_maker_free(hhm);
		errno = err;
		return NULL;
	}

	hhm->off = hhm->superblock.data_start = sizeof hhm->superblock;
	if(fwrite(&hhm->superblock, 1, sizeof hhm->superblock, hhm->db) < sizeof hhm->superblock) {
		err = errno;
		hardhat_maker_free(hhm);
		errno = err;
		return NULL;
	}

	hhm->recbuf = malloc(hhm->recbufsize * sizeof *hhm->recbuf);
	if(!hhm->recbuf) {
		err = errno;
		hardhat_maker_free(hhm);
		errno = err;
		return NULL;
	}

	hhm->hashtable = newhash();
	if(!hhm->hashtable) {
		err = errno;
		hardhat_maker_free(hhm);
		errno = err;
		return NULL;
	}

	return hhm;
}

export bool hardhat_maker_set_alignment(hardhat_maker_t *hhm, size_t alignment, size_t blocksize) {
	if(!hhm || hhm->failed)
		return false;

	if(hhm->started)
		return hhm_set_error(hhm, "can't change alignment after output has started"), false;

	if(alignment) {
		if(alignment & (alignment - 1))
			return hhm_set_error(hhm, "data alignment must be a power of 2"), false;
		hhm->superblock.alignment = ffs(alignment) - 1;
	} else {
		hhm->superblock.alignment = HARDHAT_DEFAULT_ALIGNMENT;
	}

	if(blocksize) {
		if(blocksize & (blocksize - 1))
			return hhm_set_error(hhm, "block size must be a power of 2"), false;
		hhm->superblock.blocksize = ffs(blocksize) - 1;
	} else {
		hhm->superblock.blocksize = HARDHAT_DEFAULT_BLOCKSIZE;
	}

	return true;
}

/* Write bytes to the database and handle any errors */
static bool hhm_db_write(hardhat_maker_t *hhm, const void *buf, size_t len) {
	if(!len)
		return true;

	if(fwrite(buf, 1, len, hhm->db) < len) {
		hhm_set_error(hhm, "writing %d bytes to %s failed: %m", len, hhm->filename);
		hhm->failed = true;
		return false;
	}

	return true;
}

/* Append bytes to the database and update off */
static bool hhm_db_append(hardhat_maker_t *hhm, const void *buf, size_t len) {
	if(!hhm_db_write(hhm, buf, len))
		return false;
	hhm->off += len;
	return true;
}

static bool hhm_db_pad(hardhat_maker_t *hhm, size_t length, size_t alignment) {
	size_t blocksize, offset, align, start, end;

	blocksize = 1 << hhm->superblock.blocksize;
	offset = hhm->off;

	align = -offset % alignment;
	offset += align;

	start = offset % blocksize;
	end = blocksize - -(offset + length) % blocksize;

	if(start > end)
		align += -offset % blocksize;

	if(fseek(hhm->db, align, SEEK_CUR) == -1) {
		hhm_set_error(hhm, "seeking %zu bytes in %s failed: %m", align, hhm->filename);
		hhm->failed = true;
		return false;
	}

	hhm->off += align;

	return true;
}

/* Fetch already written bytes from the database by maintaining a mmap()ed
	window on it */
static const uint8_t *hhm_getrec(hardhat_maker_t *hhm, uint64_t off) {
	if(hhm->windowsize <= off) {
		if(hhm->window != MAP_FAILED)
			munmap(hhm->window, hhm->windowsize);
		if(fflush(hhm->db) == EOF) {
			hhm_set_error(hhm, "writing to %s failed: %m", hhm->filename);
			hhm->window = MAP_FAILED;
			hhm->failed = true;
			return NULL;
		}
		hhm->window = mmap(NULL, hhm->off, PROT_READ, MAP_SHARED, fileno(hhm->db), 0);
		if(hhm->window == MAP_FAILED) {
			hhm_set_error(hhm, "mmap()ing %s failed: %m", hhm->filename);
			hhm->failed = true;
			return NULL;
		}
		hhm->windowsize = hhm->off;
	}
	return hhm->window + off;
}

/* Add an entry to the database (if it doesn't exist yet).
	Returns true on success (or if the entry already existed!)
	Returns false on error. */
export bool hardhat_maker_add(hardhat_maker_t *hhm, const void *key, uint16_t keylen, const void *data, uint32_t datalen) {
	size_t recsize;
	uint32_t hash, hp, value;
	uint64_t off;
	struct hashtable *ht;
	const uint8_t *old;
	void *buf;

	if(!hhm || hhm->failed || hhm->finished) {
		errno = EINVAL;
		return false;
	}
	if(!key && keylen) {
		hhm_set_error(hhm, "key parameter to hardhat_maker_add is NULL");
		return false;
	}
	if(!data && datalen) {
		hhm_set_error(hhm, "data parameter to hardhat_maker_add is NULL");
		return false;
	}
	if(datalen > INT32_MAX) {
		hhm_set_error(hhm, "datalen parameter to hardhat_maker_add is too large");
		return false;
	}

	keylen = (uint16_t)hardhat_normalize(hhm->keybuf, key, keylen);
	key = hhm->keybuf;

	/* Check if the entry isn't already in the hash table.
		If it is, return true. If not, add it and continue. */
	hash = calchash_murmur3(key, (size_t)keylen, hhm->superblock.hashseed);
	ht = hhm->hashtable;
	hp = hash % ht->size;
	for(;;) {
		value = ht->buf[hp].data;
		if(value == EMPTYHASH) {
			if(!addhash(ht, hash, hhm->recnum)) {
				if(hhm->error != enomem) {
					free(hhm->error);
					hhm->error = enomem;
				}
				hhm->failed = true;
				return false;
			}
			break;
		}

		if(ht->buf[hp].hash == hash) {
			old = hhm_getrec(hhm, hhm->recbuf[value]);
			if(!old)
				return false;
			if(u16read(old + 4) == keylen && !memcmp(old + 6, key, keylen))
				return true;
		}
		if(++hp >= ht->size)
			hp = 0;
	}

	hhm->started = true;

	recsize = (size_t)6 + (size_t)keylen;

	/* Write out the entry to disk */
	if(!hhm_db_pad(hhm, recsize, 4))
		return false;

	recsize += (size_t)datalen;

	off = hhm->off;

	if(!hhm_db_append(hhm, &datalen, sizeof datalen))
		return false;

	if(!hhm_db_append(hhm, &keylen, sizeof keylen))
		return false;

	if(!hhm_db_append(hhm, key, keylen))
		return false;

	if(!hhm_db_pad(hhm, datalen, (size_t)1 << hhm->superblock.alignment))
		return false;

	if(!hhm_db_append(hhm, data, datalen))
		return false;

	/* Add the entry offset to the list (resizing it as necessary) */
	if(hhm->recnum == hhm->recbufsize) {
		hhm->recbufsize *= 2;
		buf = realloc(hhm->recbuf, hhm->recbufsize * sizeof *hhm->recbuf);
		if(!buf) {
			if(hhm->error != enomem) {
				free(hhm->error);
				hhm->error = enomem;
			}
			hhm->failed = true;
			return false;
		}
		hhm->recbuf = buf;
	}
	hhm->recbuf[hhm->recnum++] = off;

	return true;
}

/* Add parent directory entries for all entries that do not have them yet */
export bool hardhat_maker_parents(hardhat_maker_t *hhm, const void *data, uint32_t datalen) {
	uint32_t i;
	const uint8_t *rec, *slash, *key;
	uint16_t keylen;

	if(!hhm || hhm->failed || hhm->finished) {
		errno = EINVAL;
		return false;
	}

	for(i = 0; i < hhm->recnum; i++) {
		rec = hhm_getrec(hhm, hhm->recbuf[i]);
		if(!rec)
			return false;
		key = rec + 6;
		slash = memrchr(key, '/', u16read(rec + 4));
		if(!slash)
			continue;
		keylen = (uint16_t)(slash - key);
		/* Stupidly try to add them, duplicates will be detected
			and handled by hardhat_maker_add() */
		if(!hardhat_maker_add(hhm, key, keylen, data, datalen))
			return false;
	}

	return true;
}

static hardhat_maker_t *qsort_data;

/* Compare two entries from the hashtable by fetching their key values
	and comparing them using hardhat_cmp().
	Empty hash values always come last. */
static int qsort_directory_cmp(const void *a, const void *b) {
	const uint8_t *ar, *br;
	uint32_t ad, bd;
	const uint64_t *recs;

	if(!qsort_data)
		return 0;

	ad = ((const struct hashentry *)a)->data;
	bd = ((const struct hashentry *)b)->data;

	if(ad == EMPTYHASH)
		return bd == EMPTYHASH ? 0 : 1;
	else if(bd == EMPTYHASH)
		return -1;

	recs = qsort_data->recbuf;

	ar = hhm_getrec(qsort_data, recs[ad]);
	if(!ar) {
		qsort_data = NULL;
		return 0;
	}

	br = hhm_getrec(qsort_data, recs[bd]);
	if(!br) {
		qsort_data = NULL;
		return 0;
	}

	/* get the first record again: the memory mapping may have moved */
	ar = hhm_getrec(qsort_data, recs[ad]);
	if(!ar) {
		qsort_data = NULL;
		return 0;
	}

	return hardhat_cmp(ar + 6, u16read(ar + 4), br + 6, u16read(br + 4));
}

/* Compare hash entries by hash value, with string comparison as a tie breaker. */
static int qsort_hash_cmp(const void *a, const void *b) {
	const uint8_t *ar, *br;
	uint32_t ad, bd;
	uint16_t al, bl;
	const uint64_t *recs;
	int r;

	ad = ((const struct hashentry *)a)->hash;
	bd = ((const struct hashentry *)b)->hash;

	if(ad == bd) {
		if(!qsort_data)
			return 0;

		ad = ((const struct hashentry *)a)->data;
		bd = ((const struct hashentry *)b)->data;

		if(ad == EMPTYHASH)
			return bd == EMPTYHASH ? 0 : 1;
		else if(bd == EMPTYHASH)
			return -1;

		recs = qsort_data->recbuf;

		ar = hhm_getrec(qsort_data, recs[ad]);
		if(!ar) {
			qsort_data = NULL;
			return 0;
		}

		br = hhm_getrec(qsort_data, recs[bd]);
		if(!br) {
			qsort_data = NULL;
			return 0;
		}

		/* get the first record again: the memory mapping may have moved */
		ar = hhm_getrec(qsort_data, recs[ad]);
		if(!ar) {
			qsort_data = NULL;
			return 0;
		}

		al = u16read(ar + 4);
		bl = u16read(br + 4);

		if(al < bl) {
			r = memcmp(ar + 6, br + 6, al);
			return r ? r : -1;
		} else {
			r = memcmp(ar + 6, br + 6, bl);
			return r ? r : al != bl;
		}
	}

	return ad < bd ? -1 : 1;
}

/* Find the longest common prefix (on ‘/’ boundaries) */
__attribute__((optimize(3)))
static size_t common_parents(const uint8_t *a, size_t al, const uint8_t *b, size_t bl) {
	size_t cl = 0, l, i;
	uint8_t ac, bc;

	l = al < bl ? al : bl;

	for(i = 0; i < l; i++) {
		ac = a[i];
		bc = b[i];
		if(ac != bc)
			break;
		if(ac == '/')
			cl = i + 1;
	}

	return cl;
}

/* Finish up the database by writing the indexes and the superblock */
export bool hardhat_maker_finish(hardhat_maker_t *hhm) {
	FILE *db;
	struct hashtable *ht;
	struct hashentry *he;
	uint32_t i, num, pfxnum;
	uint64_t *dir;
	const uint8_t *cur, *prev, *end;
	uint16_t curlen, prevlen, endlen;

	if(!hhm || hhm->failed || hhm->finished) {
		errno = EINVAL;
		return false;
	}

	db = hhm->db;
	num = hhm->recnum;
	hhm->superblock.data_end = hhm->off;
	qsort_data = hhm;

	if(!hhm_db_pad(hhm, num * sizeof *dir, sizeof *dir)) {
		hhm->failed = true;
		return false;
	}

	/* Sort the hashtable in directory order */
	ht = hhm->hashtable;
	qsort(ht->buf, ht->size, sizeof *ht->buf, qsort_directory_cmp);
	if(!qsort_data) {
		hhm->failed = true;
		return false;
	}

	hhm->superblock.directory_start = hhm->off;

	/* Write out the directory using the sorted hashtable for ordering */
	dir = hhm->recbuf;
	for(i = 0; i < num; i++) {
		he = ht->buf + i;

		if(!hhm_db_append(hhm, dir + he->data, sizeof *dir))
			return false;

		he->data = i;
	}

	hhm->superblock.directory_end = hhm->off;

	if(!hhm_getrec(hhm, hhm->superblock.directory_end))
		return false;

	/* Read back the list of offsets as we wrote it out earlier */
	memcpy(dir, hhm->window + hhm->superblock.directory_start, sizeof *dir * num);

	/* Now sort the hashtable again, this time on hash value */
	qsort(ht->buf, num, sizeof *ht->buf, qsort_hash_cmp);

	if(!hhm_db_pad(hhm, num * sizeof *ht->buf, sizeof *ht->buf)) {
		hhm->failed = true;
		return false;
	}

	hhm->superblock.hash_start = hhm->off;

	/* Write out the hashtable (which will serve as the primary
		entry lookup table) */
	if(!hhm_db_append(hhm, ht->buf, num * sizeof *ht->buf))
		return false;

	hhm->superblock.hash_end = hhm->off;

	/* Calculate the list of common prefixes, reusing the old hash
		table as storage */
	prev = NULL;
	prevlen = 0;
	pfxnum = 0;
	for(i = 0; i < num; i++) {
		cur = hhm->window + dir[i];
		curlen = u16read(cur + 4);
		cur += 6;

		endlen = common_parents(prev, prevlen, cur, curlen);
		end = cur + endlen;
		for(;;) {
			end = memchr(end, '/', curlen - endlen);
			if(!end)
				break;
			end++;
		
			endlen = (uint16_t)(end - cur);
			if(ht->size == pfxnum) {
				ht->size *= 2;
				he = realloc(ht->buf, ht->size * sizeof *ht->buf);
				if(!he) {
					hhm->failed = true;
					if(hhm->error != enomem) {
						free(hhm->error);
						hhm->error = enomem;
					}
					return false;
				}
				ht->buf = he;
			}
			he = ht->buf + pfxnum++;
			he->hash = calchash_murmur3(cur, endlen, hhm->superblock.hashseed);
			he->data = i;
		}
		prev = cur;
		prevlen = curlen;
	}

	/* Write out the prefix list as a hash table */
	qsort(ht->buf, pfxnum, sizeof *ht->buf, qsort_hash_cmp);

	if(!hhm_db_pad(hhm, pfxnum  * sizeof *ht->buf, sizeof *ht->buf)) {
		hhm->failed = true;
		return false;
	}

	hhm->superblock.prefix_start = hhm->off;

	if(!hhm_db_append(hhm, ht->buf, pfxnum * sizeof *ht->buf))
		return false;

	hhm->superblock.prefix_end = hhm->off;

	/* Create and write out the superblock */
	memcpy(hhm->superblock.magic, HARDHAT_MAGIC, sizeof hhm->superblock.magic);
	hhm->superblock.byteorder = UINT64_C(0x0123456789ABCDEF);
	hhm->superblock.version = UINT32_C(3);
	hhm->superblock.entries = num;
	hhm->superblock.prefixes = pfxnum;
	hhm->superblock.filesize = hhm->off;
	hhm->superblock.checksum = calchash_murmur3((const void *)&hhm->superblock, sizeof hhm->superblock - 4, hhm->superblock.hashseed);

	if(fseek(db, 0, SEEK_SET) == -1) {
		hhm_set_error(hhm, "seeking in %s failed: %m", hhm->filename);
		hhm->failed = true;
		return false;
	}

	if(!hhm_db_write(hhm, &hhm->superblock, sizeof hhm->superblock))
		return false;

	hhm->db = NULL;
	if(fflush(db) == EOF) {
		hhm_set_error(hhm, "writing to %s failed: %m", hhm->filename);
		hhm->failed = true;
		return false;
	}

	if(ftruncate(fileno(db), (off_t)hhm->off) == -1) {
		hhm_set_error(hhm, "padding %s failed: %m", hhm->filename);
		hhm->failed = true;
		return false;
	}

	if(fdatasync(fileno(db)) == -1) {
		hhm_set_error(hhm, "writing %s failed: %m", hhm->filename);
		hhm->failed = true;
		return false;
	}

	hhm->db = NULL;
	if(fclose(db) == EOF) {
		hhm_set_error(hhm, "writing to %s failed: %m", hhm->filename);
		hhm->failed = true;
		return false;
	}

	hhm->finished = true;

	return true;
}

/* Free a hardhat_maker_t struct and all it contains */
export void hardhat_maker_free(hardhat_maker_t *hhm) {
	if(!hhm)
		return;
	if(hhm->db) {
		/* Various gambits to prevent flushing the buffer.
		** Unfinished shutdown may be due to a fork(), in which case
		** our flushing could theoretically corrupt the result. */
#if defined(HAVE_FPURGE)
		fpurge(hhm->db);
#elif defined(HAVE___FPURGE)
		__fpurge(hhm->db);
#elif defined(HAVE_FILENO)
		int fd = open("/dev/null", O_NOCTTY|O_WRONLY);
		if(fd != -1) {
			dup2(fd, fileno(hhm->db));
			close(fd);
		}
#endif
		fclose(hhm->db);
	}
	freehash(hhm->hashtable);
	free(hhm->keybuf);
	free(hhm->recbuf);
	free(hhm->filename);
	if(hhm->window != MAP_FAILED)
		munmap(hhm->window, hhm->windowsize);
	if(hhm->error != enomem)
		free(hhm->error);
	*hhm = hardhat_maker_0;
	hhm->failed = true;
	hhm->error = "*** Use after free ***";
	free(hhm);
}
