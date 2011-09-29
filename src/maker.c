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
#include <sys/mman.h>

#include "maker.h"
#include "hashtable.h"
#include "layout.h"

#define export __attribute__((visibility("default")))

struct hardhat_maker {
	FILE *db;
	char *filename;
	uint8_t *keybuf, *window;
	size_t recsize, padsize, windowsize, recbufsize;
	uint64_t off, *recbuf;
	uint32_t recnum;
	struct hashtable *hashtable;
	bool failed, finished;
	char *error;
	struct hardhat_superblock superblock;
};

static char enomem[] = "Out of memory";

static const hardhat_maker_t hardhat_maker_0 = {
	.recbufsize = 65536,
	.window = MAP_FAILED
};

export const char *hardhat_maker_error(hardhat_maker_t *hhm) {
	return hhm
		? hhm->error
			? hhm->error
			: ""
		: strerror(errno);
}

export bool hardhat_maker_fatal(hardhat_maker_t *hhm) {
	return hhm ? hhm->failed : true;
}

/* normalize a path:

	- remove repeated slashes
	- remove leading/trailing slashes
	- remove occurrences of .
	- resolve occurrences of ..
*/
export size_t hardhat_normalize(uint8_t *dst, const uint8_t *src, size_t size) {
	uint8_t *cur, *end;
	const uint8_t *sep, *nul;
	size_t len;

#if 0
	/* enable this to preserve absolute paths */
	if(*src == '/')
		*dst++ = *src++;
#endif

	nul = src + size;
	cur = dst;
	do {
		/* strchrnul() */
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
			if(end)
				cur = end;
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

	- paths are sorted by the number of slashes
	- if that number is equal, do a standard string comparison
*/
export int hardhat_cmp(const void *a, size_t al, const void *b, size_t bl) {
	const char *as, *bs, *ap, *bp, *ae, *be;
	size_t ac, bc;
	int c;

	if(!al)
		return bl ? -1 : 0;
	if(!bl)
		return 1;

	as = a;
	bs = b;
	ae = as + al;
	be = bs + bl;

	for(;;) {
		ap = memchr(as, '/', (size_t)(ae - as));
		bp = memchr(bs, '/', (size_t)(be - bs));
		if(ap) {
			if(!bp)
				return 1;
			ac = (size_t)(ap - as);
			bc = (size_t)(bp - bs);
		} else {
			if(bp)
				return -1;
			ac = (size_t)(ae - as);
			bc = (size_t)(be - bs);
		}

		c = memcmp(as, bs, ac < bc ? ac : bc);
		if(c)
			return c;

		if(ac < bc)
			return -1;
		else if(ac > bc)
			return 1;
		else if(!ap)
			return 0;

		as = ap + 1;
		bs = bp + 1;
	}
}

static size_t pad4(size_t x) {
	size_t p;
	p = x & 3;
	if(p)
		return x + 4 - p;
	return x;
}

static size_t pad4k(size_t x) {
	size_t p;
	p = x & 4095;
	if(p)
		return x + 4096 - p;
	return x;
}

#define u16read(buf) (*(uint16_t *)(buf))
#define u32read(buf) (*(uint32_t *)(buf))
#define u64read(buf) (*(uint64_t *)(buf))

static void hhm_set_error(hardhat_maker_t *hhm, const char *fmt, ...) {
	int r;
	va_list ap;

	if(!hhm)
		return;

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

export hardhat_maker_t *hardhat_maker_new(const char *filename) {
	hardhat_maker_t *hhm;
	int err;

	if(!filename) {
		errno = EINVAL;
		return NULL;
	}

	hhm = malloc(sizeof *hhm);
	if(!hhm)
		return NULL;

	*hhm = hardhat_maker_0;

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

	hhm->db = fopen(filename, "w+");
	if(!hhm->db) {
		err = errno;
		hardhat_maker_free(hhm);
		errno = err;
		return NULL;
	}

	hhm->off = 4096;
	if(fseek(hhm->db, hhm->off, SEEK_SET) == -1) {
		err = errno;
		hardhat_maker_free(hhm);
		errno = err;
		return NULL;
	}
	hhm->superblock.data_start = hhm->off;

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

static bool hhm_db_append(hardhat_maker_t *hhm, const void *buf, size_t len) {
	if(!hhm_db_write(hhm, buf, len))
		return false;
	hhm->off += len;
	return true;
}

static const uint8_t *hhm_getrec(hardhat_maker_t *hhm, uint64_t off) {
	if(hhm->windowsize < off) {
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

export bool hardhat_maker_add(hardhat_maker_t *hhm, const void *key, uint16_t keylen, const void *data, uint32_t datalen) {
	size_t recsize, padsize;
	static const char padding[4] = {0};
	uint32_t hash, hp, value;
	uint64_t off;
	struct hashtable *ht;
	const uint8_t *old;
	void *buf;

	if(!hhm || hhm->failed || hhm->finished) {
		errno = EINVAL;
		return false;
	}
	if(!key) {
		hhm_set_error(hhm, "key parameter to hardhat_maker_add is NULL");
		return false;
	}
	if(!data) {
		hhm_set_error(hhm, "data parameter to hardhat_maker_add is NULL");
		return false;
	}
	if(datalen > INT32_MAX) {
		hhm_set_error(hhm, "datalen parameter to hardhat_maker_add is too large");
		return false;
	}

	keylen = (uint16_t)hardhat_normalize(hhm->keybuf, key, keylen);
	key = hhm->keybuf;

	hash = calchash(key, (size_t)keylen);
	ht = hhm->hashtable;
	hp = hash % ht->size;
	for(;;) {
		value = ht->buf[hp].data;
		if(value == EMPTYHASH) {
			if(!addhash(ht, hash, hhm->recnum)) {
				hhm->error = enomem;
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

	recsize = (size_t)6 + (size_t)keylen + (size_t)datalen;
	padsize = pad4(recsize);

	off = hhm->off;

	if(!hhm_db_append(hhm, &datalen, sizeof datalen))
		return false;

	if(!hhm_db_append(hhm, &keylen, sizeof keylen))
		return false;

	if(!hhm_db_append(hhm, key, keylen))
		return false;

	if(!hhm_db_append(hhm, data, datalen))
		return false;

	if(!hhm_db_append(hhm, padding, padsize - recsize))
		return false;

	if(hhm->recnum == hhm->recbufsize) {
		hhm->recbufsize *= 2;
		buf = realloc(hhm->recbuf, hhm->recbufsize * sizeof *hhm->recbuf);
		if(!buf) {
			hhm->error = enomem;
			hhm->failed = true;
			return false;
		}
		hhm->recbuf = buf;
	}
	hhm->recbuf[hhm->recnum++] = off;

	return true;
}

export bool hardhat_maker_parents(hardhat_maker_t *hhm, const void *data, uint32_t datalen) {
	struct hashtable *ht;
	uint32_t i;
	const uint8_t *rec, *slash, *key;
	uint16_t keylen;

	if(!hhm || hhm->failed || hhm->finished) {
		errno = EINVAL;
		return false;
	}

	ht = hhm->hashtable;
	for(i = 0; i < hhm->recnum; i++) {
		rec = hhm_getrec(hhm, hhm->recbuf[i]);
		if(!rec)
			return false;
		key = rec + 6;
		slash = memrchr(key, '/', u16read(rec + 4));
		if(!slash)
			continue;
		keylen = (uint16_t)(slash - key);
		if(!hardhat_maker_add(hhm, key, keylen, data, datalen))
			return false;
	}

	return true;
}

static hardhat_maker_t *qsort_data;

static int qsort_directory_cmp(const void *a, const void *b) {
	const uint8_t *ar, *br;
	uint32_t ad, bd;
	const uint64_t *recs;

	if(!qsort_data)
		return 0;

	ad = ((const struct hashentry *)a)->data;
	bd = ((const struct hashentry *)b)->data;

	if(ad == UINT32_MAX)
		return bd == UINT32_MAX ? 0 : 1;
	else if(bd == UINT32_MAX)
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

	return hardhat_cmp(ar + 6, u16read(ar + 4), br + 6, u16read(br + 4));
}

static int qsort_hash_cmp(const void *a, const void *b) {
	uint32_t am, bm;

	am = ((const struct hashentry *)a)->hash;
	bm = ((const struct hashentry *)b)->hash;

	return am < bm ? -1 : am > bm ? 1 : 0;
}

export bool hardhat_maker_finish(hardhat_maker_t *hhm) {
	FILE *db;
	struct hashtable *ht;
	struct hashentry *he;
	uint32_t i, num;
	uint64_t *dir;

	if(!hhm || hhm->failed || hhm->finished) {
		errno = EINVAL;
		return false;
	}

	db = hhm->db;
	num = hhm->recnum;

	hhm->superblock.data_end = hhm->off;

	hhm->off = pad4k(hhm->off);
	if(fseek(db, hhm->off, SEEK_SET) == -1) {
		hhm_set_error(hhm, "seeking in %s failed: %m", hhm->filename);
		hhm->failed = true;
		return false;
	}

	ht = hhm->hashtable;
	qsort_data = hhm;
	qsort(ht->buf, ht->size, sizeof *ht->buf, qsort_directory_cmp);

	hhm->superblock.directory_start = hhm->off;

	dir = hhm->recbuf;
	for(i = 0; i < num; i++) {
		he = ht->buf + i;

		if(!hhm_db_append(hhm, dir + he->data, sizeof *dir))
			return false;

		he->data = i;
	}

	hhm->superblock.directory_end = hhm->off;

	qsort_data = hhm;
	qsort(ht->buf, num, sizeof *ht->buf, qsort_hash_cmp);
	if(!qsort_data) {
		hhm->failed = true;
		return false;
	}

	hhm->off = pad4k(hhm->off);
	if(fseek(db, hhm->off, SEEK_SET) == -1) {
		hhm_set_error(hhm, "seeking in %s failed: %m", hhm->filename);
		hhm->failed = true;
		return false;
	}

	hhm->superblock.hash_start = hhm->off;

	if(!hhm_db_append(hhm, ht->buf, num * sizeof *ht->buf))
		return false;

	hhm->superblock.hash_end = hhm->off;

	hhm->off = pad4k(hhm->off);

	memcpy(hhm->superblock.magic, HARDHAT_MAGIC, sizeof hhm->superblock.magic);
	hhm->superblock.byteorder = UINT64_C(0x0123456789ABCDEF);
	hhm->superblock.version = UINT32_C(1);
	hhm->superblock.entries = num;
	hhm->superblock.filesize = hhm->off;
	hhm->superblock.checksum = calchash((const void *)&hhm->superblock, sizeof hhm->superblock - 4);

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

export void hardhat_maker_free(hardhat_maker_t *hhm) {
	if(!hhm)
		return;
	if(hhm->db)
		fclose(hhm->db);
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
	free(hhm);
}
