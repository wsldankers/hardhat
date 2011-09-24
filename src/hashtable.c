#include "config.h"

#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hashtable.h"

#define HASHSPACE 2

static const struct hashtable hashtable_0 = {0};

static uint32_t sqrt32(uint32_t u) {
	uint32_t r, p;

	if(u < 2)
		return u;

	r = p = u / 2;

	do {
		p = r;
		r = (p + u / p) / 2;
	} while(r < p);

	return p;
}

static bool isprime(uint32_t u) {
	uint32_t q;
	for(q = sqrt32(u) + 1; q > 1; q--)
		if(u % q == 0)
			return false;
	return true;
}

uint32_t nextprime(uint32_t u) {
	while(u < UINT32_MAX) {
		if(isprime(u))
			return u;
		u++;
	}

	for(;;) {
		if(isprime(u))
			return u;
		u--;
	}

	return u;
}

static uint32_t nextorderprime(int order) {
	uint32_t u;

	if(order > 31) {
		u = UINT32_MAX;
		while(!isprime(u))
			u--;
	} else {
		u = (UINT32_C(1) << order) + UINT32_C(1);
		while(!isprime(u))
			u++;
	}

	return u;
}

#if 0
uint32_t calchash(const uint8_t *key, size_t len) {
	const uint8_t *end;
	uint32_t hv = UINT32_C(5381);
	end = key + len;
	while(key < end)
		hv = ((hv << 5) + hv) ^ *key++;
	return hv;
}
#else
uint32_t calchash(const uint8_t *key, size_t len) {
    const uint8_t *e;
    uint32_t h;

    e = key + len;
    for(h = 0; key < e; key++)
        h = (h * UINT32_C(16777619)) ^ *key;

    return h;
}
#endif

static void addhash_raw(struct hashtable *ht, uint32_t hash, uint32_t data) {
	struct hashentry *buf;
	uint32_t off, end;
	buf = ht->buf;
	end = ht->size;
	off = hash % ht->size;
	while(buf[off].data != EMPTYHASH)
		if(++off > end)
			off = 0;
	buf[off].hash = hash;
	buf[off].data = data;
}

static bool rehash(struct hashtable *ht) {
	uint32_t size, off;
	struct hashentry *buf;

	size = ht->size;
	buf = ht->buf;

	if(ht->order > 32)
		return false;

	ht->order++;
	ht->size = nextorderprime(ht->order);
	ht->limit = ht->size / HASHSPACE;

	ht->buf = malloc(ht->size * sizeof *ht->buf);
	if(!ht->buf) {
		free(buf);
		return false;
	}
	memset(ht->buf, 255, ht->size * sizeof *ht->buf);

	for(off = 0; off < size; off++)
		if(buf[off].data != EMPTYHASH)
			addhash_raw(ht, buf[off].hash, buf[off].data);

	free(buf);
		
	return true;
}

bool addhash(struct hashtable *ht, uint32_t hash, uint32_t data) {
	addhash_raw(ht, hash, data);
	if(++ht->fill > ht->limit)
		return rehash(ht);
	return true;
}

struct hashtable *newhash(void) {
	struct hashtable *ht;

	ht = malloc(sizeof *ht);
	if(!ht)
		return NULL;
	*ht = hashtable_0;
	ht->order = 16;
	ht->size = nextorderprime(ht->order);
	ht->limit = ht->size / HASHSPACE;

	ht->buf = malloc(ht->size * sizeof *ht->buf);
	if(!ht->buf) {
		free(ht);
		return NULL;
	}
	memset(ht->buf, 255, ht->size * sizeof *ht->buf);

	return ht;
}

void freehash(struct hashtable *ht) {
	if(!ht)
		return;
	free(ht->buf);
	free(ht);
}
