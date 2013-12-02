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

#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hashtable.h"

/******************************************************************************

	Utility functions to maintain a simple hashtable that does not
	support deletes and only stores 32-bit unsigned integers.

	Functions returning bool return true on success and false
	on failure. After they return false once, the table is unusable.

	There are no functions to support lookup. To look up a value, use
	the hash function modulo the table size to get the first possible
	position, then iterate over the items in the table (looping at the
	end) until you either find the entry or encounter EMPTYHASH (which
	means the item was not in the table).

******************************************************************************/

/* hashtable size will always be at least twice the number of entries: */
#define HASHSPACE 2

static const struct hashtable hashtable_0 = {0};

/* 32-bit integer version of a square root */
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

/* naive prime test */
static bool isprime(uint32_t u) {
	uint32_t q;
	for(q = sqrt32(u) + 1; q > 1; q--)
		if(u % q == 0)
			return false;
	return true;
}

/* return a prime number that is strictly larger than u */
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

/* return a prime number that is strictly larger than 2^order */
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

/* hashing function (Fowler-Noll-Vo 1a) */
uint32_t calchash(const uint8_t *key, size_t len) {
	const uint8_t *e;
	uint32_t h;

	e = key + len;
	for(h = UINT32_C(2166136261); key < e; key++)
		h = (h ^ *key) * UINT32_C(16777619);

	return h;
}

/*
uint64_t calchash64(const uint8_t *key, size_t len) {
	const uint8_t *e;
	uint64_t h;

	e = key + len;
	for(h = UINT64_C(14695981039346656037); key < e; key++)
		h = (h ^ *key) * UINT64_C(1099511628211);

	return h;
}
*/

/* add a value at the first free slot of the hash */
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

/* allocate a new hash table and copy the old elements over */
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

/* add an element and check if the hash table hasn't become too large */
bool addhash(struct hashtable *ht, uint32_t hash, uint32_t data) {
	addhash_raw(ht, hash, data);
	if(++ht->fill > ht->limit)
		return rehash(ht);
	return true;
}

/* allocate and initialize the hash table */
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
