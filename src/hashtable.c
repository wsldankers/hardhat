/******************************************************************************

	hardhat - read and write databases optimized for filename-like keys
	Copyright (c) 2011-2014 Wessel Dankers <wsl@fruit.je>

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

#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hashtable.h"
#include "murmur3.h"

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

#define START_ORDER ((order_t)8)
#define MIN_FREE(size) ((size) >> 3)
#define ENTRY_NOT_FOUND __SIZE_MAX__

static const struct hashtable hashtable_0 = {NULL, 0, START_ORDER};
//static const struct hashentry hashentry_0 = {0, EMPTYHASH};

/* hashing function (Fowler-Noll-Vo 1a) */
uint32_t calchash_fnv1a(const uint8_t *key, size_t len) {
	uint32_t h = UINT32_C(2166136261);
	for(const uint8_t *e = key + len; key < e; key++)
		h = (h ^ *key) * UINT32_C(16777619);
	return h;
}

uint32_t calchash_murmur3(const uint8_t *key, size_t len, uint32_t seed) {
	uint32_t hash;
	murmurhash3_32(key, len, seed, &hash);
	return hash;
}

static inline uint32_t size_to_mask(uint32_t size) {
	return size - UINT32_C(1);
}

/* add a value at the first free slot of the hash */
static void addhash_raw(struct hashtable *ht, uint32_t my_hash, uint32_t my_data) {
	struct hashentry *entries = ht->entries;
	order_t shift = order_to_shift(ht->order);
	uint32_t mask = shift_to_mask(shift);
	uint32_t offset = hash_to_offset(my_hash, shift);

	for(uint32_t my_diff = 0;; my_diff++) {
		struct hashentry *entry = entries + offset;
		uint32_t their_data = entry->data;
		if(their_data == EMPTYHASH) {
			entry->hash = my_hash;
			entry->data = my_data;
			return;
		}
		if(my_data == their_data)
			return;

		uint32_t their_hash = entry->hash;
		uint32_t their_diff = difference(offset, hash_to_offset(their_hash, shift), mask);
		if(their_diff < my_diff) {
			entry->hash = my_hash;
			entry->data = my_data;
			my_hash = their_hash;
			my_data = their_data;
			break;
		}

		offset = (offset + 1) & mask;
	}

	for(;;) {
		offset = (offset + 1) & mask;
		struct hashentry *entry = entries + offset;

		uint32_t their_data = entry->data;
		uint32_t their_hash = entry->hash;
		entry->hash = my_hash;
		entry->data = my_data;
		if(their_data == EMPTYHASH)
			break;
		my_hash = their_hash;
		my_data = their_data;
	}
}

static inline struct hashentry *alloc_entries(uint32_t num) {
	size_t len = (size_t)num * sizeof(struct hashentry);
	struct hashentry *entries = malloc(len);
	if(entries)
		memset(entries, 255, len);
	return entries;
}

#define free_entries free

/* allocate a new hash table and copy the old elements over */
static bool rehash(struct hashtable *ht, order_t new_order) {
	struct hashentry *new_entries = alloc_entries(order_to_size(new_order));
	if(!new_entries)
		return false;

	//fprintf(stderr, "resized to %zd\n", order_to_size(new_order));

	struct hashentry *old_entries = ht->entries;
	order_t old_order = ht->order;
	ht->entries = new_entries;
	ht->order = new_order;

	uint32_t old_size = order_to_size(old_order);
	for(uint32_t offset = 0; offset < old_size; offset++) {
		struct hashentry *entry = old_entries + offset;
		uint32_t data = entry->data;
		if(data != EMPTYHASH)
			addhash_raw(ht, entry->hash, data);
	}

	free_entries(old_entries);

	return true;
}

/* add an element and check if the hash table hasn't become too large */
bool addhash(struct hashtable *ht, uint32_t hash, uint32_t data) {
	uint32_t fill = ht->fill + 1;
	order_t order = ht->order;

	size_t size = order_to_size(order);
	if(fill > size - MIN_FREE(size) && !rehash(ht, order + 1))
		return false;

	addhash_raw(ht, hash, data);
	ht->fill = fill;

	return true;
}

/* allocate and initialize the hash table */
struct hashtable *newhash(void) {
	struct hashtable *ht = malloc(sizeof *ht);
	if(ht) {
		*ht = hashtable_0;
		struct hashentry *entries = alloc_entries(order_to_size(ht->order));
		if(entries) {
			ht->entries = entries;
		} else {
			free(ht);
			ht = NULL;
		}
	}
	return ht;
}

void freehash(struct hashtable *ht) {
	if(ht) {
		free_entries(ht->entries);
		free(ht);
	}
}
