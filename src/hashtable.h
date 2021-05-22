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

#ifndef HARDHAT_HASHTABLE_H
#define HARDHAT_HASHTABLE_H

#include <stdint.h>

struct hashentry {
	uint32_t hash;
	uint32_t data;
};

typedef uint32_t order_t;

struct hashtable {
	struct hashentry *entries;
	uint32_t fill;
	order_t order;
};

#define EMPTYHASH UINT32_MAX
#define PHI UINT32_C(2654435769)
#define THEORY 1

extern uint32_t calchash_fnv1a(const uint8_t *key, size_t len);
extern uint32_t calchash_murmur3(const uint8_t *key, size_t len, uint32_t seed);
extern struct hashtable *newhash(void);
extern bool addhash(struct hashtable *ht, uint32_t hash, uint32_t data);
extern void freehash(struct hashtable *ht);

static inline order_t order_to_shift(order_t order) {
	return 32 - order;
}

static inline uint32_t shift_to_mask(order_t shift) {
	return ~UINT32_C(0) >> shift;
}

static inline uint32_t order_to_size(order_t order) {
	return UINT32_C(1) << order;
}

static inline uint32_t hash_to_offset(uint32_t hash, order_t shift) {
	return (hash * PHI) >> shift;
}

static inline uint32_t difference(uint32_t a, uint32_t b, uint32_t mask) {
	return (a - b) & mask;
}

#endif
