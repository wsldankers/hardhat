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

#ifndef _HARDHAT_HASHTABLE_H
#define _HARDHAT_HASHTABLE_H

#include <stdint.h>

struct hashentry {
	uint32_t hash;
	uint32_t data;
};

struct hashtable {
	struct hashentry *buf;
	uint32_t fill;
	uint32_t limit;
	uint32_t size;
	int order;
};

#define EMPTYHASH UINT32_MAX

extern uint32_t calchash(const uint8_t *key, size_t len);
extern uint32_t nextprime(uint32_t u);
extern struct hashtable *newhash(void);
extern bool addhash(struct hashtable *ht, uint32_t hash, uint32_t data);
extern void freehash(struct hashtable *ht);

#endif
