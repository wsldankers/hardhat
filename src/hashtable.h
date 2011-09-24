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
