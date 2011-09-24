#ifndef HARDHAT_READER_H
#define HARDHAT_READER_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

typedef struct hardhat_cursor {
	const void *hardhat;
	const void *key;
	const void *data;
	uint32_t cur;
	uint32_t datalen;
	uint16_t keylen;
	uint16_t prefixlen;
	uint8_t prefix[1];
} hardhat_cursor_t;

void *hardhat_open(const char *filename);
hardhat_cursor_t *hardhat_cursor(const void *hardhat, const void *prefix, uint16_t prefixlen);
bool hardhat_fetch(hardhat_cursor_t *c, bool recursive);
void hardhat_cursor_free(hardhat_cursor_t *c);

#endif
