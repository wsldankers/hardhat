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

extern void *hardhat_open(const char *filename);
extern void hardhat_precache(void *buf, bool data);
extern void hardhat_close(void *hardhat);
extern hardhat_cursor_t *hardhat_cursor(const void *hardhat, const void *prefix, uint16_t prefixlen);
extern bool hardhat_fetch(hardhat_cursor_t *c, bool recursive);
extern void hardhat_cursor_free(hardhat_cursor_t *c);

#endif
