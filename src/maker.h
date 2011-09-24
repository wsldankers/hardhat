#ifndef HARDHAT_MAKER_H
#define HARDHAT_MAKER_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct hardhat_maker hardhat_maker_t;

extern const char *hardhat_maker_error(hardhat_maker_t *hhm);
extern bool hardhat_maker_fatal(hardhat_maker_t *hhm);
extern hardhat_maker_t *hardhat_maker_new(const char *filename);
extern bool hardhat_maker_add(hardhat_maker_t *hhm, const void *key, uint16_t keylen, const void *data, uint32_t datalen);
extern bool hardhat_maker_parents(hardhat_maker_t *hhm, const void *data, uint32_t datalen);
extern bool hardhat_maker_finish(hardhat_maker_t *hhm);
extern void hardhat_maker_free(hardhat_maker_t *hhm);
extern size_t hardhat_normalize(uint8_t *dst, const uint8_t *src, size_t size);
extern int hardhat_cmp(const void *a, size_t al, const void *b, size_t bl);

#endif
