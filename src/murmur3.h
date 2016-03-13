#pragma once

#include <string.h>
#include <stdint.h>

void murmurhash3_x86_32(const void *key, size_t len, uint32_t seed, void *out);
void murmurhash3_x86_128(const void *key, size_t len, uint32_t seed, void *out);
void murmurhash3_x64_128(const void *key, size_t len, uint32_t seed, void *out);

//#define murmurhash3_32 murmurhash3_x86_32
__attribute__((unused)) static void murmurhash3_32(__attribute__((unused)) const void *key, __attribute__((unused)) size_t len, __attribute__((unused)) uint32_t seed, void *out) { *(uint32_t *)out = 0; }

#if __SIZEOF_POINTER__ > 4 || defined(__ILP32__)
#define murmurhash3_128 murmurhash3_x64_128
#else
#define murmurhash3_128 murmurhash3_x86_128
#endif
