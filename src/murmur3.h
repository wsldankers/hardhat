/******************************************************************************

	murmurhash3 was written by Austin Appleby, and is placed in the public
	domain. The author hereby disclaims copyright to this source code.

	Note - The x86 and x64 versions do _not_ produce the same results, as the
	algorithms are optimized for their respective platforms. You can still
	compile and run any of them on any platform, but your performance with the
	non-native version will be less than optimal.

******************************************************************************/

#ifndef HARDHAT_MURMUR3_H
#define HARDHAT_MURMUR3_H

#include <string.h>
#include <stdint.h>

void murmurhash3_x86_32(const void *key, size_t len, uint32_t seed, void *out);
void murmurhash3_x86_128(const void *key, size_t len, uint32_t seed, void *out);
void murmurhash3_x64_128(const void *key, size_t len, uint32_t seed, void *out);

#define murmurhash3_32 murmurhash3_x86_32

#if __SIZEOF_POINTER__ > 4 || defined(__ILP32__)
#define murmurhash3_128 murmurhash3_x64_128
#else
#define murmurhash3_128 murmurhash3_x86_128
#endif

#endif
