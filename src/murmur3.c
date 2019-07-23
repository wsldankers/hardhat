/******************************************************************************

	murmurhash3 was written by Austin Appleby, and is placed in the public
	domain. The author hereby disclaims copyright to this source code.

	Note - The x86 and x64 versions do _not_ produce the same results, as the
	algorithms are optimized for their respective platforms. You can still
	compile and run any of them on any platform, but your performance with the
	non-native version will be less than optimal.

******************************************************************************/

#include "murmur3.h"

#ifdef __GNUC__
#define PURE_INLINE __attribute__((always_inline,pure,optimize(3))) inline
#else
#define PURE_INLINE inline
#endif

static PURE_INLINE uint32_t rotl32(uint32_t x, int r) {
	return (x << r) | (x >> (32 - r));
}

static PURE_INLINE uint64_t rotl64(uint64_t x, int r) {
	return (x << r) | (x >> (64 - r));
}

#define	ROTL32(x, y) rotl32(x, y)
#define ROTL64(x, y) rotl64(x, y)

// Block read - if your platform needs to do endian-swapping or can only
// handle aligned reads, do the conversion here
#if defined(__i386__) || defined(__amd64__)
#define getblock32(p, i) (p[i])
#define getblock64(p, i) (p[i])
#else
static PURE_INLINE uint32_t getblock32(const uint32_t *p, size_t off) {
	const uint8_t *s = (const uint8_t *)(p + off);
	return (uint32_t)s[0]
		| ((uint32_t)s[1] << 8)
		| ((uint32_t)s[2] << 16)
		| ((uint32_t)s[3] << 24);
}
static PURE_INLINE uint64_t getblock64(const uint64_t *p, size_t off) {
	const uint8_t *s = (const uint8_t *)(p + off);
	return (uint64_t)s[0]
		| ((uint64_t)s[1] << 8)
		| ((uint64_t)s[2] << 16)
		| ((uint64_t)s[3] << 24)
		| ((uint64_t)s[4] << 32)
		| ((uint64_t)s[5] << 40)
		| ((uint64_t)s[6] << 48)
		| ((uint64_t)s[7] << 56);
}
#endif

// Finalization mix - force all bits of a hash block to avalanche
static inline PURE_INLINE uint32_t fmix32(uint32_t h) {
	h ^= h >> 16;
	h *= UINT32_C(0x85EBCA6B);
	h ^= h >> 13;
	h *= UINT32_C(0xC2B2AE35);
	h ^= h >> 16;

	return h;
}

static inline PURE_INLINE uint64_t fmix64(uint64_t k) {
	k ^= k >> 33;
	k *= UINT64_C(0xFF51AFD7ED558CCD);
	k ^= k >> 33;
	k *= UINT64_C(0xC4CEB9FE1A85EC53);
	k ^= k >> 33;

	return k;
}

//-----------------------------------------------------------------------------

void murmurhash3_x86_32(const void * key, size_t len, uint32_t seed, void *out) {
	const uint8_t *data = (const uint8_t *)key;
	const size_t nblocks = len / 4;
	size_t i;

	uint32_t h1 = seed;

	uint32_t c1 = UINT32_C(0xCC9E2D51);
	uint32_t c2 = UINT32_C(0x1B873593);

	//----------
	// body

	const uint32_t *blocks = (const uint32_t *)data;

	for(i = 0; i < nblocks; i++) {
		uint32_t k1 = getblock32(blocks, i);

		k1 *= c1;
		k1 = ROTL32(k1, 15);
		k1 *= c2;

		h1 ^= k1;
		h1 = ROTL32(h1, 13);
		h1 = h1 * 5 + UINT32_C(0xE6546B64);
	}

	//----------
	// tail

	const uint8_t *tail = (const uint8_t *)(data + nblocks * 4);

	uint32_t k1 = 0;

	switch(len & 3) {
		case 3: k1 ^= tail[2] << 16; // FALLTHROUGH
		case 2: k1 ^= tail[1] << 8; // FALLTHROUGH
		case 1: k1 ^= tail[0];
			k1 *= c1;
			k1 = ROTL32(k1, 15);
			k1 *= c2;
			h1 ^= k1;
	}

	//----------
	// finalization

	h1 ^= len;

	h1 = fmix32(h1);

	*(uint32_t *)out = h1;
}

//-----------------------------------------------------------------------------

void murmurhash3_x86_128(const void *key, const size_t len, uint32_t seed, void *out) {
	const uint8_t *data = (const uint8_t *)key;
	const size_t nblocks = len / 16;
	size_t i;

	uint32_t h1 = seed;
	uint32_t h2 = seed;
	uint32_t h3 = seed;
	uint32_t h4 = seed;

	uint32_t c1 = UINT32_C(0x239B961B);
	uint32_t c2 = UINT32_C(0xAB0E9789);
	uint32_t c3 = UINT32_C(0x38B34AE5);
	uint32_t c4 = UINT32_C(0xA1E38B93);

	//----------
	// body

	const uint32_t *blocks = (const uint32_t *)data;

	for(i = 0; i < nblocks; i++) {
		uint32_t k1 = getblock32(blocks, i * 4 + 0);
		uint32_t k2 = getblock32(blocks, i * 4 + 1);
		uint32_t k3 = getblock32(blocks, i * 4 + 2);
		uint32_t k4 = getblock32(blocks, i * 4 + 3);

		k1 *= c1;
		k1 = ROTL32(k1, 15);
		k1 *= c2;
		h1 ^= k1;

		h1 = ROTL32(h1, 19);
		h1 += h2;
		h1 = h1 * 5 + UINT32_C(0x561CCD1B);

		k2 *= c2;
		k2 = ROTL32(k2, 16);
		k2 *= c3;
		h2 ^= k2;

		h2 = ROTL32(h2, 17);
		h2 += h3;
		h2 = h2 * 5 + UINT32_C(0x0BCAA747);

		k3 *= c3;
		k3 = ROTL32(k3, 17);
		k3 *= c4;
		h3 ^= k3;

		h3 = ROTL32(h3, 15);
		h3 += h4;
		h3 = h3 * 5 + UINT32_C(0x96CD1C35);

		k4 *= c4;
		k4 = ROTL32(k4, 18);
		k4 *= c1;
		h4 ^= k4;

		h4 = ROTL32(h4, 13);
		h4 += h1;
		h4 = h4 * 5 + UINT32_C(0x32AC3B17);
	}

	//----------
	// tail

	const uint8_t *tail = (const uint8_t *)(data + nblocks * 16);

	uint32_t k1 = 0;
	uint32_t k2 = 0;
	uint32_t k3 = 0;
	uint32_t k4 = 0;

	switch(len & 15) {
		case 15: k4 ^= tail[14] << 16; // FALLTHROUGH
		case 14: k4 ^= tail[13] << 8; // FALLTHROUGH
		case 13: k4 ^= tail[12] << 0;
			k4 *= c4;
			k4 = ROTL32(k4, 18);
			k4 *= c1;
			h4 ^= k4;
			// FALLTHROUGH
		case 12: k3 ^= tail[11] << 24; // FALLTHROUGH
		case 11: k3 ^= tail[10] << 16; // FALLTHROUGH
		case 10: k3 ^= tail[9] << 8; // FALLTHROUGH
		case 9: k3 ^= tail[8] << 0;
			k3 *= c3;
			k3 = ROTL32(k3, 17);
			k3 *= c4;
			h3 ^= k3;
			// FALLTHROUGH
		case 8: k2 ^= tail[7] << 24; // FALLTHROUGH
		case 7: k2 ^= tail[6] << 16; // FALLTHROUGH
		case 6: k2 ^= tail[5] << 8; // FALLTHROUGH
		case 5: k2 ^= tail[4] << 0;
			k2 *= c2;
			k2 = ROTL32(k2, 16);
			k2 *= c3;
			h2 ^= k2;
			// FALLTHROUGH
		case 4: k1 ^= tail[3] << 24; // FALLTHROUGH
		case 3: k1 ^= tail[2] << 16; // FALLTHROUGH
		case 2: k1 ^= tail[1] << 8; // FALLTHROUGH
		case 1: k1 ^= tail[0] << 0;
			k1 *= c1;
			k1 = ROTL32(k1, 15);
			k1 *= c2;
			h1 ^= k1;
	}

	//----------
	// finalization

	h1 ^= len;
	h2 ^= len;
	h3 ^= len;
	h4 ^= len;

	h1 += h2;
	h1 += h3;
	h1 += h4;
	h2 += h1;
	h3 += h1;
	h4 += h1;

	h1 = fmix32(h1);
	h2 = fmix32(h2);
	h3 = fmix32(h3);
	h4 = fmix32(h4);

	h1 += h2;
	h1 += h3;
	h1 += h4;
	h2 += h1;
	h3 += h1;
	h4 += h1;

	((uint32_t *)out)[0] = h1;
	((uint32_t *)out)[1] = h2;
	((uint32_t *)out)[2] = h3;
	((uint32_t *)out)[3] = h4;
}

//-----------------------------------------------------------------------------

void murmurhash3_x64_128(const void *key, const size_t len, const uint32_t seed, void *out) {
	const uint8_t * data = (const uint8_t*)key;
	const size_t nblocks = len / 16;
	size_t i;

	uint64_t h1 = seed;
	uint64_t h2 = seed;

	uint64_t c1 = UINT64_C(0x87C37B91114253D5);
	uint64_t c2 = UINT64_C(0x4CF5AD432745937F);

	//----------
	// body

	const uint64_t *blocks = (const uint64_t *)data;

	for(i = 0; i < nblocks; i++) {
		uint64_t k1 = getblock64(blocks, i * 2 + 0);
		uint64_t k2 = getblock64(blocks, i * 2 + 1);

		k1 *= c1;
		k1 = ROTL64(k1, 31);
		k1 *= c2;
		h1 ^= k1;

		h1 = ROTL64(h1, 27);
		h1 += h2;
		h1 = h1 * 5 + UINT32_C(0x52DCE729);

		k2 *= c2;
		k2 = ROTL64(k2, 33);
		k2 *= c1;
		h2 ^= k2;

		h2 = ROTL64(h2, 31);
		h2 += h1;
		h2 = h2 * 5 + UINT32_C(0x38495AB5);
	}

	//----------
	// tail

	const uint8_t *tail = (const uint8_t*)(data + nblocks * 16);

	uint64_t k1 = 0;
	uint64_t k2 = 0;

	switch(len & 15) {
		case 15: k2 ^= (uint64_t)(tail[14]) << 48; // FALLTHROUGH
		case 14: k2 ^= (uint64_t)(tail[13]) << 40; // FALLTHROUGH
		case 13: k2 ^= (uint64_t)(tail[12]) << 32; // FALLTHROUGH
		case 12: k2 ^= (uint64_t)(tail[11]) << 24; // FALLTHROUGH
		case 11: k2 ^= (uint64_t)(tail[10]) << 16; // FALLTHROUGH
		case 10: k2 ^= (uint64_t)(tail[9]) << 8; // FALLTHROUGH
		case 9: k2 ^= (uint64_t)(tail[8]) << 0;
			k2 *= c2;
			k2 = ROTL64(k2, 33);
			k2 *= c1;
			h2 ^= k2;
			// FALLTHROUGH
		case 8: k1 ^= (uint64_t)(tail[7]) << 56; // FALLTHROUGH
		case 7: k1 ^= (uint64_t)(tail[6]) << 48; // FALLTHROUGH
		case 6: k1 ^= (uint64_t)(tail[5]) << 40; // FALLTHROUGH
		case 5: k1 ^= (uint64_t)(tail[4]) << 32; // FALLTHROUGH
		case 4: k1 ^= (uint64_t)(tail[3]) << 24; // FALLTHROUGH
		case 3: k1 ^= (uint64_t)(tail[2]) << 16; // FALLTHROUGH
		case 2: k1 ^= (uint64_t)(tail[1]) << 8; // FALLTHROUGH
		case 1: k1 ^= (uint64_t)(tail[0]) << 0;
			k1 *= c1;
			k1 = ROTL64(k1, 31);
			k1 *= c2;
			h1 ^= k1;
	}

	//----------
	// finalization

	h1 ^= len;
	h2 ^= len;

	h1 += h2;
	h2 += h1;

	h1 = fmix64(h1);
	h2 = fmix64(h2);

	h1 += h2;
	h2 += h1;

	((uint64_t*)out)[0] = h1;
	((uint64_t*)out)[1] = h2;
}
