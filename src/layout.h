#ifndef HARDHAT_LAYOUT_H
#define HARDHAT_LAYOUT_H

#include <stdint.h>

#define HARDHAT_MAGIC "*HARDHAT"

struct hardhat_superblock {
	char magic[8];
	uint64_t byteorder;
	uint32_t version;
	uint64_t filesize;
	uint64_t data_start, data_end;
	uint64_t hash_start, hash_end;
	uint64_t directory_start, directory_end;
	uint64_t prefix_start, prefix_end;
	uint32_t entries;
	uint32_t prefixes;
	char unused[3988];
	uint32_t checksum;
};

#endif
