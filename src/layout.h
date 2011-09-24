#ifndef HARDHAT_LAYOUT_H
#define HARDHAT_LAYOUT_H

#include <stdint.h>

#define HARDHAT_MAGIC "*HARDHAT"

struct hardhat_superblock {
	char magic[8];
	uint64_t byteorder;
	uint32_t version;
	uint32_t entries;
	uint32_t filesize;
	uint32_t data_start, data_end;
	uint32_t hash_start, hash_end;
	uint32_t directory_start, directory_end;
	char unused[4040];
	uint32_t checksum;
};

#endif
