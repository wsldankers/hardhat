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

#ifndef HARDHAT_LAYOUT_H
#define HARDHAT_LAYOUT_H

#include <stdint.h>

/******************************************************************************

	Defines the hardhat superblock. Padded to 4096 bytes.

	The hardhat file format uses 4 major data sections. Each section is
	aligned to 4096 bytes.

	The first is the data itself, laid out as:
		data length (4 bytes)
		key length (2 bytes)
		key (up to 2^16 bytes)
		data (up to 2^32 bytes)
	The start of each entry is 4-byte aligned.

	The second is the directory, which is a list of offsets of all
	key/value pairs, sorted in the order defined in hardhat_cmp().
	These offsets are represented as 64-bit unsigned integers.

	The third is a hash table of all entries, with each entry an index
	into the directory.

	The fourth is a hash table of all prefixes, with each entry an index
	into the directory.

	The hash tables that are written to disk are a bastardized form of
	hash tables that is really a sorted list of the hash values. Lookup
	is done by doing a weighted binary search.

	Each entry in the hash table is a 32-bit unsigned integer hash value
	followed by a 32-bit unsigned integer offset into the directory.

	All integers are stored in the byte order indicated in the superblock.

******************************************************************************/

#define HARDHAT_MAGIC "*HARDHAT"

struct hardhat_superblock {
	/* Magic value to detect files of this type,
		should always be HARDHAT_MAGIC */
	char magic[8];
	/* Defines the byteorder of this database, should always be set to
		0x0123456789ABCDEF in the current byteorder */
	uint64_t byteorder;
	/* Database version */
	uint32_t version;
	/* Size of the database file, to detect truncated databases */
	uint64_t filesize;
	/* Start and end of the section containing the entries themselves */
	uint64_t data_start, data_end;
	/* Start and end of the hashtable for finding entries */
	uint64_t hash_start, hash_end;
	/* Start and end of the sorted list of entries */
	uint64_t directory_start, directory_end;
	/* Start and end of the hash of entry prefixes */
	uint64_t prefix_start, prefix_end;
	/* Number of entries stored */
	uint32_t entries;
	/* Number of prefixes stored */
	uint32_t prefixes;
	/* Seed for the hash function */
	uint32_t hashseed;
	/* Padding */
	char unused[3984];
	/* Checksum over the first 4092 bytes of the header, using the
		hashtable hash algorithm */
	uint32_t checksum;
};

#endif
