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

#ifndef HARDHAT_MAKER_H
#define HARDHAT_MAKER_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct hardhat_maker hardhat_maker_t;

/* Retrieve the last error that occurred in the context of
   this hardhat_maker_t structure.
   Always returns a valid string, though it may be empty
   if there's no error to report.
   Do not attempt to free() the string. */
extern const char *hardhat_maker_error(hardhat_maker_t *hhm);

/* Returns true iff the creation of the database failed in a
   way that can't be recovered from */
extern bool hardhat_maker_fatal(hardhat_maker_t *hhm);

/* Allocate and initialize a new hardhat_maker_t control structure.
   Returns NULL (and sets errno) on error. */
extern hardhat_maker_t *hardhat_maker_new(const char *filename);
extern hardhat_maker_t *hardhat_maker_newat(int dirfd, const char *filename, int mode);

/* Configure the alignment to use for this database.
   The value determines how stored values are aligned.
   Returns the previous alignment value or 0 on error.
   Must be powers of 2.
   Supply a value of 0 to query the current alignment.
   Supply a value 1 to disable alignment. */
extern uint64_t hardhat_maker_alignment(hardhat_maker_t *hhm, uint64_t alignment);
#define HAVE_HARDHAT_MAKER_ALIGNMENT

/* Configure the block size for this database. The value determines the
   size of the block boundaries to avoid when writing out keys and indexes.
   Returns the previous block size or 0 on error.
   Must be a power of 2.
   Supply a value of 0 to query the current block size.
   Supply a value 1 to disable block size optimizations. */
extern uint64_t hardhat_maker_blocksize(hardhat_maker_t *hhm, uint64_t blocksize);
#define HAVE_HARDHAT_MAKER_BLOCKSIZE

/* Add an entry. Will silently ignore attempts to add duplicate keys
   (and even return true). Returns false on error. */
extern bool hardhat_maker_add(hardhat_maker_t *hhm, const void *key, uint16_t keylen, const void *data, uint32_t datalen);

/* Fills in missing parent nodes. For example, if you add the following keys:

	foo
	foo/bar/baz

   Then doing a shallow listing on ‘foo’ would turn up 0 results. This
   function would add ‘foo/bar’ (with the indicated data) so that shallow
   listings function properly. This function will not add a root node (the
   empty string). Returns false on error. */
extern bool hardhat_maker_parents(hardhat_maker_t *hhm, const void *data, uint32_t datalen);

/* Create the indexes, write and flush everything to disk. Returns false on
   error. After calling this function, no entries can be added. */
extern bool hardhat_maker_finish(hardhat_maker_t *hhm);

/* Free the hardhat_maker_t control structure and any associated data. */
extern void hardhat_maker_free(hardhat_maker_t *hhm);

/* Utility function: normalize a path according to hardhat's rules.
   Returns the size of the result string. The destination buffer should
   be at least as large as the source buffer. In place conversions are
   supported (simply pass the same pointer for src and dst. */
extern size_t hardhat_normalize(void *dst, const void *src, size_t size);

/* Utility function: compare two paths according to hardhat's rules. */
extern int hardhat_cmp(const void *a, size_t al, const void *b, size_t bl);

#endif
