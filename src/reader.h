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

#ifndef HARDHAT_READER_H
#define HARDHAT_READER_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

/* Opaque structure for open hardhat databases */
typedef const struct hardhat hardhat_t;

/* Cursor for lookups. All fields are read-only, some are private.
   This structure represents a single entry in the database, but
   also contains enough information about the query that found it
   to act as an iterator. See hardhat_cursor() and hardhat_fetch().
   Private values are subject to change without notice. */
typedef struct hardhat_cursor {
	/* Pointer to hardhat handle. Private! */
	hardhat_t *hardhat;
	/* Pointer to key value, not \0 terminated. */
	const void *key;
	/* Pointer to data value, not \0 terminated. */
	const void *data;
	/* Unique identifier for each key/value pair. Only valid if
	   key/value are. */
	uint32_t cur;
	/* Length of current data */
	uint32_t datalen;
	/* Length of current data */
	uint16_t keylen;
	/* Length of the prefix passwd to hardhat_cursor(). Private! */
	uint16_t prefixlen;
	/* Whether the first entry has been returned. Private! */
	bool started;
	/* Inline buffer containing the prefix. Private!
	  Extends past the end of the structure. */
	uint8_t prefix[1];
} hardhat_cursor_t;

/* Open a hardhat database for querying. Returns NULL (and sets errno)
   on failure. EPROTO means that the database is invalid, corrupted or
   otherwise unusable. */
extern hardhat_t *hardhat_open(const char *filename);

/* Fill the buffer cache so that subsequent accesses are not limited by
   rotational storage seektimes. May block. */
extern void hardhat_precache(hardhat_t *, bool data);

/* Close the hardhat database. */
extern void hardhat_close(hardhat_t *hardhat);

/* Search for an entry. If an error occurs, NULL is returned and errno set.
   Otherwise a hardhat_cursor_t structure is returned, with the key, data,
   keylen, and datalen values set.
   If the entry was not found, the key and data fields are NULL. */
extern hardhat_cursor_t *hardhat_cursor(hardhat_t *, const void *prefix, uint16_t prefixlen);

/* Return the next entry for a cursor. This will return only entries that
   have names strictly underneath the searched path. If recursive is false,
   only direct descendents will be returned. Returns false (and sets key
   and data to NULL) if no more entries could be found.
   Example usage for a shallow listing of the foo directory:

	hardhat_cursor_t *c = hardhat_cursor(hh, "foo", 3);
	while(hardhat_fetch(c, false)) {
		fwrite(c->key, 1, c->keylen, stdout);
		putchar('\n');
	}

   Works even the parent node itself was not found. */
extern bool hardhat_fetch(hardhat_cursor_t *c, bool recursive);

/* Frees the cursor and associated storage */
extern void hardhat_cursor_free(hardhat_cursor_t *c);

#endif
