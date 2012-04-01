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

typedef struct hardhat_cursor {
	const void *hardhat;
	const void *key;
	const void *data;
	uint32_t cur;
	uint32_t datalen;
	uint16_t keylen;
	uint16_t prefixlen;
	bool started;
	uint8_t prefix[1];
} hardhat_cursor_t;

extern void *hardhat_open(const char *filename);
extern void hardhat_precache(void *buf, bool data);
extern void hardhat_close(void *hardhat);
extern hardhat_cursor_t *hardhat_cursor(const void *hardhat, const void *prefix, uint16_t prefixlen);
extern bool hardhat_fetch(hardhat_cursor_t *c, bool recursive);
extern void hardhat_cursor_free(hardhat_cursor_t *c);

#endif
