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

#include "config.h"

#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include "reader.h"

/* test program to exercise a hardhat database */

int main(int argc, char **argv) {
	void *buf;
	hardhat_cursor_t *c, *cc;
	int i;

	if(argc < 3) {
		fprintf(stderr, "Usage: %s input.db path [path...]\n", argv[0]);
		exit(2);
	}

	buf = hardhat_open(argv[1]);
	if(!buf) {
		perror(argv[1]);
		exit(2);
	}
	hardhat_precache(buf, true);

	for(i = 2; i < argc; i++) {
		c = hardhat_cursor(buf, argv[i], (uint16_t)strlen(argv[i]));
		if(c) {
			/* loop over all entries and print the ones that cannot
			** be found by hash lookup (should be zero) */
			do {
				if(!c->key)
					continue;
				cc = hardhat_cursor(buf, c->key, c->keylen);
				if(!cc || !cc->key) {
					printf("[");
					fwrite(c->key, 1, c->keylen, stdout);
					printf("] → [");
					fwrite(c->data, 1, c->datalen, stdout);
					printf("]\n");
				}
				if(cc)
					hardhat_fetch(cc, true);
				hardhat_cursor_free(cc);
			} while(hardhat_fetch(c, true));
		}
		hardhat_cursor_free(c);
	}

	return 0;
}
