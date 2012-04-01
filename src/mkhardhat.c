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
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#include "layout.h"
#include "maker.h"

/******************************************************************************

	Simple tool that creates and fills a hardhat database with the contents
	of one or more files in cdb format. cdb format is zero or more lines in
	the following format:

		+[key length],[value length]:[key]->[value]

	(The square brackets are not part of the format.) For example:

		+4,5:quux->xyzzy

	Line breaks must be a single \n. The file must end with an empty line
	(i.e., an extra \n). The keys and values are binary safe.

******************************************************************************/

static bool errors = false;

/* Read a single byte and check for errors */
static int readchar(FILE *fh, const char *name) {
	int c;
	c = fgetc(fh);
	if(c == EOF) {
		if(ferror(fh))
			perror(name);
		else if(feof(fh))
			fprintf(stderr, "%s: Unexpected end of file\n", name);
		else
			fprintf(stderr, "%s: Unexpected error\n", name);
		errors = true;
	}
	return c;
}

/* Read multiple bytes and check for errors */
static bool readchars(FILE *fh, const char *name, void *buf, size_t num) {
	size_t r;
	r = fread(buf, 1, num, fh);
	if(r < num) {
		if(ferror(fh))
			perror(name);
		else if(feof(fh))
			fprintf(stderr, "%s: Unexpected end of file\n", name);
		else
			fprintf(stderr, "%s: Unexpected error\n", name);
		errors = true;
		return false;
	}
	return true;
}

/* Skip a byte (but check if it's the right value) and check for errors */
static bool skipchar(FILE *fh, const char *name, int expect) {
	int c;

	c = readchar(fh, name);
	if(c == EOF)
		return false;
	if(c == expect)
		return true;

	fprintf(stderr, "%s: Unexpected character in input\n", name);
	errors = true;
	return false;
}

/* Read a number in ascii format from the input and check for errors */
static uint64_t readnumber(FILE *fh, const char *name, int end) {
	uint64_t n = 0;
	int c;
	bool first = true;

	for(;;) {
		c = readchar(fh, name);
		if(c == EOF)
			return UINT64_MAX;
		if(c == end)
			return first ? UINT64_MAX : n;
		if(c < '0' || c > '9') {
			fprintf(stderr, "%s: Unexpected character in input\n", name);
			errors = true;
			return UINT64_MAX;
		}
		if(c == '0' && !n && !first) {
			fprintf(stderr, "%s: Unexpected character in input\n", name);
			errors = true;
			return UINT64_MAX;
		}
		n = UINT64_C(10) * n + (uint64_t)(c - '0');
		if(n > INT32_MAX) {
			fprintf(stderr, "%s: Invalid field size\n", name);
			errors = true;
			return UINT64_MAX;
		}
		first = false;
	}
	return n;
}

int main(int argc, char **argv) {
	int i, c;
	FILE *fh;
	hardhat_maker_t *hhm;
	char *keybuf, *databuf;
	size_t databufsize = 1048576;
	uint64_t keysize, datasize;
	uint32_t line;

	if(argc < 3) {
		fprintf(stderr, "Usage: %s output.db input.txt [input...]\n", argv[0]);
		exit(2);
	}

	hhm = hardhat_maker_new(argv[1]);
	if(!hhm) {
		perror(argv[1]);
		exit(2);
	}

	keybuf = malloc(65536);
	if(!keybuf) {
		perror("malloc()");
		exit(2);
	}

	databuf = malloc(databufsize);
	if(!databuf) {
		perror("malloc()");
		exit(2);
	}

	for(i = 2; i < argc; i++) {
		fh = fopen(argv[i], "r");
		if(!fh) {
			perror(argv[i]);
			errors = true;
			continue;
		}

		line = 0;

		for(;;) {
			line++;

			c = readchar(fh, argv[i]);
			if(c == EOF || c == '\n') {
				break;
			} else if(c != '+') {
				fprintf(stderr, "%s: Unexpected character in input\n", argv[i]);
				errors = true;
				break;
			}
			keysize = readnumber(fh, argv[i], ',');
			if(keysize == UINT64_MAX)
				break;
			if(keysize > UINT16_MAX) {
				fprintf(stderr, "%s: Key too large (%"PRIu64" > %"PRIu16")\n", argv[i], keysize, UINT16_MAX);
				errors = true;
				break;
			}
			datasize = readnumber(fh, argv[i], ':');
			if(datasize == UINT64_MAX)
				break;
			if(datasize > INT32_MAX) {
				fprintf(stderr, "%s: Data too large (%"PRIu64" > %"PRId32")\n", argv[i], datasize, INT32_MAX);
				errors = true;
				break;
			}
			if(datasize > databufsize) {
				databufsize = datasize + 1048576;
				free(databuf);
				databuf = malloc(databufsize);
				if(!databuf) {
					perror("malloc()");
					exit(2);
				}
			}
			if(!readchars(fh, argv[i], keybuf, keysize))
				break;
			if(!skipchar(fh, argv[i], '-') || !skipchar(fh, argv[i], '>'))
				break;
			if(!readchars(fh, argv[i], databuf, datasize))
				break;
			if(!skipchar(fh, argv[i], '\n'))
				break;

			if(!hardhat_maker_add(hhm, keybuf, (uint16_t)keysize, databuf, (uint32_t)datasize)) {
				fprintf(stderr, "%s:%"PRIu32": %s\n", argv[i], line, hardhat_maker_error(hhm));
				if(hardhat_maker_fatal(hhm))
					exit(2);
				errors = true;
			}
		}
		fclose(fh);
	}

	if(!hardhat_maker_parents(hhm, "", 0) || !hardhat_maker_finish(hhm)) {
		fprintf(stderr, "%s\n", hardhat_maker_error(hhm));
		if(hardhat_maker_fatal(hhm))
			exit(2);
		errors = true;
	}

	hardhat_maker_free(hhm);

	return errors;
}
