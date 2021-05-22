#include <stdio.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "src/reader.h"
#include "src/maker.h"
#include "tests/tap.h"

const char hex[] = "0123456789abcdef";

int main(void) {
	char *filename;
	const char *tmpdir;
	hardhat_t *hh;
	hardhat_cursor_t *hhc;
	hardhat_maker_t *hhm;
	unsigned int u;
	size_t z;
	char key[32], data[32];

	tmpdir = getenv("TMPDIR");
	if(!tmpdir) bail("no $TMPDIR set");

	filename = malloc(strlen(tmpdir) + 20);
	if(!filename) bail("no memory");

	sprintf(filename, "%s/test.hh", tmpdir);
	hhm = hardhat_maker_new(filename);
	if(!tap(hhm, NULL, "create a hardhat_maker"))
		bail("no hardhat_maker object: %m");

	for(u = 0; u < 10; u++) {
		sprintf(key, "%u", u);
		sprintf(data, "%x", u);
		tap(hardhat_maker_add(hhm, key, strlen(key), data, strlen(data)), NULL, "add an entry");
	}

	if(!tap(hardhat_maker_finish(hhm), NULL, "close the hardhat_maker"))
		printf("# %s\n", hardhat_maker_error(hhm));

	hardhat_maker_free(hhm);

	hh = hardhat_open(filename);
	free(filename);
	tap(hh, NULL, "open the hardhat for reading");

	if(hh) {
		for(u = 0; u < 10; u++) {
			sprintf(key, "%u", u);
			sprintf(data, "%x", u);
			hhc = hardhat_cursor(hh, key, strlen(key));
			tap(hhc, NULL, "get a cursor");
			tap(hhc->data, NULL, "find an entry");
			if(hhc->data) {
				tap(hhc->datalen == strlen(data) && !memcmp(data, hhc->data, hhc->datalen), NULL, "entry has the right value");
				printf("%s: ", data);
				for(z = 0; z < hhc->datalen; z++) {
					putchar(hex[((unsigned char *)hhc->data)[z] >> 4]);
					putchar(hex[((unsigned char *)hhc->data)[z] & 15]);
				}
				putchar('\n');
			}
			hardhat_cursor_free(hhc);
		}
	}

	printf("1..%u\n", testcounter);

	hardhat_close(hh);

	return 0;
}
