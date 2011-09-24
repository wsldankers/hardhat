#include "config.h"

#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include "reader.h"

int main(int argc, char **argv) {
	void *buf;
	hardhat_cursor_t *c, *cc;
	int i;

	if(argc < 3) {
		fprintf(stderr, "Usage: %s output.db path [path...]\n", argv[0]);
		exit(2);
	}

	buf = hardhat_open(argv[1]);
	if(!buf) {
		perror(argv[1]);
		exit(2);
	}

	for(i = 2; i < argc; i++) {
		c = hardhat_cursor(buf, argv[i], (uint16_t)strlen(argv[i]));
		if(c && c->data) {
			while(hardhat_fetch(c, true)) {
				cc = hardhat_cursor(buf, c->key, c->keylen);
				if(!cc || !cc->key) {
					printf("[");
					fwrite(c->key, 1, c->keylen, stdout);
					printf("] → [");
					fwrite(c->data, 1, c->datalen, stdout);
					printf("]\n");
				}
				hardhat_cursor_free(cc);
			}
		}
		hardhat_cursor_free(c);
	}

	return 0;
}
