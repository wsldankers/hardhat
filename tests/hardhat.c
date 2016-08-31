#include <stdio.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "src/reader.h"
#include "src/maker.h"

static unsigned int testcounter;

static void tap(bool test, const char *description) {
	testcounter++;
	printf("%s %u - %s\n", test ? "ok" : "not ok", testcounter, description);
}

static void bail(const char *description) {
	printf("Bailing out! %s\n", description);
	exit(1);
}

int main(void) {
	char *filename;
	const char *tmpdir;
	hardhat_maker_t *hhm;

	tmpdir = getenv("TMPDIR");
	if(!tmpdir) bail("no $TMPDIR set");

	filename = malloc(strlen(tmpdir) + 20);
	if(!filename) bail("no memory");

	sprintf(filename, "%s/test.hh", tmpdir);
	hhm = hardhat_maker_new(filename);
	if(!hhm) bail("no hardhat_maker object");

	tap(true, "able to create a hardhat_maker");

	tap(hardhat_maker_finish(hhm), "close the hardhat_maker # TODO");

	hardhat_maker_free(hhm);

	printf("1..%u\n", testcounter);
	return 0;
}
