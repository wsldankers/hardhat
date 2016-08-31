#include <stdio.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "src/reader.h"
#include "src/maker.h"

#define TODO "TODO"
#define SKIP "SKIP"

static unsigned int testcounter;

static bool tap(bool test, const char *modifier, const char *fmt, ...) {
	va_list ap;
	printf("%s %u", test ? "ok" : "not ok", ++testcounter);
	if(fmt) {
		printf(" - ");
		va_start(ap, fmt);
		vprintf(fmt, ap);
		va_end(ap);
	}
	if(modifier)
		printf(" # %s", modifier);
	putchar('\n');
	fflush(stdout);
	return test;
}

static void bail(const char *fmt, ...) {
	va_list ap;
	printf("Bailing out!");
	if(fmt) {
		printf(" ");
		va_start(ap, fmt);
		vprintf(fmt, ap);
		va_end(ap);
	}
	putchar('\n');
	fflush(stdout);
	abort();
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
	if(!tap(hhm, NULL, "create a hardhat_maker"))
		bail("no hardhat_maker object");

	tap(hardhat_maker_add(hhm, "foo", 3, "data", 4), NULL, "add an entry");

	if(!tap(hardhat_maker_finish(hhm), NULL, "close the hardhat_maker"))
		printf("# %s\n", hardhat_maker_error(hhm));

	hardhat_maker_free(hhm);

	tap(hardhat_open(filename), NULL, "open the hardhat for reading");

	printf("1..%u\n", testcounter);
	return 0;
}
