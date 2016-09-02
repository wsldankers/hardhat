#pragma once

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
