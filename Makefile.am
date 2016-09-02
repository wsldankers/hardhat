bin_PROGRAMS = bin/hardhat bin/mkhardhat
bin_hardhat_SOURCES = src/hardhat.c
bin_hardhat_LDADD = lib/libhardhat.la
bin_mkhardhat_SOURCES = src/mkhardhat.c
bin_mkhardhat_LDADD = lib/libhardhat.la

noinst_PROGRAMS = tests/hardhat
tests_hardhat_SOURCES = tests/hardhat.c
tests_hardhat_LDADD = lib/libhardhat.la

LOG_DRIVER = AM_TAP_AWK='$(AWK)' $(top_srcdir)/tap-driver.sh
TESTS = tests/wrapper

lib_LTLIBRARIES = lib/libhardhat.la
lib_libhardhat_la_SOURCES = src/hashtable.c src/hashtable.h src/layout.h src/maker.c src/maker.h src/reader.c src/reader.h src/murmur3.c src/murmur3.h src/readerimpl.h
lib_libhardhat_la_LDFLAGS = -Wl,--version-script,$(srcdir)/libhardhat.ver
lib_libhardhat_la_LIBADD = -lrt

hh_HEADERS = src/layout.h src/reader.h src/hashtable.h src/maker.h
hhdir = $(pkgincludedir)

EXTRA_DIST = libhardhat.ver
AM_CFLAGS = -std=c99 -pipe -fvisibility=hidden -Wall -Wextra -Werror -Wno-missing-field-initializers
