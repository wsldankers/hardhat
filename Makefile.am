bin_PROGRAMS = hardhat mkhardhat
hardhat_SOURCES = src/hardhat.c
hardhat_LDADD = libhardhat.la libcommon.la -lrt
mkhardhat_SOURCES = src/mkhardhat.c
mkhardhat_LDADD = libhardhat.la -lrt

lib_LTLIBRARIES = libhardhat.la
libhardhat_la_SOURCES = src/hashtable.c src/hashtable.h src/layout.h src/maker.c src/maker.h src/reader.c src/reader.h
libhardhat_la_LDFLAGS = -Wl,--version-script,$(srcdir)/libhardhat.ver

hh_HEADERS = src/layout.h src/reader.h src/hashtable.h
hhdir = $(pkgincludedir)

EXTRA_DIST = makedist libhardhat.ver
AM_CFLAGS = -std=gnu99 -pipe -fvisibility=hidden -Wall -Wextra -Werror
