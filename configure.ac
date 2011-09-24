# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(hardhat, 1.0.0, wsl-hardhat-bugs@fruit.je)

AM_INIT_AUTOMAKE()
AC_CONFIG_HEADERS([src/config.h])
AC_CONFIG_SRCDIR([src/hardhat.c])
AC_CONFIG_FILES([Makefile])

AC_DEFINE([_GNU_SOURCE],1,[needed for some calls])
AC_DEFINE([_XOPEN_SOURCE],500,[needed for some calls])
AC_DEFINE([_FILE_OFFSET_BITS],64,[because gnu libc is retarded])

AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LIBTOOL

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([stdint.h inttypes.h stdlib.h unistd.h fcntl.h], , [
	AC_MSG_FAILURE([Required system header files not found.])
	exit 1
])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_CONST
AC_TYPE_SIZE_T
AC_FUNC_MMAP

AC_OUTPUT
