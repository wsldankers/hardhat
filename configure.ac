AC_PREREQ(2.59)
AC_INIT(hardhat, 1.1.5, wsl-hardhat-bugs@fruit.je)
AM_INIT_AUTOMAKE([foreign subdir-objects dist-xz no-dist-gzip])

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/hardhat.c])
AC_CONFIG_HEADERS([src/config.h])

AC_DEFINE(_GNU_SOURCE, 1, [needed for some calls])
AC_DEFINE(_FILE_OFFSET_BITS, 64, [gnu libc has insane defaults])
AC_DEFINE(_XOPEN_SOURCE, 500, [needed for some calls])

# Checks for typedefs, structures, and compiler characteristics.
AC_PROG_CC
AC_PROG_CC_C99
AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_SYS_LARGEFILE

AC_HEADER_STDBOOL
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_FUNC_MALLOC
AC_FUNC_MMAP

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([stdint.h inttypes.h stdlib.h unistd.h fcntl.h], , [
	AC_MSG_FAILURE([Required system header files not found.])
	exit 1
])

AC_CHECK_LIB(rt, clock_gettime, [true], [
	AC_MSG_FAILURE([rt clock library not found.])
	exit 1
])

AC_CHECK_FUNCS([fpurge __fpurge])
AC_CHECK_HEADERS([stdio_ext.h])

AC_CHECK_FUNCS([qsort_r], [have_qsort_r=true], [have_qsort_r=false])
AM_CONDITIONAL([HAVE_QSORT_R], [$have_qsort_r])

MY_GCC_BUILTIN(bswap16, 0)
MY_GCC_BUILTIN(bswap32, 0)
MY_GCC_BUILTIN(bswap64, 0)

AX_APPEND_FLAG([-Wall -Werror -Wstrict-aliasing -include src/config.h])

AC_REQUIRE_AUX_FILE([tap-driver.sh])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
