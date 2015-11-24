# Process this file with autoconf to produce a configure script.

AC_INIT(hardhat, 1.1.4, wsl-hardhat-bugs@fruit.je)
AM_INIT_AUTOMAKE([foreign subdir-objects dist-xz no-dist-gzip])

AC_CONFIG_SRCDIR([src/hardhat.c])
AC_CONFIG_HEADERS([src/config.h])

AC_DEFINE([_GNU_SOURCE], 1, [needed for some calls])
AC_DEFINE([_XOPEN_SOURCE], 500, [needed for some calls])

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

AC_CHECK_FUNCS([fpurge __fpurge fileno], [break])
AC_CHECK_HEADERS([stdio_ext.h])

AC_DEFUN([MY_GCC_BUILTIN], [
	AS_VAR_PUSHDEF([ac_var], [ax_cv_have_builtin_$1])

	AC_CACHE_CHECK([for __builtin_$1], [ac_var], [
		AC_LINK_IFELSE([AC_LANG_PROGRAM([], [__builtin_$1($2)])], 
			[AS_VAR_SET([ac_var], [yes])], [AS_VAR_SET([ac_var], [no])])
	])

	case AS_VAR_GET([ac_var]) in yes)
		AC_DEFINE_UNQUOTED(AS_TR_CPP(HAVE_BUILTIN_$1), 1, [has GCC __builtin_$1 function])
	esac

	AS_VAR_POPDEF([ac_var])
])

MY_GCC_BUILTIN(bswap16, 0)
MY_GCC_BUILTIN(bswap32, 0)
MY_GCC_BUILTIN(bswap64, 0)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
