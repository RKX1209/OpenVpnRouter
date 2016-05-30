#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([vrouter], [1.0])
AM_INIT_AUTOMAKE([foreign])
AC_CONFIG_SRCDIR([router.c])
AC_CONFIG_HEADERS([include/config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h string.h sys/ioctl.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.
AC_CHECK_FUNCS([inet_ntoa memset socket strerror])

AC_CONFIG_FILES([
Makefile
protocol/Makefile])

AC_OUTPUT
