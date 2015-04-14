#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([Evo Netflow Collector], [1.0], [evo@evo.nl])
AM_INIT_AUTOMAKE(pippo, 2.6)
AC_CONFIG_SRCDIR([EvoNetflow.h])
AC_PREFIX_DEFAULT(/opt/evonetflowcollector)

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_C_CONST
AC_LANG([C++])
CXXFLAGS='-Wall -std=c++11 -O2 -pthread'

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([sys/socket.h netinet/in.h string.h unistd.h stdio.h vector string sstream iostream signal.h thread mutex algorithm])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL

# Checks for library functions.
AC_CHECK_FUNCS([socket bind recvfrom memcpy strcmp])

AC_OUTPUT(Makefile)
