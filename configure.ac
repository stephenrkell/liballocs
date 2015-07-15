AC_CONFIG_MACRO_DIR([m4])
AC_PREREQ([2.69])
AC_INIT([liballocs], [0.1], [srk31@cl.cam.ac.uk])
AC_CONFIG_SRCDIR([tools/ifacetypes.cpp])

CFLAGS="-I$prefix/include $CFLAGS"
CXXFLAGS="-I$prefix/include $CXXFLAGS"
CPPFLAGS="-I$prefix/include $CPPFLAGS"
LDFLAGS="-L$prefix/lib $LDFLAGS"
PKG_CONFIG_PATH="$prefix/lib/pkgconfig:$PKG_CONFIG_PATH"
export CFLAGS CXXFLAGS LDFLAGS PKG_CONFIG_PATH

LT_INIT
AC_LANG([C++])
AM_INIT_AUTOMAKE([foreign subdir-objects -Wno-portability])
AM_MAINTAINER_MODE
AC_PROG_CXX

AX_CXX_COMPILE_STDCXX_11
export CXXFLAGS

AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_SIZE_T
AC_CHECK_TYPES([ptrdiff_t])
AC_PROG_LN_S
AC_PROG_INSTALL

OLD_CPPFLAGS=$CPPFLAGS
CPPFLAGS="-std=c++11 $CPPFLAGS"

AC_CHECK_HEADERS([alloca.h assert.h cassert cctype cmath cstddef cstdint cstdio cstdlib deque dlfcn.h elf.h err.h errno.h fstream iomanip iostream libunwind.h link.h map memory pthread.h search.h set sstream stdarg.h stdbool.h stddef.h stdint.h stdio.h stdlib.h string string.h strings.h sys/mman.h sys/resource.h sys/stat.h sys/syscall.h sys/time.h sys/types.h unistd.h vector wchar.h], [], [AC_MSG_FAILURE([required standard headers: alloca.h assert.h cassert cctype cmath cstddef cstdint cstdio cstdlib deque dlfcn.h elf.h err.h errno.h fstream iomanip iostream libunwind.h link.h map memory pthread.h search.h set sstream stdarg.h stdbool.h stddef.h stdint.h stdio.h stdlib.h string string.h strings.h sys/mman.h sys/resource.h sys/stat.h sys/syscall.h sys/time.h sys/types.h unistd.h vector wchar.h])])

AX_BOOST_BASE

AC_CHECK_HEADER([boost/regex/concepts.hpp], [], [AC_MSG_FAILURE([boost::regex is required])])
AC_HAVE_LIBRARY(boost_regex, [], [AC_MSG_FAILURE([boost::regex is required])])

CPPFLAGS=$OLD_CPPFLAGS

PKG_PROG_PKG_CONFIG
PKG_CHECK_MODULES([LIBCXXFILENO], [libcxxfileno])
PKG_CHECK_MODULES([LIBSRK31CXX], [libsrk31cxx])
PKG_CHECK_MODULES([LIBDWARFPP], [libdwarfpp])
PKG_CHECK_MODULES([LIBCXXGEN], [libcxxgen])
PKG_CHECK_MODULES([DWARFIDL], [dwarfidl])

AC_ARG_ENABLE([debug], AS_HELP_STRING([--enable-debug], [Enable debug mode]))
AC_ARG_ENABLE([real-libunwind], AS_HELP_STRING([--enable-real-libunwind], [Use real libunwind (by default we have our own)]))

AM_CONDITIONAL(DEBUG, [test "x$enable_debug" = "xyes"])
AM_CONDITIONAL(USE_REAL_LIBUNWIND, [test "x$enable_real-libunwind" = "xyes"])

AC_CONFIG_FILES([Makefile footprints/Makefile liballocs.pc])
AC_OUTPUT
