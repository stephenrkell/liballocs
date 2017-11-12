#!/bin/sh
aclocal && \
autoconf && \
libtoolize --ltdl && \
(test -f libltdl/ltdl.mk || cd libltdl && ln -s Makefile.inc ltdl.mk) && \
autoheader && \
automake --add-missing && \
automake

# autoreconf --force --install -I config -I m4 && \
