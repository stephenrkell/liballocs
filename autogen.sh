#!/bin/sh
aclocal && \
autoconf && \
libtoolize --force --ltdl && \
(test -f libltdl/ltdl.mk || (cd libltdl && ln -sf Makefile.inc ltdl.mk)) && \
autoheader && \
automake --add-missing && \
automake

# autoreconf --force --install -I config -I m4 && \
