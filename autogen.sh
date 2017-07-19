#!/bin/sh
aclocal && \
autoconf && \
libtoolize --ltdl && \
autoheader && \
automake --add-missing && \
automake

# autoreconf --force --install -I config -I m4 && \
