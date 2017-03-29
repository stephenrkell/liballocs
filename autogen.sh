#!/bin/sh
aclocal && \
autoconf && \
libtoolize --ltdl && \
automake --add-missing && \
automake

# autoreconf --force --install -I config -I m4 && \
