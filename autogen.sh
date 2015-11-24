#!/bin/sh
aclocal && \
autoconf && \
automake --add-missing && \
automake && \
libtoolize

# autoreconf --force --install -I config -I m4 && \
