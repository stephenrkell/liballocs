#!/bin/sh
aclocal && \
autoconf && \
libtoolize && \
automake --add-missing && \
automake

# autoreconf --force --install -I config -I m4 && \
