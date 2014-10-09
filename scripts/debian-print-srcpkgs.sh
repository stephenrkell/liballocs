#!/bin/sh

ldd "$1" | grep ' => ' | grep -v ld-linux | \
sed 's/.* =>[[:blank:]]*//' | sed 's/ *(0x.*//' | sed '/^$/ d' | while read lib; do
    dpkg -S "$lib" | sed 's/: .*//'
done | sort | uniq
