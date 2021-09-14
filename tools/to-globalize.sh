#!/bin/bash

obj="$1"
shift

for sym in "$@"; do
   eregexp="${eregexp:+${eregexp}|}"${sym}
done
nm -fposix "$obj" | egrep "^(${eregexp}) t " | sed 's/[[:blank:]].*//'
