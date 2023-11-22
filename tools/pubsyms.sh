#!/bin/bash

# We use this tool to dump the ABI of liballocs_preload.a
# and it provides a symbol list as input to 'noopgen' for generating
# the noop version of each public symbol. That gets linked into the
# _preload.so.

READELF=${READELF:-readelf}
file=$1

# First check whether we have a dynsym.
grep '^[[:blank:]]*\[[[:blank:]0-9]\+\][[:blank:]]\+\.dynsym' >/dev/null 2>&1 <<<"$( "$READELF" -WS "$file" )"
has_dynsym=$?

do_readelf () {
    if [[ $has_dynsym -eq 0 ]]; then
        ${READELF} -D "$@"
    else
        ${READELF} "$@"
    fi
}
# Here we dump symbols that are FUNC, GLOBAL and not HIDDEN
do_readelf -Ws "$file" | sed 's/^[[:blank:]]*//' | tr -s '[:blank:]' '\t' | \
       sed '/^[[:blank:]]*$/ d' | egrep '^File|^[0-9]+' | \
       awk 'BEGIN { pat="^File:[[:blank:]]*"; file=""; } $0 ~ pat { file=gensub(pat, "", 1); next; } { print file "\t" $0; }' | \
       grep 'FUNC[[:blank:]]GLOBAL[[:blank:]][^H]' | cut -f1,3,5,6,7,9 | sort -k6
