#!/bin/bash

# "Historical interest only"
# -- a pleasingly primitive version of dumpallocs!

escape_eregexp () {
    # filter which reads a string on input, and yields a plain grep-style regexp
    # which matches the string literally, by escaping the metacharacters
    sed -r 's/(\*|\.|\[|\^|\$|\[|\]|\||\{|\}|\?|\+|\(|\)|\\)/\\\1/g'
}

escapefn_eregexp () {
    echo "$1" | escape_eregexp
}

# Build a list of allocation sites with the power of objdump.
# We record them as the string inside the < >
# i.e. <symname+0xoffset>, without the < >.
line_regexp='^[0-9a-f]* <([^>]*)>'
alloc_site_regexp="${line_regexp}.*"'call.*alloc'
allocation_sites="$( objdump --prefix-addresses -d "$1" | \
egrep "$alloc_site_regexp" | \
sed -r "s/${alloc_site_regexp}.*/\1/" )" #"

# read the whole objdump in, to avoid re-disassembling
objdump_output="$( objdump --prefix-addresses -dS "$1" )"

while read sym offset; do
    # Now use the power of objdump -S to get the source line for that alloc.
    # 1, Build a regexp that will re-locate the current alloc site.
    regexp="<$( escapefn_eregexp "$sym" )\+$( escapefn_eregexp "$offset")>"
    echo "regexp: $regexp" 1>&2
    # 2. Grab that and 200 lines of pre-context, 
    # which hopefully will include the allocating source line
    context="$( echo "$objdump_output" | egrep -B200 "$regexp" )" #"
    echo "context: $context" 1>&2
    # 3. Filter out non-source lines, and collapse to a single line
    source="$( echo "$context" | egrep -v "$line_regexp" | tr '\n' ' ' )" #"
    #echo "source: $source" 1>&2
    # 4. Get the first ident following the last occurrence of "new" or "sizeof"
    token="$( echo "$source" | egrep '(new|sizeof)([^0-9a-z_]|$)' | sed -r 's/.*(new|sizeof)([^0-9a-zA-Z_]|$)/\2/' | sed -r 's/[^0-9a-zA-Z_]*([a-zA-Z0-9_ \*]+).*/\1/' )" #"
    echo "token: $token" 1>&2
    # 5. Print the token and the site
    echo "Guessed that site <${sym}+${offset}> allocated: ${token}"
done <<<"$( echo "$allocation_sites" | sed -r 's/\+(0x[0-9a-f]*)$/ \1/' )" #"
