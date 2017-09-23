#!/bin/bash

# turn tab-separated lines into one line per field, with \f for original newlines
fields_as_lines () {
    tr '\n' '\f' | \
    sed 's/\f/\f\n/g' | \
    tr '\t' '\n'
    # now a line break is \f\n and a field break is \n
}

recover_lines () {
    tr '\n' '\t' | \
     sed 's/\f\t/\n/g'
}

pad_numbers () {
    # be careful not to swallow a trailing \f
    fields_as_lines | \
    sed -r "s/^([[:space:]]*[0-9]+[[:space:]]*)(\\f|\$)/printf '%06d' '\\1'; printf '\\2'/e" | \
    recover_lines
    # this gawk replacement doesn't work
    #gawk '/^[[:space:]]*[0-9]+[[:space:]]*$/ { printf "%06d%s\n", $0, gensub(/.*[^[:space:]]*([[:space:]]*)$/, "\\1", ""); next }; /.*/ { printf "%s", $0; }' | \
}

use_src_realpaths () {
    while IFS=$'\t' read -r alloc_sourcefile alloc_sourceline alloc_fun alloc_rest; do
    echo "Saw alloc_rest: $alloc_rest" 1>&2
        echo "$( readlink -f $alloc_sourcefile)"$'\t'"$alloc_sourceline"$'\t'"$alloc_fun"$'\t'"$alloc_rest"
    done
}

# for readelf_debug
. $(dirname $0)/debug-funcs.sh

our_name="$(basename "$0")"
our_name_rewritten="$( echo "$our_name" | sed 's/gather-\(.*\)\.sh/gather-\1/' )"

all_obj_allocs_file="$1"

# echo Hello 1>&2

# Do a per-CU loop over the file and dispatch to a per-language allocs-gatherer

cat "$all_obj_allocs_file" | cut -f1 | sort | uniq | while read obj rest; do
    echo "Saw line $obj $rest" 1>&2
    all_cus_info="$( get_cu_info "$obj" )"
    
    echo "$all_cus_info" | while read_cu_info; do
        case "$cu_language_num" in
            (1|2|12) # DW_LANG_C89, DW_LANG_C, DW_LANG_C99
                $(dirname "$0")/lang/c/bin/c-"$our_name_rewritten" "$cu_sourcepath" "$obj" "$cu_fname" "$cu_compdir"
            ;;
            (*) # unknown
                echo "Warning: could not gather source-level allocs for unknown language: $cu_language_fullstr ($cu_language_num, $( echo -n "$cu_language_fullstr" | hd ))" 1>&2
            ;;
        esac
    done
done | pad_numbers | sort -t$'\t' -k1 -k2 | uniq        #use_src_realpaths | 
