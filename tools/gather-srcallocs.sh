#!/bin/bash

pad_numbers () {
    tr '\n' '\f' | \
    sed 's/\f/\f\n/g' | \
    tr '\t' '\n' | \
    sed -r "s/^[[:space:]]*[0-9]+[[:space:]]*\$/printf '%06d' '&'/e" | \
    tr '\n' '\t' | \
    sed 's/\f\t/\n/g'
}

use_src_realpaths () {
    while IFS=$'\t' read -r alloc_sourcefile alloc_sourceline alloc_fun alloc_ciltype; do
	echo "Saw alloc_ciltype: $alloc_ciltype" 1>&2
        echo "$( readlink -f $alloc_sourcefile)"$'\t'"$alloc_sourceline"$'\t'"$alloc_fun"$'\t'"$alloc_ciltype"
    done
}

# for readelf_debug
. $(dirname $0)/../lib/debug-funcs.sh

all_obj_allocs_file="$1"

# echo Hello 1>&2

# Do a per-CU loop over the file and dispatch to a per-language allocs-gatherer

cat "$all_obj_allocs_file" | cut -f1 | sort | uniq | while read obj rest; do
    echo "Saw line $obj $rest" 1>&2
    all_cus_info="$( readelf_debug -wi "$obj" | grep -A7 'DW_TAG_compile_unit' | tr '\n' '\f' | sed 's/\f--\f/\n/g' )"
    
    echo "$all_cus_info" | while read cu_info; do
        if [[ -z "$cu_info" ]]; then
            continue
        fi
        cu_fname="$( echo "$cu_info" | tr '\f' '\n' | grep DW_AT_name | head -n1 | sed 's/.*DW_AT_name[[:blank:]]*:[[:blank:]]*(.*, offset: 0x[0-9a-f]*): \(.*\)/\1/' | sed 's/[[:blank:]]*$//')"
        cu_language_fullstr="$( echo "$cu_info" | tr '\f' '\n' | grep DW_AT_language | head -n1 | sed 's/.*DW_AT_language[[:blank:]]*:[[:blank:]]*//' | sed 's/[[:blank:]]*$//')"
        echo "Note: found CU $cu_fname" 1>&2
        echo "CU info is: $cu_info" 1>&2
        echo "language field of CU info is $( echo "$cu_language_fullstr" )" 1>&2
        echo "comp_dir line of CU info is $( echo "$cu_info" | tr '\f' '\n' | grep DW_AT_comp_dir )" 1>&2
        cu_compdir="$( echo "$cu_info" | tr '\f' '\n'  | grep DW_AT_comp_dir | sed 's/.*DW_AT_comp_dir[[:blank:]]*:[[:blank:]]*(.*, offset: 0x[0-9a-f]*): \(.*\)/\1/' | sed 's/[[:blank:]]*$//' )"
        echo "Note: found comp_dir $cu_compdir" 1>&2
        # don't prepend compdir if cu_fname is fully-qualified
        case "$cu_fname" in
            (/*)
                cu_sourcepath="${cu_fname}"
                ;;
            (*)
                cu_sourcepath="${cu_compdir}/${cu_fname}"
                ;;
        esac
        cu_language_num="$( echo "$cu_language_fullstr" | tr -s '[[:blank:]]' '\t' | cut -f1 )"
        case "$cu_language_num" in
            (1|2) # DW_LANG_C89, DW_LANG_C
                $(dirname "$0")/lang/c/bin/c-gather-srcallocs "$cu_sourcepath" "$obj" "$cu_fname" "$cu_compdir"
            ;;
            (*) # unknown
                echo "Warning: could not gather source-level allocs for unknown language: $cu_language_fullstr ($cu_language_num, $( echo -n "$cu_language_fullstr" | hd ))" 1>&2
            ;;
        esac
    done
done | pad_numbers | use_src_realpaths | sort -t$'\t' -k1 -k2 | uniq 
