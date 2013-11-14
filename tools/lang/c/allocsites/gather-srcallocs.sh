#!/bin/bash

pad_numbers () {
    tr '\n' '\f' | \
    sed 's/\f/\f\n/g' | \
    tr '\t' '\n' | \
    sed -r "s/^[[:space:]]*[0-9]+[[:space:]]*\$/printf '%06d' '&'/e" | \
    tr '\n' '\t' | \
    sed 's/\f\t/\n/g'
}

. ~/lib/bin/bash

all_obj_allocs_file="$1"

echo Hello 1>&2

cat "$all_obj_allocs_file" | cut -f1 | sort | uniq | while read obj rest; do
    echo "Saw line $obj $rest" 1>&2
    all_cus_info="$( readelf -wi "$obj" | grep -A7 'DW_TAG_compile_unit' | tr '\n' '\f' | sed 's/\f--\f/\n/g' )"
    echo "$all_cus_info" | while read cu_info; do
        cu_fname="$( echo "$cu_info" | tr '\f' '\n' | grep DW_AT_name | head -n1 | sed 's/.*DW_AT_name[[:blank:]]*:[[:blank:]]*(.*, offset: 0x[0-9a-f]*): \(.*\)/\1/' | sed 's/[[:blank:]]*$//')"
        echo "Note: found CU $cu_fname" 1>&2
        echo "CU info is: $cu_info" 1>&2
        echo "comp_dir line of CU info is $( echo "$cu_info" | tr '\f' '\n' | grep DW_AT_comp_dir )" 1>&2
        cu_compdir="$( echo "$cu_info" | tr '\f' '\n'  | grep DW_AT_comp_dir | sed 's/.*DW_AT_comp_dir[[:blank:]]*:[[:blank:]]*(.*, offset: 0x[0-9a-f]*): \(.*\)/\1/' | sed 's/[[:blank:]]*$//' )"
        echo "Note: found comp_dir $cu_compdir" 1>&2
        cu_sourcepath="${cu_compdir}/${cu_fname}"
        cu_allocspath="$( echo "$cu_sourcepath" | grep '\.cil\.c$' | sed 's/\.cil\.c/.i.allocs/' )"
        if [[ ! -r "$cu_allocspath" ]]; then
            echo "Warning: missing expected allocs file ($cu_allocspath) for source file: $cu_sourcepath" 1>&2
        else
            cat "$cu_allocspath"
        fi
    done
done | pad_numbers | sort -t$'\t' -k1 -k2 | uniq 
