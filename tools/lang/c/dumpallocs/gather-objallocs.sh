#!/bin/bash

pad_numbers () {
    tr '\n' '\f' | \
    sed 's/\f/\f\n/g' | \
    tr '\t' '\n' | \
    sed -r "s/^[[:space:]]*[0-9]+[[:space:]]*\$/printf '%06d' '&'/e" | \
    tr '\n' '\t' | \
    sed 's/\f\t/\n/g'
}

pad_numbers | sort -t$'\t' -k4 -k5 #> "$all_obj_allocs_file"
