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
our_name_frag="$( echo "$our_name" | sed -n '/gather-src\(.*\)\.sh/ {s//\1/;p}' )"
if [[ -z "$our_name_frag" ]]; then echo "Did not understand our name ($0)"; exit 1; fi
our_name_rewritten=gather-src${our_name_frag}

all_obj_allocs_file="$1"

echo Hello 1>&2

rewrite_relative_src_filenames () {
    while read fname rest; do
        # if the filename is relative, it's relative to the compilation directory.
        # prepend the full path *as the compiler saw it*, i.e. cu_compdir.
        case "$fname" in
            ('/'*)
                echo "$fname"$'\t'"$rest"
                ;;
            (*)
                # HACK: just pick up cu_compdir from the environment
                echo "$cu_compdir"/"$fname"$'\t'"$rest"
                ;;
        esac
    done
}

# For each linked binary file (probably just one!), do a per-CU loop
# where we iterate over CUs and dispatch to a per-language allocs-gatherer.
# HOWEVER, the linked binary may contain a .allocs_srcallocs section...
# if it does, we slurp that. Since we sort and uniq our output, it does not
# hurt if there are duplicates between these sources of data.
cat "$all_obj_allocs_file" | cut -f1 | sort | uniq | while read obj rest; do
    echo "Saw line $obj $rest" 1>&2
    embedded_info="$( ${OBJCOPY:-objcopy} -Obinary -j.allocs_src${our_name_frag} "$obj" /dev/stdout )"
    echo "Embedded info is \`$embedded_info'" 1>&2
    # We dropped the step of rewriting uniqtype names s.t. base type names are canonicalised.
    # PROBLEM: might not some to-be-dumped symnames, like bitfields, always
    # need DWARF to figure out. So can we really eliminate this step? Probably we should
    # work around the bitfield issue by assuming a certain algorithm for allocating bit positions
    # and then checking later that we were correct.
    # Dumpallocs never has to output a bitfield type, though... even with synthetic (dwarfidl)
    # typenames, I think it just never does, even when sizing structs that use bitfields.
    all_cus_info="$( get_cu_info "$obj" )"
    echo "$all_cus_info" | while read_cu_info; do
        case "$cu_language_num" in
            (1|2|12|29) # DW_LANG_C89, DW_LANG_C, DW_LANG_C99, DW_LANG_C11
                $(dirname "$0")/lang/c/bin/c-"$our_name_rewritten" "$cu_sourcepath" "$obj" "$cu_fname" "$cu_compdir"
            ;;
            (*) # unknown
                echo "Warning: could not gather source-level allocs for unknown language: $cu_language_fullstr ($cu_language_num, $( echo -n "$cu_language_fullstr" | hd ))" 1>&2
            ;;
        esac
    done
    echo "$embedded_info"
done | pad_numbers | sort -t$'\t' -k1 -k2 | uniq        #use_src_realpaths | 
