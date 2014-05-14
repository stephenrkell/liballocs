#!/bin/bash 

if [[ -z "$EQUIVS" ]]; then
    EQUIVS=$( readlink -f `dirname $0`/../frontend/c/base-type-equivs.txt )
    if [[ -z "$EQUIVS" ]]; then
        echo "Error: no equivs file" 1>&2
    fi
fi

# we are reading the output of nm -fposix on a -uniqtypes.o file
uniqtypes="$( tr -s '[:blank:]' '\t' | cut -f1 | grep '^__uniqtype_' )"

# build a big regexp for each equivalence class, to filter out only 
# the ones that are actually used
while read equivclass; do
    # grep uniqtypes for any member of this equivalence class
    big_regexp='^__uniqtype_([0-9a-f]{7,8})?_('"$( echo "$equivclass" | sed 's/, */|/g' | tr ' ' '_' )"')$'
    matches="$( echo "$uniqtypes" | egrep "$big_regexp" )"
    # We expect at most one typecode-qualified line for each equivclass -- 
    # i.e. a single DWARF name is used consistently in the debug info.
    if [[ $( echo "$matches" | grep '^__uniqtype_[0-9a-f]{7,8}_' | wc -l ) -gt 1 ]]; then
        echo "Error: expected at most one matching uniqtype for ${big_regexp}; got " $matches 1>&2
        # If this fails, it probably means that we have multiple CUs, and some of them 
        # use different DWARF names for a given base type than others do.
        # We can be more clever about tolerating this, but it gets subtle because
        # we should really check that each CU's version of a given apparently-synonymous base type 
        # is actually the same (w.r.t. size, bit-size, encoding) as the others. 
        # Otherwise we can claim it's a type-incorrect link, although that might be a bit 
        # conservative.
        exit 1
    fi
    echo "$matches" | sed '/^$/ d' | while read matching_typesym; do
        # grep-delete the matching uniq type from the equivalence class, then
        # output a linker alias option for all the others
        matching_type="$( echo "$matching_typesym" | sed -r 's/^__uniqtype_([0-9a-f]{7,8})?_//' )"
        echo "$equivclass" | sed 's/, */\n/g' | tr ' ' '_' | grep -v "^${matching_type}"'$' | while read equiv; do
            synonym_typesym="$( echo "$matching_typesym" | sed -r "s/^(__uniqtype_([0-9a-f]{7,8})?_).*/\1${equiv}/" )" 
            echo -Wl,--defsym,${synonym_typesym}=${matching_typesym}
        done
    done
done < "$EQUIVS"
