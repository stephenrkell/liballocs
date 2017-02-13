#!/bin/bash

this_filename () {
    # look through the defined functions
    ctr=0
    while true; do
        if [[ -z "${FUNCNAME[$ctr]}" ]]; then
            echo "Error: couldn't find this_filename" 1>&2
            exit 1
        fi
        if [[ "${FUNCNAME[$ctr]}" == "this_filename" ]]; then
            echo ${BASH_SOURCE[$ctr]}
            exit 0
        fi
        ctr=$(( $ctr + 1 ))
    done
}

LIBALLOCS_BASE="${LIBALLOCS_BASE:-$( dirname "$(this_filename)" )/..}"
USEDTYPES=${USEDTYPES:-${LIBALLOCS_BASE}/tools/usedtypes}
BASE_TYPES_TRANSLATION=${BASE_TYPES_TRANSLATION:-${LIBALLOCS_BASE}/tools/lang/c/bin/base-types-translation}
CC=${CC:-$(which cc)}
LD=${LD:-$(which ld)}
OBJCOPY=${OBJCOPY:-$(which objcopy)}

compile () {
   src="$1"
   dest="$2"
   asm="$( mktemp --suffix=.s )"
   # HACK: only gcc lets us do the section flags injection attack ("comdat#..." trick)
   gcc -S -x c -o "$asm" "$src" && \
   gcc -c -o "$dest" "$asm" && \
   echo "Compiler generated $dest" 1>&2
}

link_defining_aliases () {
  our_objfile="$1"
  our_usedtypes_obj="$2"
  temporary_out=$( mktemp )
  # NOTE: we used to add aliases here...
  # `nm -fposix "${our_usedtypes_obj}" | $(dirname ${USEDTYPES})/alias-linker-opts-for-base-types.sh | sed -r 's/-Wl,--defsym,/--defsym /g'`
  # but this seems wrong (and, at least, will create "multiple definition" errors at link time)
  ${LD} -o "$temporary_out" -r "$our_objfile" "$our_usedtypes_obj" && \
  echo "Linker generated ${temporary_out}, moving to ${our_objfile}" 1>&2 && \
  mv "$temporary_out" "$our_objfile"
}

symbol_redefinitions () {
    f="$1"
    # Here we are renaming codeless symnames with codeful ones, for the codeful
    # ones that are defined in our temporary (usedtypes) object file. 
    nm -fposix --defined-only "$f" | tr -s '[:blank:]' '\t' | cut -f1 | \
      egrep '__uniqtype_([0-9a-f]{8})_' | \
      sed -r 's/__uniqtype_([0-9a-f]{8})_(.*)/--redefine-sym __uniqtype__\2=__uniqtype_\1_\2/'
}

objcopy_and_redefine_codeless_names () {
    our_objfile="$1"
    our_usedtypes_obj="$2"
    
    # now, fill in the codeful names for codeless ones
    second_redefinition_args="$( symbol_redefinitions "$our_usedtypes_obj" )" && \
    echo ${OBJCOPY} $second_redefinition_args "$our_objfile" 1>&2 && \
    ${OBJCOPY} $second_redefinition_args "$our_objfile" && \
    echo "objcopy renamed symbols in $our_objfile according to $second_redefinition_args" 1>&2
}
