
translate_symnames() {
    objfile="$1"
    
    # We want to select out only a certain CU, if the caller asks. 
    # That's because we might be being run on a whole binary
    # (from c-gather-srcallocs)
    # or on a single relocatable file (link-used-types).
    cu_fname="$2"
    cu_compdir="$3"
    
    BASE_TYPES_TRANSLATION=${BASE_TYPES_TRANSLATION:-$( dirname $0 )/../src/base-types-translation}

    signpost_frag_regexp="__ARG[0-9]+_|__PTR_|__REF_|__RR_|__ARR[0-9]+_|__FUN_FROM_|__FUN_TO_|__VA_"
    type_pred_regexp="__uniqtype__|${signpost_frag_regexp}"
    type_succ_regexp="${signpost_frag_regexp}|\$"
    
    # join the substitutions into a big sed program
    sed_program=""
    echo ${BASE_TYPES_TRANSLATION} "$objfile" 1>&2
    while read c_base canon_base; do
        sed_program="${sed_program}; s/(${type_pred_regexp})${c_base}(${type_succ_regexp})/\1${canon_base}\2/g"
    done<<<"$( ${BASE_TYPES_TRANSLATION} "$objfile" "$cu_fname" "$cu_compdir" )"
    
    echo "sed program is $sed_program" 1>&2
    if [[ -n "$( echo "$sed_program" | tr -d '[:blank:]' )" ]]; then

        # apply the substitutions to this symname, "til a fixed point"
                sed -r "$sed_program" | \
                sed -r "$sed_program" | \
                sed -r "$sed_program" | \
                sed -r "$sed_program" | \
                sed -r "$sed_program" | \
                sed -r "$sed_program" | \
                sed -r "$sed_program" | \
                sed -r "$sed_program" | \
                sed -r "$sed_program" | \
                sed -r "$sed_program" | \
                sed -r "$sed_program"
    else
        cat
    fi
}
