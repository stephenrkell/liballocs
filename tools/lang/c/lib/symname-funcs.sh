# horrible HACK
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

translate_symnames() {
    objfile="$1"
    
    # We want to select out only a certain CU, if the caller asks. 
    # That's because we might be being run on a whole binary
    # (from c-gather-srcallocs)
    # or on a single relocatable file (link-used-types).
    cu_fname="$2"
    cu_compdir="$3"
    
    BASE_TYPES_TRANSLATION=${BASE_TYPES_TRANSLATION:-$( dirname "$(this_filename)" )/../src/base-types-translation}

    signpost_frag_regexp="__ARG[0-9]+_|__PTR_|__REF_|__RR_|__ARR[0-9]*_|__FUN_FROM_|__FUN_TO_|__VA_"
    type_pred_regexp="__uniqtype__|${signpost_frag_regexp}"
    type_succ_regexp="${signpost_frag_regexp}|\$|"$'\t'
    
    # FIXME: we should really use our hard-coded table of base type equivalences here,
    # to save me the pain of remembering it's "short unsigned int" and not
    # "unsigned short int", say.

    # join the substitutions into a big sed program
    sed_program=""
    echo running ${BASE_TYPES_TRANSLATION} "$objfile" "$cu_fname" "$cu_compdir"  1>&2
    while read c_base canon_base; do
        sed_program="${sed_program}; s/(${type_pred_regexp})$(echo "${c_base}" | sed 's/\$/\\$/')(${type_succ_regexp})/\1${canon_base}\2/g"
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
