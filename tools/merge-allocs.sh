#!/bin/bash

# We merge the binary-derived allocsite information from objdumpallocs
# with the precise source-level allocsite information from dumpallocs.ml.

. ~/lib/bash/util

# We can't easily predict where the .allocs file will be for a given source file.
# (see dumpallocs.ml for the reason).

all_obj_allocs_file="$1"

lexicographic_compare_le () {
    sorted="$( echo "$1"$'\n'"$2" | LANG=C sort )"
    if [[ "$sorted" == "$1"$'\n'"$2" ]]; then
        echo "strings $1 and $2 compare le" 1>&2
        return 0 # true
    elif [[ "$sorted" == "$2"$'\n'"$1" ]]; then
        echo "strings $1 and $2 compare gt" 1>&2
        return 1 # false
    else
        echo "lexicographic_compare_le: internal error" 1>&2
        return 99
    fi
}
lexicographic_compare_lt () { # is $1 lt $2?
    if [[ "$1" == "$2" ]]; then
        #echo "strings compare eq" 1>&2
        return 1 # false
    else
        lexicographic_compare_le "$1" "$2"
    fi
}

lexicographic_compare_gt () {
    if ! lexicographic_compare_le "$1" "$2"; then 
        # true
        return 0
    else
        # false
        return 1
    fi
}

lexicographic_compare_ge () {
    if ! lexicographic_compare_lt "$1" "$2"; then 
        # true
        return 0
    else
        # false
        return 1
    fi

}

all_source_allocs_file="$2"
# first pass over the input: gather all the .allocs files we might want.
# NOTE: previously we just took all the directories containing source files,
# then looked for .i.allocs files within those. This results in false positives
# when multiple executables/libraries are built within the same source tree,
# because some .allocs files refer to compilation units that only went into
# one or other of those objects. Instead, we exploit the fact that we now have
# a one-to-one correspondence between compiler input files and .i.allocs files:
# we get the CU names for every compiler input, and look for a similarly-named
# .i.allocs file.

#while read obj func offset sourcefile rest; do
#    echo "$( dirname "$sourcefile" )"
#done < "$all_obj_allocs_file" | sort | uniq | while read dir; do find $dir -name '*.allocs'; done | \
#xargs cat | pad_numbers | sort -t$'\t' -k1 -k2 | uniq > "$all_source_allocs_file"
## FIXME: I'm not sure why we need the uniq here: why does dumpallocs sometimes output
## multiple lines for the same malloc call? 
## e.g. for /usr/local/src/git-1.7.5.4/builtin/log.c line 1268

# echo "all_source_allocs_file: $all_source_allocs_file" 1>&2
# echo "all_obj_allocs_file: $all_obj_allocs_file" 1>&2

# second pass -- we read input grouped by source file then line number
keep_old_source_line=0
have_matched_this_source_line=0
while read obj func addr sourcefile sourceline sourceline_end alloctype rest; do
    #echo "read line for obj $obj sourcefile $sourcefile" 1>&2
    
    # We have our source-level allocs data on fd 3
    while true; do 
        # read a line of source-level allocs data, unless the last line is still good
        if [[ $keep_old_source_line -eq 0 ]]; then
            #echo "reading some more" 1>&2
            have_matched_this_source_line=0
            read alloc_sourcefile alloc_sourceline alloc_fun alloc_ciltype <&3 || break 2
            #echo "Setting have_matched_this_source_line to 0 for sourcefile $alloc_sourcefile line $alloc_sourceline" 1>&2
            #echo "read returned $?, new sourceline is $alloc_sourceline" 1>&2
        else
            #echo "retained old line" 1>&2
            true
        fi
        
        # possibilities:
        # 1. this is the allocs data that matches our toplevel line
        # 2. this precedes the allocs data that matches our toplevel line
        # 3. our toplevel line will never be matched, and we need to advance past it
        # (There is no "this follows our toplevel line" case, because we sorted
        # both inputs.)
        # Detecting 1 is easy; if so, we advance both inputs.
        #  ... NO! We can have >1 call instr for a given source-level call, so just advance obj.
        # Detecting 2: if it has source line < toplevel, we can safely skip it as it will never be needed.
        # Else if its source line is in our window, it's a match
        # Else we have case 3, so we need to advance toplevel.
        if [[ "$(readlink -f "$alloc_sourcefile" )" == "$( readlink -f "$sourcefile" )" ]] && \
           lexicographic_compare_ge "$alloc_sourceline" "$sourceline" && \
           lexicographic_compare_lt "$alloc_sourceline" "$sourceline_end"; then
#           [[ "$alloc_sourceline" -lt "$(( $sourceline + $sourceline_end ))" ]]; then
            # matched -- output, and advance both inputs
            #echo "matched, so advancing both" 1>&2
            # if we got "(none)" as the type, it's dumpallocs's way of telling us
            # that it's definitely not an allocation function after all, so just
            # skip without printing
            case "$alloc_ciltype" in
                ('(none)')
                    true
                ;;
                (*)
                    #echo "Outputting match for sourcefile $alloc_sourcefile line $alloc_sourceline" 1>&2
                    echo "$obj"$'\t'"$func"$'\t'"$addr"$'\t'"$sourcefile"$'\t'"$sourceline"$'\t'"$sourceline_end"$'\t'"$alloc_ciltype"$'\t' 
                ;;
            esac
            #echo "Setting have_matched_this_source_line to 1 for sourcefile $alloc_sourcefile line $alloc_sourceline" 1>&2
            have_matched_this_source_line=1
            
            # We might want to keep the old source line, because there might be other
            # call instructions that it matches. But we can definitely consume the objdump line
            keep_old_source_line=1
            continue 2
        # lexicographic compare...
        else
            echo found "$(readlink -f "$alloc_sourcefile" )" != "$( readlink -f "$sourcefile" )" or \
           NOT lexicographic_compare_ge "$alloc_sourceline" "$sourceline" or \
           NOT lexicographic_compare_lt "$alloc_sourceline" "$sourceline_end" 1>&2
            if lexicographic_compare_lt "$(readlink -f "$alloc_sourcefile")" "$( readlink -f "$sourcefile" )" || \
             ( [[ "$(readlink -f "$alloc_sourcefile")" == "$( readlink -f "$sourcefile" )" ]] && \
               lexicographic_compare_lt "$alloc_sourceline" "$sourceline_end" ); then
               # we will not use this source line [again], so skip it
               # warn only if we have not used this source line
               if ! [[ $have_matched_this_source_line -eq 1 ]]; then
                   #echo "Found have_matched_this_source_line not equal to 1" 1>&2
                   echo "warning: skipping source allocs line, comparing lt next obj entry (which has file ${sourcefile}, lines ${sourceline}-${sourceline_end}, address ${obj}<${func}> @${addr}): $alloc_sourcefile"$'\t'"$alloc_sourceline"$'\t'"$alloc_ciltype" 1>&2
               fi
               keep_old_source_line=0
               # we have not yet consumed the obj line, so don't grab a new obj line
               continue 1
            else 
                # This means we didn't match, and the source line is not LT the obj line. 
                # Try advancing the outer loop and re-testing
                # We might have a match for the next iteration of the outer loop
                # Each time we advance the outer, we are giving up on matching that line. 
                # (We can say "comparing lt" because the equality case was handled in the first test.)
                echo "warning: skipping objdump allocs line, comparing lt next source entry (which has file ${alloc_sourcefile}, line ${alloc_sourceline}): $obj $func $addr $sourcefile $sourceline $sourceline_end $alloctype $rest" 1>&2
                keep_old_source_line=1
                continue 2
            fi
        fi
    done
   
done <"$all_obj_allocs_file" 3<"$all_source_allocs_file"
#rm -f "$all_source_allocs_file"
#rm -f "$all_obj_allocs_file"
