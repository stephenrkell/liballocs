#!/bin/bash

# We merge the binary-derived allocsite information from objdumpallocs
# with the precise source-level allocsite information from dumpallocs.ml.
# And similarly for other metadata -- the idea is generic.
# What we're really doing is matching binary-level features (instructions)
# against source-level features (file/line/column spans)
# and outputting the union of the metadata,
# generally propagating source-level metadata (allocation types)
# to binary features (instructions).

all_obj_meta_file="$1"

lexicographic_compare_le () {
    sorted="$( echo "$1"$'\n'"$2" | LANG=C sort )"
    if [[ "$sorted" == "$1"$'\n'"$2" ]]; then
        # echo "strings $1 and $2 compare le" 1>&2
        return 0 # true
    elif [[ "$sorted" == "$2"$'\n'"$1" ]]; then
        # echo "strings $1 and $2 compare gt" 1>&2
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

all_source_meta_file="$2"
echo "all_source_meta_file: $all_source_meta_file" 1>&2
echo "all_obj_meta_file: $all_obj_meta_file" 1>&2

# second pass -- we read input grouped by source file then line number
keep_old_source_line=0
have_matched_this_source_line=0
while read -r obj func addr sourcefile sourceline sourceline_end typ rest; do
    #echo "read line for obj $obj sourcefile $sourcefile" 1>&2
    
    # We have our source-level metadata on fd 3
    while true; do 
        # read a line of source-level metadata, unless the last line is still good
        if [[ $keep_old_source_line -eq 0 ]]; then
            #echo "reading some more" 1>&2
            have_matched_this_source_line=0
            # for allocsite metadata, srcmeta_rest will be two fields: the target function and then the type name/descr
            read -r srcmeta_sourcefile srcmeta_sourceline srcmeta_sourceline_end srcmeta_rest <&3 || break 2
            #echo "Setting have_matched_this_source_line to 0 for sourcefile $srcmeta_sourcefile line $srcmeta_sourceline" 1>&2
            #echo "read returned $?, new sourceline is $srcmeta_sourceline" 1>&2
        else
            #echo "retained old line" 1>&2
            true
        fi
        
        # possibilities:
        # 1. this is the metadata that matches our toplevel line
        # 2. this precedes the metadata that matches our toplevel line
        # 3. our toplevel line will never be matched, and we need to advance past it
        # (There is no "this follows our toplevel line" case, because we sorted
        # both inputs.)
        # Detecting 1 is easy; if so, we advance both inputs.
        #  ... NO! We can have >1 instr for a given source-level feature, so just advance obj.
        # Detecting 2: if it has source line < toplevel, we can safely skip it as it will never be needed.
        # Else if its source line is in our window, it's a match
        # Else we have case 3, so we need to advance toplevel.
        if [[ "$srcmeta_sourcefile" == "$sourcefile" ]] && \
           lexicographic_compare_ge "$srcmeta_sourceline" "$sourceline" && \
           lexicographic_compare_lt "$srcmeta_sourceline" "$sourceline_end"; then

            # matched -- output, and advance both inputs
            #echo "matched, so advancing both" 1>&2

            echo "$obj"$'\t'"$func"$'\t'"$addr"$'\t'"$sourcefile"$'\t'"$sourceline"$'\t'"$sourceline_end"$'\t'"$srcmeta_rest"$'\t' 

            #echo "Setting have_matched_this_source_line to 1 for sourcefile $srcmeta_sourcefile line $srcmeta_sourceline" 1>&2
            have_matched_this_source_line=1
            
            # We might want to keep the old source line, because there might be other
            # instructions that it matches. But we can definitely consume the objdump line
            keep_old_source_line=1
            continue 2
        # lexicographic compare...
        else
            echo "NO MATCH: found $srcmeta_sourcefile != $sourcefile or " \
           "NOT lexicographic_compare_ge $srcmeta_sourceline $sourceline or" \
           "NOT lexicographic_compare_lt $srcmeta_sourceline $sourceline_end" 1>&2
           
            if lexicographic_compare_lt "$srcmeta_sourcefile" "$sourcefile" || \
             ( [[ "$srcmeta_sourcefile" == "$sourcefile" ]] && \
               lexicographic_compare_lt "$srcmeta_sourceline" "$sourceline_end" ); then
               # we will not use this source line [again], so skip it
               # warn only if we have not used this source line
               if ! [[ $have_matched_this_source_line -eq 1 ]]; then
                   #echo "Found have_matched_this_source_line not equal to 1" 1>&2
                   echo "warning: skipping source meta line, comparing lt next obj entry (which has file ${sourcefile}, lines ${sourceline}-${sourceline_end}, address ${obj}<${func}> @${addr}): $srcmeta_sourcefile"$'\t'"$srcmeta_sourceline"$'\t'"$srcmeta_rest" 1>&2
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
                echo "warning: skipping objdump meta line, comparing lt next source entry (which has file ${srcmeta_sourcefile}, line ${srcmeta_sourceline}): $obj $func $addr $sourcefile $sourceline $sourceline_end $srcmeta_rest" 1>&2
                keep_old_source_line=1
                continue 2
            fi
        fi
    done
   
done <"$all_obj_meta_file" 3<"$all_source_meta_file"
