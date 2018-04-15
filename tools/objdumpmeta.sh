#!/bin/bash

# Build a list of allocation sites using the power of objdump.
# We record them as the string inside the < >
# i.e. <symname+0xoffset>, without the < >.

case $(basename "$0") in
    (*dumpallocs|*dumpmeta|*dumpmemacc)
        outputstyle="tab"
        ;;
    (*)
        outputstyle="punc"
        ;;
esac

pad_numbers () {
    tr '\n' '\f' | \
    sed 's/\f/\f\n/g' | \
    tr '\t' '\n' | \
    sed -r "s/^[[:space:]]*[0-9]+[[:space:]]*\$/printf '%06d' '&'/e" | \
    tr '\n' '\t' | \
    sed 's/\f\t/\n/g'
}

. $(dirname "$0")/debug-funcs.sh

# objdumpmeta currently: we read from three temporary files:
# allocsites_tmpfile: 
# addr2line_tmpfile: 
# objdump_tmpfile: an interleaving of instructions and headers

# objdumpmeta completely rewritten as a two-pass awk script
# pass 1: build an address-sorted list of metadata'd instructions

# HACK 1: to make this work for llvm, we just use gold to generate
# a native file with DWARF info, 
filetype="$( file -bi "$1" )"
case "$filetype" in
    (application/x-object*)
        inputfile="$1"
    ;;
    (application/x-executable*)
        inputfile="$1"
    ;;
    (application/x-sharedlib*)
        inputfile="$1"
    ;;
    (application/octet-stream*|application/x-archive*)
        # probably an LLVM bitcode file
        llvm_nm_output="$( llvm-nm "$1" 2>/dev/null )"
        if [[ -n "$llvm_nm_output" ]]; then
            # yes, bitcode. So make a temporary file
            inputfile="$(mktemp)"
            echo "Using temporary object file: $inputfile" 1>&2
            ld.gold -r --plugin LLVMgold.so -o "$inputfile" toy.o || \
            (echo "Error converting LLVM bitcode to native object." 1>&2; false) || exit 1
        else
            # actually, not bitcode; roll with it
            inputfile="$1"
        fi
    ;;
    (*) echo "Error: unrecognised file type $filetype" 1>&2; exit 1
    ;;
esac

echo "objdumpmeta has meta_instr_regexp: $meta_instr_regexp" 1>&2

case "$( file "$inputfile" | grep reloc )" in
    ('')
        # not relocatable
        disassembly_opts="-Rd"
        ;;
    (*)
        # relocatable
        disassembly_opts="-rd"
        ;;
esac

apply_relocs () {
    # We can only identify callees if we know how call sites are relocated,
    # e.g. R_X86_64_PC32 <malloc>.
    # This is a filter for objdump output that 
    # for each disassembly line,
    # if it is followed by one or more relocs,
    # will merge that reloc info into the line. 
    # We do it in the most stupid wqay possible: 
    # delete newlines preceding reloc info.
    tr '\n' '\f' | sed 's/\f\([[:blank:]]*[0-9a-f]\+: R\)/\1/g' | tr '\f' '\n'
}

# get allocation sites in "address sym offset" form
make_allocsites_tmpfile () {
allocsites_tmpfile="$(mktemp)"
objdump --prefix-addresses --show-raw-insn ${disassembly_opts} "$inputfile" | \
apply_relocs | \
egrep "$meta_instr_regexp" | \
sed -r "s/${meta_instr_regexp}.*/\1\t\2/" | \
sed -r 's/([-\+]0x[0-9a-f]*) *$/ \1/' > "$allocsites_tmpfile"
echo "Written allocsites output to $allocsites_tmpfile" 1>&2
echo "$allocsites_tmpfile"
}

# read the whole objdump to a temporary file, to avoid re-disassembling
get_objdump () {
objdump --line-numbers --prefix-addresses --show-raw-insn ${disassembly_opts} -S "$inputfile" | \
   apply_relocs
}
make_objdump_tmpfile () {
    objdump_tmpfile="$(mktemp)" 
    get_objdump > "$objdump_tmpfile"
    echo "Written objdump output to $objdump_tmpfile" 1>&2
    echo "$objdump_tmpfile"
}

#echo "Found allocation sites: " 1>&2
#cat "$allocsites_tmpfile" 1>&2

# HACK: sometimes our gnu_debuglink section is wrong, i.e. does not reflect
# the location of the debug info, e.g. according to Debian policy where
# the debug info is moved into /usr/lib/debug but the debuglink is stuck
# with the same-directory path (i.e. plain filename) that was correct when
# stripping occurred during the build process. 

#bytes_consumed=0
input_up_to_next_instr_line=""

get_raw_addresses () {
    while read address sym offset; do
        # 0. skip blank lines
        if [[ -z "${address}${sym}${offset}" ]]; then
            continue
        fi

        echo 0x${address}
    done <"$allocsites_tmpfile"
}

generate_output_lines () {

    raw_addresses="$( get_raw_addresses )"

    # the way this should work: one loop generates return addresses and code context.
    # another loop does addr2line.
    # we merge them.
    
    # we want to make sure we get exactly one line in addr2line_output per line in allocsites_tmpfile
    # FIXME: and delete the "discriminator" stuff
    addr2line_output="$( if test -n "$raw_addresses"; then addr2line -a -e "$1" $raw_addresses; else true; fi | sed -r 's/^0x[0-9a-f]{8,}/\f&\t/' | tr -d '\n' | tr '\f' '\n' | tail -n+2 )"
    echo "addr2line said $addr2line_output" 1>&2

    addr2line_tmpfile="$(mktemp)"
    echo "addr2line temp file is $addr2line_tmpfile" 1>&2
    echo "$addr2line_output" > "$addr2line_tmpfile"
    while read address sym offset; do
    # 0. skip blank lines
    if [[ -z "${address}${sym}${offset}" ]]; then
        continue
    fi
    
    read addr2line_addr addr2line_line <&3 || (echo "could not read addr2line file" 1>&2; false) || exit 1
    
    if [[ "$addr2line_addr" != 0x"$address" ]]; then
        echo "Warning: $addr2line_addr != 0x$address" 1>&2
    fi

    # Now use the power of objdump -S to get the source line for that alloc.
    # 1, Build a regexp that will let us identify (and stop at) the next alloc site in order
    regexp="^${address}[[:blank:]]*<"
    #echo "regexp: $regexp" 1>&2
    # 2. Grab that and some lines of pre-context, 
    # which hopefully will include the allocating source line
    # instead of this, use sed
    next_chunk="$( tmp="$( sed -r "/${regexp}.*/ q" <<<"$input_up_to_next_instr_line" )"; \
       if [[ -n "$( tail -n1 <<<"$tmp" | egrep "$regexp" )" ]]; then echo "$tmp"; else sed -r "/${regexp}.*/ q" <&4; fi )"
    #echo "fast way, next chunk: $next_chunk" 1>&2
    #bytes_consumed=$(( $bytes_consumed + $( echo "$next_chunk" | wc -c ) ))
    #echo "bytes_consumed is now $bytes_consumed" 1>&2
    context="$( echo "$next_chunk" | tail -n31 )"
    #echo "fast way, context: $context" 1>&2
    
    #echo "context: $context" 1>&2
    # 2a. Narrow that context to the last objdump-printed source line.
    # Remember the file/line pair.
    # All this "discriminator" stuff is to hack around the fact that
    # *both* addr2line *and* objdump --line-numbers sometimes output
    # ' (discriminator [0-9]+)' at the end of a filename.
    with_file_line_header="$( echo "$context" | tac | sed -r '/^\/.*:[0-9]+( \(discriminator [0-9]*\))?$/ q' | tac )"
    # If we didn't hit a source header line,
    # what we read next will be garbage, so grep for something that matches the pattern
    file_line_header="$( echo "$with_file_line_header" | egrep '^/.*:[0-9]+( \(discriminator [0-9]*\))?$' | head -n1 )"
    if [[ -z "$file_line_header" ]]; then 
        echo "Warning: could not find source line for ${sym}${offset}, skipping" 1>&2
        echo "Context attempt was:"$'\n'"$with_file_line_header" 1>&2
    else
        filename="$( echo "$file_line_header" | sed -r 's/:[0-9]+( \(discriminator [0-9]*\))?$//' )"
        line_number="$( echo "$file_line_header" | sed -r 's/.*:([0-9]+)( \(discriminator [0-9]*\))?$/\1/' )"
        # How many source lines are in the chunk?
        # We grep -v out the header and anything that looks like an instruction disassembly line
        source_lines="$( echo "$with_file_line_header" | egrep -v '^/.*:[0-9]+( \(discriminator [0-9]*\))?$' | egrep -v \
            '^[0-9a-f]+[[:blank:]]*<.+(\+0x[0-9a-f]+)?>.*' )"
        source_lines_count="$( echo "$source_lines" | wc -l )"
        # HACK: if we didn't get anything, make sure we output a 1-line interval anyway
        if [[ $source_lines_count -eq 0 ]]; then
            echo "Warning: context for ${sym}${offset} appears to contain zero source lines. Context follows." 1>&2
            echo "$source_lines" 1>&2
            source_lines_count=1
        fi
        context_min="$( echo "$with_file_line_header" | tail -n+2 )"
        #echo "context_min: $context_min" 1>&2
        # 3. Filter out non-source lines., and collapse to a single line
        source="$( echo "$context_min" | egrep -v "$line_regexp" | tr '\n' ' ' )" #"
        #echo "source: $source" 1>&2
        # 3a. collapse to a single line
        source_oneline="$( echo "$source" | tr '\n' ' ' )"
        #echo "source_oneline: $source_oneline" 1>&2
        # 4. Get the first ident following the last occurrence of "new" or "sizeof"
        token="$( echo "$source_oneline" | \
        egrep '(new|sizeof)([^0-9a-z_]|$)' | \
        sed -r 's/.*(new|sizeof)([^0-9a-zA-Z_]|$)/\2/' | \
        sed -r 's/[^0-9a-zA-Z_]*([a-zA-Z0-9_ \*]+).*/\1/' | tr -s '[:blank:]' ' ' )" #"
        #echo "token: $token" 1>&2
    fi
    # 4a. We want the *return address*, not the site of the call per se. Fix this up.
    instr_line_regexp='([0-9a-f]+)[[:blank:]]*<([^-\+]+)([-\+](0x[0-9a-f]+))?>.*'
    input_up_to_next_instr_line="$( sed -r "/^${instr_line_regexp}.*/ q" <&4 )"
    next_instr_line="$( echo "$input_up_to_next_instr_line" | tail -n1 | egrep "$instr_line_regexp" )"
    next_instr_line_formatted="$( echo "$next_instr_line" | sed -rn "/$instr_line_regexp/ { s/$instr_line_regexp/\1\t\2\t\4/; p }" )"
    read return_addr return_addr_sym return_addr_offset <<<"$next_instr_line_formatted"
    #return_addr_sym="$sym"
    #return_addr_offset="$offset"
    echo "return_addr is $return_addr, sym $return_addr_sym, offset ${return_addr_offset:=0}" 1>&2
    if [[ "$return_addr_sym" != "$sym" ]]; then
        echo "Warning: return address for alloc site ${sym}${offset} does not appear to be in same function, but at ${return_addr_sym}+${return_addr_offset:-??}." 1>&2
        # we continue
    fi
    # 5. Compare with addr2line
    addr2line_filename="$( echo "$addr2line_line" | sed 's/:.*//' )"
    if [[ "$addr2line_filename" != "??" ]]; then
        addr2line_filename="$addr2line_filename"
    fi
    addr2line_line_number="$( echo "$addr2line_line" | sed -r 's/.*:([0-9]+)( \(discriminator [0-9]*\))?$/\1/' | sed 's/.*://' )"
    if [[ "$addr2line_line_number" == "?" ]]; then
        addr2line_line_number=0
    fi
    if [[ "$addr2line_filename" != "${filename:-??}" ]]; then
        echo "Warning: filenames disagreed: addr2line '$addr2line_filename', objdump '$filename'" 1>&2
    fi
    # 6. Print stuff
    #echo "${return_addr_sym}"$'\t'"0x${return_addr}"$'\t'"${return_addr_offset}"$'\t'"0x${address}"$'\t'"${filename}"$'\t'"${line_number}"$'\t'$(( ${line_number:-0} + ${source_lines_count:-0} ))$'\t'"${token:-\$FAILED\$}"$'\t'"${source_oneline}"
    echo "${return_addr_sym}"$'\t'"0x${return_addr}"$'\t'"${return_addr_offset}"$'\t'"0x${address}"$'\t'"${addr2line_filename}"$'\t'"${addr2line_line_number}"$'\t'$(( ${addr2line_line_number:-0} + 1 ))$'\t'"${token:-\$FAILED\$}"$'\t'"${source_oneline}"
done <"$allocsites_tmpfile" 3<"$addr2line_tmpfile" 4<"$objdump_tmpfile" | \
   pad_numbers | LANG=C sort -s -t$'\t' -k5 -k6 # i.e. sort by filename and line number
}

# comment to help debugging
#rm -f "$objdump_tmpfile"
#rm -f "$allocsites_tmpfile"
#rm -f "$addr2line_tmpfile"
