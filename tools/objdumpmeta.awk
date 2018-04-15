#!/usr/bin/gawk -bf
# here we enable ^"treat-characters-as-bytes" because...
# it makes the code go faster

BEGIN { 
    # state is
    # 0: initial state
    # 1: might be a resetting line or a source line only;
    # 2: might be a resetting line or a source or filename/line line
    # 3: might be a resetting line or a source or function name line
    # 4: might be a resetting line or a source or function name line or filename/line line;
    state = 0;
    start_new_source_fragment = 1;
    disassembly_line_prefix="^([0-9a-f]+)[[:blank:]]*<([^-+]*)([-+](0x[0-9a-f]+))?>";
    disassembly_line_pattern=disassembly_line_prefix "[[:blank:]]*([0-9a-f]{2}[[:blank:]]+)*.*";
    filename_line_pattern="^(.+):([0-9]+)( \\(discriminator [0-9]*\\))?$";
    source_fragment="";
    filename_line="";
    function_name="";
    #meta_instr_regexp=ARGV[1]
    # for testing:
    if (meta_instr_regexp_cmdline=="") {
        meta_instr_regexp=disassembly_line_prefix ".*((call|jmp).*(<((malloc)|(calloc)|(realloc)|(memalign)|(posix_memalign)|(valloc)|(__monalloca_)|( malloc)|(__wrap_malloc)|(calloc)|(__wrap_calloc)|(realloc)|(__wrap_realloc)|(memalign)|(__wrap_memalign)|(alloca)|(__wrap_alloca))|(.*)\\*))";
    } else {
        meta_instr_regexp=meta_instr_regexp_cmdline
    }
    #meta_instr_regexp="^([0-9a-f]*) <([^>]*)>.*((call|jmp).*(<((malloc)|(calloc)|(realloc)|(memalign)|(posix_memalign)|(valloc)|(__monalloca_)|( malloc)|(__wrap_malloc)|(calloc)|(__wrap_calloc)|(realloc)|(__wrap_realloc)|(memalign)|(__wrap_memalign)|(alloca)|(__wrap_alloca))|.*\\*)|.* 00 00 00 00.*callq)"
    if (debug) printf("meta_instr_regexp: %s\n", meta_instr_regexp) >"/dev/stderr";
    #meta_instr_regexp="^([0-9a-f]*) <([^>]*)>.*((call|jmp).*(<((malloc)|(calloc)|(realloc)|(memalign)|(posix_memalign)|(valloc)|(__monalloca_)|( malloc)|(__wrap_malloc)|(calloc)|(__wrap_calloc)|(realloc)|(__wrap_realloc)|(memalign)|(__wrap_memalign)|(alloca)|(__wrap_alloca))|.*\\*)|.* 00 00 00 00.*callq)"
    #if (debug) printf("now meta_instr_regexp: %s\n", meta_instr_regexp) >"/dev/stderr";
    next_disas_line_is_meta_return_addr=0
    source_offset=0
}

# The format of objdump output we see has a few kinds of lines.
/.*:[[:blank:]]*file format [-a-zA-Z0-9_]*$/ {
    state=0
    if (debug) printf("header  : %s\n", $0) >"/dev/stderr";
    next
}

/^[[:blank:]]*$/ {
    # leave state unchanged
    if (state == 0) {
        if (debug) printf("blank   : %s\n", $0) >"/dev/stderr";
        next
    } else {
        if (debug) printf("source0 : %s\n", $0) >"/dev/stderr";
        # treat it as a source line
        if (start_new_source_fragment) {
            start_new_source_fragment = 0;
            source_fragment="";
            source_offset=0;
        }
        source_fragment = source_fragment "\n" $0;
        source_offset += 1;
        state=1;
        next
    }
}

/Disassembly of section .*:$/ {
    if (debug) printf("dishdr  : %s\n", $0) >"/dev/stderr";
    state=4; # i.e. we might now see stuff
    start_new_source_fragment = 0;
    source_fragment="";
    source_offset=0;
    filename_line=""
    next
}

$0 ~ filename_line_pattern {
    # This is *probably* a filename/line line.
    # It might also be a source line.
    # Note that we don't always get a filename/line line.
    # If we do, it means we're not getting a function name line
    
    # If we might be a filename/line line, suppose we are
    if (state == 4 || state == 2) {
        if (debug) printf("filename: %s\n", $0) >"/dev/stderr";
        # okay, suppose we are
        filename_line=$0
        if (state == 4) state=3;
        if (state == 2) state=1;
        start_new_source_fragment = 0;
        source_fragment="";
        source_offset=0;
        next
    } else {
        if (debug) printf("source1 : %s\n", $0) >"/dev/stderr";
        # treat it as a source line
        if (start_new_source_fragment) {
            start_new_source_fragment = 0;
            source_fragment="";
            source_offset=0;
        }
        source_fragment = source_fragment "\n" $0;
        source_offset += 1;
        state=1;
        next
    }
}

/.*\(\):$/ {
    # This is probably a function name line.
    # It might also be a source line.
    # Note that we don't always get a function name line.
    # If we do, it comes before the filename/line line
    # If we might be, suppose we are
    if (state == 3 || state == 4) {
        if (debug) printf("funname : %s\n", $0) >"/dev/stderr";
        function_line=$0;
        start_new_source_fragment = 0;
        source_fragment="";
        source_offset=0;
        filename_line="";
        state=2;
        next
    } else {
        if (debug) printf("source2 : %s\n", $0) >"/dev/stderr";
        # treat it as a source line
        if (start_new_source_fragment) {
            start_new_source_fragment = 0;
            source_fragment="";
            source_offset=0;
        }
        source_fragment = source_fragment "\n" $0;
        source_offset += 1;
        state=1;
        next
    }
}

/^[[:blank:]]*\.\.\.$/ {
    # seeing a "..." in disassembly output means a section break (maybe?); reset to state 4
    if (debug) printf("skip     : %s\n", $0) >"/dev/stderr";
    state=4;
    next
}

$0 !~ disassembly_line_pattern {
    # treat it as a source line
    if (debug) printf("source3 : %s\n", $0) >"/dev/stderr";
    if (start_new_source_fragment) {
        start_new_source_fragment = 0;
        source_fragment="";
        source_offset=0;
    }
    source_fragment = source_fragment "\n" $0;
    source_offset += 1;
    state=1;
    next
}

$0 ~ disassembly_line_pattern {
    # unpack the line a bit
    thisline_address=gensub(disassembly_line_pattern, "\\1", "");
    thisline_sym=gensub(disassembly_line_pattern, "\\2", "");
    thisline_offset=0 + gensub(disassembly_line_pattern, "\\3", "");
    # are we ready to output?
    if (next_disas_line_is_meta_return_addr) {
        return_addr_sym=thisline_sym
        return_addr=thisline_address
        return_addr_offset=sprintf("0x%x", thisline_offset)
        address=meta_instr_address
        addr2line_filename=gensub(filename_line_pattern, "\\1", "", meta_instr_filename_line)
        if (addr2line_filename == "") addr2line_filename="??";
        addr2line_line_number=gensub(filename_line_pattern, "\\2", "", meta_instr_filename_line)
        addr2line_next_line_number=addr2line_line_number + (meta_instr_source_offset == 0 ? 1 : meta_instr_source_offset)
        # the first ident following the last occurrence of "new" or "sizeof"
        token="$FAILED$"
        source_oneline=gensub("(\n|\t)", " ", "g", meta_instr_source_fragment)
        line_to_output=return_addr_sym "\t0x" return_addr "\t" return_addr_offset "\t0x" address "\t" addr2line_filename "\t" sprintf("%06d", addr2line_line_number) "\t" sprintf("%06d", addr2line_next_line_number) "\t" token "\t" source_oneline
        print line_to_output
        if (debug) printf("*OUTPUT*: %s\n", line_to_output) >"/dev/stderr";
    }
    # this is a disassembly line, but does it match the meta-instr regexp?
    if ($0 ~ meta_instr_regexp) {
        if (debug) printf("*META*  : %s\n", $0) >"/dev/stderr";
        # latch the meta-instr stuff
        meta_instr_address=gensub(disassembly_line_pattern, "\\1", "");
        meta_instr_sym=gensub(disassembly_line_pattern, "\\2", "");
        meta_instr_offset=gensub(disassembly_line_pattern, "\\3", "");
        meta_instr_filename_line=filename_line
        meta_instr_source_offset=source_offset
        meta_instr_source_fragment=source_fragment
        next_disas_line_is_meta_return_addr=1
    } else {
        if (debug) printf("disass  : %s\n", $0) >"/dev/stderr";
        next_disas_line_is_meta_return_addr=0
    }
    
    state=4
}
