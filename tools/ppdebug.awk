#!/usr/bin/gawk -bf
# here we enable ^"treat-characters-as-bytes" because...
# it makes the code go faster

# This script filters the preprocessed (.i) C source file
# named by ARGV[1], and outputs a version that "hides" source
# files whose name matches the pattern in ARGV[1].
# It rewrites the #line or #... directives so that debugging
# the generated code will instead show the preprocessed file.

BEGIN {
    infile=ARGV[1];
    filepat=ARGV[2];
    printf("infile is %s\n", infile)>"/dev/stderr"
    printf("filepat is %s\n", filepat)>"/dev/stderr"
    if (ARGC != 3) {
        printf("Please specify (just) an input filename and a file pattern.\n") >"/dev/stderr";
        exit 1;
    }
    # awk will read files named in ARGV. so remove filepat from it
    ARGV[2]="";
    # count the lines in the input file
    inlinenum=0;
    do_rewrite=0;
    # KEEP the brackets on these patterns so that \1 and \4 etc. are
    # the logically equivalent components (line number, filename)
    compiler_internal_linepat="^# *([0-9]+)( *)(\"([^\"]*)\")";
    preprocessor_linepat="^#line ([0-9]+)( *(\"([^\"]*)\"))?";
}

{
    ++inlinenum;
}

$0 ~ compiler_internal_linepat {
    filename=gensub(compiler_internal_linepat, "\\4", 1);
    line=gensub(compiler_internal_linepat, "\\1", 1);
    insert=""
    if (filename ~ filepat) do_rewrite=1; else do_rewrite=0;
}

$0 ~ preprocessor_linepat {
    filename=gensub(preprocessor_linepat, "\\4", 1);
    line=gensub(preprocessor_linepat, "\\1", 1);
    insert=""
}

$0 !~ compiler_internal_linepat && $0 !~ compiler_internal_linepat {
    print $0
    next
}

# if we got here, we have a directive that we'd like to rewrite...
# if we're already referring
{
    if (do_rewrite == 1) {
        printf("#%s %d \"%s\"\n", insert, inlinenum+1, infile);
    }
    else print $0
}
