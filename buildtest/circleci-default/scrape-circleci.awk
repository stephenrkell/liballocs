BEGIN {
    begin_marker_marker = "# MARKER BEGIN ([A-Z_]*)( +\\+([0-9]+)( +([^[:blank:]]+))?)?"
    end_marker_marker = "# MARKER END ([A-Z_]*)"
    skipctr=0
    regex=""
}

$0 ~ begin_marker_marker {
    curvar=gensub("[[:blank:]]*" begin_marker_marker, "\\1", 1)
    skipctr=0 + gensub("[[:blank:]]*" begin_marker_marker, "\\3", 1)
    regex=gensub("[[:blank:]]*" begin_marker_marker, "\\5", 1)
    printf("applying regex %s\n", regex)>"/dev/stderr"
    lines=""
    next
}

$0 ~ end_marker_marker {
    print_one();
}

function print_one() {
    printf("export %s=\"%s\"\n", curvar, lines);
    lines=""
    curvar=""
    regex=""
}

{
    if (curvar && skipctr == 0) { lines = (lines ? (lines "\n") : "") gensub(regex ? ".*" regex ".*" : "(.*)", "\\1", 1); }
    else if (curvar && skipctr > 0) { --skipctr; }
}

END {
    if (curvar) print_one();
}
