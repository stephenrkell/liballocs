#!/bin/sh

if [ $# -lt 1 ]; then echo "Please specify a filename" 1>&2; exit 1; fi

# We want to print one line of output
# for every symlink that needs to be resolved
# when calculating the canonical ("realpath", "readlink -f") path
# for a given input pathname.
# Ideally, the existing tools would give us this, but they don't.

resolve_one_and_maybe_print () {
    local already_resolved_d="$1"
    local name="$2"
    if [ "$already_resolved_d" != "$(readlink -f "$already_resolved_d")" ]; then
        echo "Error: resolve_one_and_maybe_print received not-fully-resolved first argument ($1)" 1>&2; exit 1
    fi
    # "name" is not allowed to include '/'
    case "$name" in
        (*/*) echo "Error: we should not ask ourselves to resolve multi-hop relative paths" 1>&2; exit 1 ;;
        (*) true ;;
    esac
    readlink_out="$( cd "$already_resolved_d" && readlink "$name" )"
    if [ $? -eq 0 ]; then
       # a symlink was involved
       case "$already_resolved_d" in
           ('/') lhs="/$name"; d_prefix='/' ;;
           (*'/') echo "Internal error: non-root already_resolved_d must not end in a slash" 1>&2; exit 1 ;;
           (*)   lhs="$already_resolved_d/$name"; d_prefix="$already_resolved_d"/ ;;
       esac
       case "$readlink_out" in
           ('')  # hmm
              echo "Error: readlink succeeded but no output?" 1>&2; exit 1
           ;;
           (/*)
              # PROBLEM: if readlink's output itself names a symlink, we're not finished yet.
              # We may need to recursively resolve_all. Might this cause an infinite recursion?
              # YES, if we have a symlink cycle, of course.
              # FIXME: keep a global array of what we've been asked to resolve. If the same
              # thing comes up twice, abort with the equivalent of ELOOP.
              printf "%s\\tabsolute\\t%s\\n" "$lhs" "$readlink_out"
              resolve_all "$readlink_out"
           ;;
           (*)
              printf "%s\\trelative from %s\\t%s\\n" "$lhs" "${d_prefix}" "${readlink_out}"
              # We don't have to resolve_all, but we still recurse
              # FIXME: what if "readlink_out" has a chain of components?
              # We will hit the error above: multi-hop relative paths.
              # So we may need an iterative rather than our recursive approach below
              if [ -h "${d_prefix}${readlink_out}" ]; then
                  resolve_one_and_maybe_print "$already_resolved_d" "$readlink_out"
              fi
           ;;
       esac
    fi
}

resolve_all () {
    # recursively resolve the dirname and basename...
    # our base case is if the dirname is '/'
    local d="$( dirname "$1" )"
    local b="$( basename "$1" )"
    case "$d" in
        ('.') echo "Error: got relative path but expected absolute" 1>&2; exit 1
        ;;
        ('/') # OK, no symlinks in the directory part so our recursion has bottomed out
              resolve_one_and_maybe_print "/" "$b"
              # ... then return to the caller so it can append its "$b"'s resolution, etc.
        ;;
        (*)   resolve_all "$d"; resolve_one_and_maybe_print "$( readlink -f "$d" )" "$b"
        ;;
    esac
}

case "$1" in
    ('') echo "Empty filename!" 1>&2; exit 1 ;;
    (/*) # it's already absolute
         resolve_all "$1" ;;
    (*)  resolve_all "`pwd`"/"$1" ;;
esac
