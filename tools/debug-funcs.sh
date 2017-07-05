# NOTE: these functions use lots of GNU bashisms.

echo_then_sudo () {
    echo "About to execute privileged command: $@" 1>&2
    sudo -k "$@"
}

# $1: the object file to fixup
# $2: the real location of its debug info
fixup_debuglink () {
    echo "begin fixup_debuglink" 1>&2
    obj="$1"
    debuglink="$2"
    current_debuglink="$( read_debuglink "$obj" )"
    has_debuglink=$?
    
    if [[ $has_debuglink -eq 0 ]] && [[ "$current_debuglink" == "$debuglink" ]]; then
        echo "detected that debuglink $debuglink_value is already valid" 1>&2
        return 0
    else
        if [[ $has_debuglink -eq 0 ]]; then 
            echo "detected that debuglink $current_debuglink needs fixing up to $debuglink" 1>&2
            # For safety, we use a tempfile
            tmpfile="$(mktemp)"
            saved_ug="$( stat -c "%u:%g" "$( readlink -f "$obj" )" )"
            saved_mode="$( stat -c "%a" "$( readlink -f "$obj" )" )"
            (echo_then_sudo objcopy --remove-section .gnu_debuglink "$obj" "$tmpfile" && \
            echo_then_sudo chown "$saved_ug" "$tmpfile" && \
            echo_then_sudo chmod "$saved_mode" "$tmpfile" && \
            echo_then_sudo mv "$tmpfile" "$obj" ) || \
            echo "objcopy failed" 1>&2; return 1
        fi
        # now there is no debuglink, so add one
        # For safety, we use a tempfile
        tmpfile="$(mktemp)"
        saved_ug="$( stat -c "%u:%g" "$( readlink -f "$obj" )" )"
        saved_mode="$( stat -c "%a" "$( readlink -f "$obj" )" )"
        echo_then_sudo objcopy --add-gnu-debuglink="$debuglink" "$obj" "$tmpfile" && \
            echo_then_sudo chown "$saved_ug" "$tmpfile" && \
            echo_then_sudo chmod "$saved_mode" "$tmpfile" && \
            echo_then_sudo mv "$tmpfile" "$obj" && \
            echo "success" 1>&2 && return 0 || \
            (echo "objcopy failed" 1>&2; return 1)
    fi
}

contains_debug_symbols () {
    objdump -h "$1" | grep '\.debug_info' 1>/dev/null 2>/dev/null
}

read_debuglink () {
    debuglink_info="$( objdump -h "$1" | grep '\.gnu_debuglink' )"
    if [[ -z "$debuglink_info" ]]; then
        echo "no debuglink in $1" 1>&2
        return 1
    fi
    debuglink_off="$( echo "$debuglink_info" | sed 's/^[[:blank:]]*//' | tr -s '[:blank:]' '\t' | cut -f6 )"
    echo "read debuglink_off: $debuglink_off" 1>&2
    if [[ -n "$debuglink_off" ]]; then
        debuglink_off_bytes=$(( 0x$debuglink_off + 0 ))
        if [[ -z "$debuglink_off_bytes" ]]; then
            echo "bad debuglink header" 1>&2 
            return 1
        else
            od --skip-bytes=${debuglink_off_bytes} --string "$1" | head -n1 | sed 's/^[0-9a-f]* //'
            return 0
        fi
    fi
    return 1
}

find_debug_file_for () {
    file="$1"
    # handle the case where there's no DWARF in the file, but is a debug link
    if ! readelf -wi "$file" | grep -m1 . >/dev/null; then
        debuglink_val="$( read_debuglink "$file" )"
        if [[ -n "$debuglink_val" ]]; then
            echo "Read debuglink val: $debuglink_val" 1>&2
            resolved_debuglink="$( resolve_debuglink "$file" "$debuglink_val" )"
            echo "Resolved debuglink to: $resolved_debuglink" 1>&2
            echo "$resolved_debuglink"
        else
            echo "No debuglink found" 1>&2
            echo "$file"
        fi
    else
        echo "$file"
    fi
}

readelf_debug () {
    declare -a args
    ctr=1
    while true; do
        args[$ctr]=$1
        shift || break;
        ctr=$(( $ctr + 1 ))
    done
    file=${args[$(( $ctr - 1 ))]}
    echo "Slurped args: ${args[@]}" 1>&2
    echo "Guessed file arg: $file" 1>&2
    unset args[$(( $ctr - 1 ))]
    readelf ${args[@]} "$( find_debug_file_for "$file" )"
}

get_cu_info () {
    readelf_debug -wi "$1" | grep -A7 'DW_TAG_compile_unit' | tr '\n' '\f' | sed 's/\f--\f/\n/g'
}

read_cu_info () {
    read cu_info
    ret=$?
    if [[ -n "$cu_info" ]]; then
        cu_fname="$( echo "$cu_info" | tr '\f' '\n' | grep DW_AT_name | head -n1 | sed 's/.*DW_AT_name[[:blank:]]*:[[:blank:]]*\((.*, offset: 0x[0-9a-f]*): \)\?\(.*\)/\2/' | sed 's/[[:blank:]]*$//')"
        cu_language_fullstr="$( echo "$cu_info" | tr '\f' '\n' | grep DW_AT_language | head -n1 | sed 's/.*DW_AT_language[[:blank:]]*:[[:blank:]]*//' | sed 's/[[:blank:]]*$//')"
        echo "Note: found CU $cu_fname" 1>&2
        echo "CU info is: $cu_info" 1>&2
        echo "language field of CU info is $( echo "$cu_language_fullstr" )" 1>&2
        echo "comp_dir line of CU info is $( echo "$cu_info" | tr '\f' '\n' | grep DW_AT_comp_dir )" 1>&2
        cu_compdir="$( echo "$cu_info" | tr '\f' '\n'  | grep DW_AT_comp_dir | sed 's/.*DW_AT_comp_dir[[:blank:]]*:[[:blank:]]*\((.*, offset: 0x[0-9a-f]*): \)\?\(.*\)/\2/' | sed 's/[[:blank:]]*$//' )"
        echo "Note: found comp_dir $cu_compdir" 1>&2
        # don't prepend compdir if cu_fname is fully-qualified
        case "$cu_fname" in
            (/*)
                cu_sourcepath="${cu_fname}"
                ;;
            (*)
                cu_sourcepath="${cu_compdir}/${cu_fname}"
                ;;
        esac
        cu_language_num="$( echo "$cu_language_fullstr" | tr -s '[[:blank:]]' '\t' | cut -f1 )"
    else
        cu_fname=""
        cu_language_fullstr=""
        cu_compdir=""
        cu_sourcepath=""
        cu_language_num=""
    fi

    if [[ $ret -eq 0 ]]; then true; else false; fi
}

resolve_debuglink () {
    obj="$1"
    debuglink_value="$2"
    
    canon_obj_path="$( readlink -f "$obj" )"

    for candidate in "$( dirname "$canon_obj_path" )/.debug/$debuglink_value" \
       /usr/lib/debug"$( dirname ${canon_obj_path} )"/$debuglink_value \
       /usr/lib/debug/.build-id/*/$debuglink_value; do
        if contains_debug_symbols "$candidate"; then
            echo "detected debug info within debuglink $debuglink_value resolved at $candidate" 1>&2
            echo "$candidate"
            return 0
        fi
    done
    
    return 1
}

ensure_debug_symbols () {
    obj="$1"
    # do we have debug symbols already?
    if contains_debug_symbols "$obj"; then 
        echo "detected debug info within file $obj" 1>&2
        echo "$1"
        return 0
    fi
    
    # no; do we have a working .gnu_debuglink?
    if debuglink_value="$( read_debuglink "$obj" )"; then
        resolved_debuglink="$( resolve_debuglink "$obj" "$debuglink_value" )"
        if [[ -n "$resolved_debuglink" ]] && contains_debug_symbols "$resolved_debuglink"; then
            echo "detected debug info within debuglink $debuglink_value resolved at $candidate" 1>&2
            echo "$candidate"
            return 0
        fi
        # else we failed to resolve a good debuglink
    fi

    
    # if we got here, then 
    # if there is a debuglink entry, it is bad, so we don't know where to find the debug info.
    # See if we can install it. 

#    # no; does the debuglink fix up trivially (by rel=>abs path rewriting)?
#    case "$debuglink_value" in
#        (/*)
#            # already relative, so no
#            ;;
#        ('') # no value, so no
#            ;;
#        (*)
#            # maybe... try it
#            guessed_abs_debuglink="$( dirname "$(readlink -f "$obj" )" )/$debuglink_value"
#            if contains_debug_symbols "$guessed_abs_debuglink"; then
#                echo "detected debug info within relative-addressed debuglink'd file $guessed_abs_debuglink" 1>&2
#                if fixup_debuglink "$obj" "$guessed_abs_debuglink"; then
#                    echo "success" 1>&2
#                    echo "$guessed_abs_debuglink"
#                    return 0
#                else
#                    echo "failed" 1>&2
#                    return 1
#                fi
#            else
#                true # doesn't contain debug symbols, so continue 
#            fi
#            ;;
#    esac
#    
#    # if we got here, then rel=>abs rewriting didn't work out
#    # So try /usr/lib/debug...
#    for attempt in \
#    /usr/lib/debug"$( readlink -f "$1" )" \
#    /usr/lib/debug"$( dirname "$( readlink -f "$1" )" )/$( basename "$1" )" ; do 
#        if contains_debug_symbols "$attempt"; then
#            if ! fixup_debuglink "$obj" "$attempt"; then
#                echo "failed" 1>&2
#                return 1
#            else
#                # else succeeded
#                echo "$attempt"
#                return 0
#            fi
#            # else might have one more to try...
#        fi
#    done
    
    # If no, does some Debian package provide the /usr/lib/debug files?
    success_attempt=""
    #echo_then_sudo apt-file update || ( echo "apt-file failed! please install it" 1>&2; return 1 )
    for attempt in \
    /usr/lib/debug"$( readlink -f "$obj" )" \
    /usr/lib/debug"$( dirname "$( readlink -f "$obj" )" )/$( basename "$obj" )" ; do 
        echo "looking for a package containing $attempt" 1>&2
        apt_found="$( echo_then_sudo apt-file -F find "$attempt" | sed 's^: /.*^^' )"
        if [[ -n "$apt_found" ]]; then
            pkg="$( echo "$apt_found" | cut -f1 )"
            echo "found $pkg" 1>&2
            if [[ -n "$pkg" ]]; then
                if dpkg -p "$pkg" >/dev/null 2>/dev/null; then
                    echo "$pkg is already installed" 1>&2
                else
                    echo "Attempting install of $pkg" 1>&2
                    if ! echo_then_sudo apt-get install "$pkg"; then
                        echo "install failed" 1>&2
                        return 1
                    fi
                    # now we have it installed
                fi
                if contains_debug_symbols "$attempt"; then
                    # this is promising -- work out what the debuglink should say
                    correct_debuglink="$( basename "$( readlink -f "$attempt" )" )"
                    echo "debuglink should say $correct_debuglink" 1>&2
                    if ! fixup_debuglink "$obj" "$attempt"; then
                        echo "failed" 1>&2
                        return 1 
                    fi
                    # else succeeded -- check that debuglink is now correct_debuglink
                    verify_debuglink="$( read_debuglink "$obj" )"
                    if [[ "$verify_debuglink" == "$correct_debuglink" ]]; then
                        echo "$attempt" 
                        return 0
                    else
                        echo "debuglink not fixed up properly" 1>&2
                        return 1
                    fi
                else 
                    echo "installed package unexpectedly lacked debug info" 1>&2
                    return 1
                fi
            else # -z "$pkg"
                echo "apt-file printed something strange" 1>&2
                continue
            fi
        else
            # apt-file didn't find anything, so continue
            echo "package not found" 1>&2
            continue
        fi
    done
    
    # If we got here, we're really stuck!
    echo "giving up" 1>&2
    return 1
}

ensure_debug_source () {
    obj="$1"
    # look up some source path in the debug info; does it exist?
    first_compile_unit_context="$( readelf -wi "$obj" | grep -m1 -A5 compile_unit )" #"
    compile_unit_name="$( echo "$first_compile_unit_context" | grep DW_AT_name | \
        sed 's/.*DW_AT_name.*indirect string, offset: 0x[0-9a-f]\+): //' | sed 's/[[:blank:]]*$//' )" #"

    # HACK: readelf space-pads its output, annoyingly,
    # so we assume compilation file/directory names don't end in space

    echo "extracted CU name: $compile_unit_name" 1>&2
    comp_dir="$( echo "$first_compile_unit_context" | grep comp_dir | \
        sed 's/.*DW_AT_comp_dir.*(indirect string, offset: 0x[0-9a-f]\+): //' | sed 's/[[:blank:]]*$//'  )" #"
    echo "extracted compilation directory: $comp_dir" 1>&2
    
    # does the given file exist in the given dir?
    if [[ -r "${comp_dir}/${compile_unit_name}" ]]; then
        echo "guessing that source does exist already" 1>&2
        return 0
    else
        echo "source does not exist already" 1>&2
    fi
    
    # no; download the source using apt-get source `dpkg -S ... `
    if [[ -z "$DPKG_SOURCE_ROOT" ]]; then
        DPKG_SOURCE_ROOT="$( mktemp -d )"
    fi
    echo "downloading source to $DPKG_SOURCE_ROOT" 1>&2
    
    ( 
        cd "$DPKG_SOURCE_ROOT"
        owning_package="$( dpkg -S "$obj" | sed 's^: /.*^^' )" || (echo "failed to identify owning package" 1>&2; return 1)
        apt-get source "$owning_package" || (echo "failed to download source" 1>&2; return 1)
        source_dirname="$( ls -t | head -n1 )"
        echo "guessing source was extracted in $source_dirname" 1>&2

        # now match some known cases of source prefixes
        case "$comp_dir" in
            (/build/buildd/*)
                echo "found a buildd build" 1>&2
                source_dirname_escaped="$( echo "$source_dirname" | escape_regexp_floating )" #"
                prefix="$( echo "$comp_dir" | sed "s^\(.*/${source_dirname_escaped}/\).*^\1^" )"
                echo "calculated source path prefix $prefix" 1>&2
                # we want to create a link s.t. prefix points to source_dirname
                echo_then_sudo mkdir -p "$( dirname "$prefix" )" && \
                echo_then_sudo ln -s "$source_dirname" "$prefix" || \
                ( echo "failed to mkdir or symlink" 1>&2; return 1)
                echo "success" 1>&2
                return 0
            ;;
            (*)
                echo "package was built at bad source directory" 1>&2 
                return 1
            ;;
        esac
    )
}
