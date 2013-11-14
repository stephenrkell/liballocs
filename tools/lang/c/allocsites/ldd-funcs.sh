# NOTE: use /bin/echo
# because we get invoked from make, as sh
# hence invoking POSIX behaviour
# in which echo -e and echo -n aren't supported.
# Similarly, $'...' is not supported

# In short, in this file, stay POSIX-compatible!

exec_text_addr=0x0 #0400000

obj_load_addrs () {
    setarch $( uname -m ) -R sh -c 'LD_TRACE_LOADED_OBJECTS=1 '"$1" 2>&1 | \
    grep '=>' | grep -v 'linux-vdso' | grep -v 'not found' | \
    sed 's/.*=> //' | tr -d '()' | \
    tr -s '[:blank:]' '\t'
    /bin/echo -n "$( readlink -f "$1" )"
    /bin/echo -e '\t'"${exec_text_addr}"
}

mangle_objname () {
    #echo "asked to mangle: $1" 1>&2
    echo "$1" | tr '/ .-' '_'
}

# Not necessary for bash, but necessary for sh
hex_to_dec () {
    printf "%d" $( echo "$1" | sed 's/^[^0][^xX].*/0x&/' )
}

obj_load_addrs_as_cpp_macros () {
    #echo "asked for: $1" 1>&2
    # We MUST output in sorted order, because allocsmt relies on this.
    # HACK: this is for debugging weird process layout that we get when
    # running ldd from dash. Have hacked around it for now....
    #printenv 1>&2
    #cat /proc/$$/maps 1>&2
    #cat /proc/$PPID/maps 1>&2
    #ldd "$1" 1>&2
    obj_load_addrs "$1" | sort | while read obj base; do 
        #echo "obj is: $obj" 1>&2
        #echo "base is $base" 1>&2
        echo "-D__LOAD_ADDR_$( mangle_objname "${obj}" | tr '[a-z]' '[A-Z]' )"="${base}ULL"
        #min_obj_load_addr=0x7eff00000000
        min_obj_load_addr=0x2aaa00000000
        if [ $( hex_to_dec $base ) -lt $( hex_to_dec $min_obj_load_addr ) ] && ! [ $( hex_to_dec $base ) -eq $( hex_to_dec ${exec_text_addr} ) ]; then
            echo "Warning: library $obj has a load address $base less than the assumed minimum $min_obj_load_addr" 1>&2
        fi
    done
}
