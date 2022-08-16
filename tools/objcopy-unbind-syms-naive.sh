#!/bin/bash

obj="$1"
shift

curobj="$obj"
LD="${LD:-ld}"
AS="${AS:-as}"
STRIP="${STRIP:-strip}"
OBJCOPY="${OBJCOPY:-objcopy}"
ourdir="$( mktemp -d )"
mktempobj () {
   mktemp -p "$ourdir" --suffix .o "$@"
}
SYM2UND=/home/stephen/work/devel/elftin.hg/abs2und/sym2und

bail () {
   local sym="$1"
   local status="$2"
   printenv | grep "obj=" 1>&2
   echo "processing $sym, subcommand returned $status" 1>&2
   exit $status
}

for sym in "$@"; do
    newobj="$(mktempobj newtmp.XXX )"
    # create a 'def' alias
    ${LD} -r -o "$newobj" --defsym __def_$sym=$sym "$curobj" || bail $sym $?
    objdump -t "$newobj" 1>&2
    # turn the ABS into UND
    undobj="$(mktempobj undtmp.XXX )"
    cp "$newobj" "$undobj" || bail $sym $?
    ${SYM2UND} "$undobj" "$sym" || bail $sym $?
    objdump -t "$undobj" 1>&2
    # rename the 'sym' into '__ref_'
    refobj="$(mktempobj reftmp.XXX )"
    cp "$undobj" "$refobj" || bail $sym $?
    ${OBJCOPY} --redefine-sym "$sym"=__ref_"$sym" "$refobj" || bail $sym $?
    objdump -t "$refobj" 1>&2
    curobj="$refobj"
done

mv "$curobj" "$obj"
rm -rf "$ourdir"
