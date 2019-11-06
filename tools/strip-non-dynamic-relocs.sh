#!/bin/bash

ctr=0
declare -a sects
while read sect; do
	args[$ctr]="-R"
        ctr=$(( $ctr + 1 ))
	args[$ctr]="$sect"
        ctr=$(( $ctr + 1 ))
done <<< "$(
readelf -WS "$1" 2>/dev/null | grep '\[[^\]*\]' | grep -v '\[Nr\]' | sed 's/\[[^\]*\]//' | while read name type address off size es flg lk inf al; do
	case "${type}_${flg}" in
            (RELA_*A*|REL_*A*) # we don't want allocatable reloc sections
               ;;
            (RELA_*|REL_*)     # we do want other reloc sections
               echo "$name" ;;
            (*) ;;             # we don't want other sections
        esac
done )"

strip "${args[@]}" "$1"
