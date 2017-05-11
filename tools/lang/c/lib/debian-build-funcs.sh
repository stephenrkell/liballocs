export UNIQTYPES_BASE=/usr/lib/meta
export LD_PRELOAD=${HOME}/work/devel/liballocs.hg/lib/libheap_index_fast_hooks.so
if [[ -z "$( echo "$PATH" | tr ':' '\n' | grep '/cil[^/]*/bin' )" ]]; then
   export PATH=/usr/local/src/cil/bin:${PATH}
fi
export LIBALLOCS_ALLOC_FNS="xcalloc(zZ) xmalloc(Z) xrealloc(pZ) xmallocz(Z)"

rebuild_debian () {
    find -name '*.cil.*' -o -name '*.i' -o -name '*.allocs' -type f | xargs rm -f
    DEB_LDFLAGS_APPEND="-L${HOME}/work/devel/liballocs.hg/lib -Wl,-R$( readlink -f ${HOME}/work/devel/liballocs.hg/lib ) -Wl,--no-add-needed -lallocs -Wl,--add-needed -ldl -Wl,--allow-shlib-undefined" \
        CC=${HOME}/work/devel/liballocs.hg/tools/lang/c/bin/allocscc \
        DEB_BUILD_OPTIONS="nostrip" dpkg-buildpackage 2>&1 | tee build.log
}

redo_git_tests () {
    CC=${HOME}/work/devel/liballocs.hg/tools/lang/c/bin/allocscc make -C t/ all
}

# DEB_LDFLAGS_APPEND="-L${HOME}/work/devel/typiklee.hg/lib \-Wl,-R$( readlink -f ${HOME}/work/devel/typiklee.hg/lib ) -Wl,-Bdynamic -Wl,--as-needed -lallocs -ldl -Wl,--dynamic-list -Wl,dynamic-list -Wl,--allow-shlib-undefined -Wl,--no-as-needed" \
