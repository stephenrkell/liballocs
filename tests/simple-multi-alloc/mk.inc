CFLAGS += $(shell pkg-config --cflags glib-2.0)
LDLIBS += $(shell pkg-config --libs glib-2.0)

# FIXME: don't make the user specify these
export LIBCRUNCH_ALLOC_FNS := xmalloc(Z)p xcalloc(zZ)p xrealloc(pZ)p
export LIBCRUNCH_FREE_FNS := xfree(P)
export LIBCRUNCH_SUBALLOC_FNS := g_slice_alloc(Z)p g_slice_alloc0(Z)p
export LIBCRUNCH_SUBFREE_FNS := g_slice_free1(zP)->g_slice_alloc
