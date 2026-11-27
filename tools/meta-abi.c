/* Linked into every -meta.so */
#include "meta-abi.h"

#ifdef LIBALLOCS_META_ABI_VERSION_OVERRIDE /* for testing */
#undef LIBALLOCS_META_ABI_VERSION
#define LIBALLOCS_META_ABI_VERSION LIBALLOCS_META_ABI_VERSION_OVERRIDE
#endif

const unsigned __liballocs_meta_abi_version = LIBALLOCS_META_ABI_VERSION;
