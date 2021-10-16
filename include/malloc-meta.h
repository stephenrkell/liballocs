#ifndef LIBALLOCS_MALLOC_META_H_
#define LIBALLOCS_MALLOC_META_H_

/* NOTE: this file gets included by liballocs_cil_inlines.h
 * so needs to be written to be tolerant of many versions of C. */

#ifndef offsetof
#define __liballocs_defined_offsetof
#define offsetof(type, member) (__builtin_offsetof(type, member))
#endif

/* HACK: copied from memtable.h. */
/* Thanks to Martin Buchholz -- <http://www.wambold.com/Martin/writings/alignof.html> */
#ifndef ALIGNOF
#if __STDC_VERSION__ >= 201112L
#define ALIGNOF _Alignof
#else
#define ALIGNOF(type) offsetof (struct { char c; type member; }, member)
#endif
#endif
#ifndef PAD_TO_ALIGN
#define PAD_TO_ALIGN(n, a) 	((0 == ((n) % (a))) ? (n) : (n) + (a) - ((n) % (a)))
#endif

/* Add the size of struct insert, and round this up to the align of struct insert.
 * This ensure we always have room for an *aligned* struct insert. */
#define CHUNK_SIZE_WITH_TRAILER(sz, trailer_t, trailer_align_t) \
    PAD_TO_ALIGN(sz + sizeof (trailer_t), ALIGNOF(trailer_align))

#endif
