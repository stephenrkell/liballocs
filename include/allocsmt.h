#ifndef LIBALLOCS_ALLOCSMT_H_
#define LIBALLOCS_ALLOCSMT_H_

struct uniqtype;
struct allocsite_entry
{ 
	void *next; 
	void *prev;
	void *allocsite; 
	struct uniqtype *uniqtype;
};
struct frame_allocsite_entry
{
	unsigned offset_from_frame_base;
	struct allocsite_entry entry;
};
struct static_allocsite_entry
{
	const char *name;
	struct allocsite_entry entry;
};
/* allocsmt is a memtable lookup mainly because it's easy 
 * and reduces code dependencies. In particular, it's easy to 
 * initialize using a single linear scan, assuming that allocsites info
 * is sorted in address order within each bucket.
 * 
 * (If we wanted to initialize a hash table, the nondeterminism would
 * randomise the order and require keeping an extra data structure
 * during this scan, namely a bucket_tails[..] array. We could still
 * chain as we go along under this approach, though.)
 *
 * Notes about sizing the memtable:
 * 
 * - the bucket may not cover more than 4KB, because we need each 
 *   bucket to cover allocations in a single unique dynamic object. 
 *
 * - one memtable entry is 8 bytes, so one 4KB page of memtable would 
 *   map 512 8-byte pointers to allocsite buckets
 *
 * - supposing that 4KB of memtable should cover at least 32KB of program
 *   text (for VAS-efficiency), then each bucket would cover 1/512 of that, 
 *   i.e. 2^6 i.e. 64 bytes, which is pretty damn good and well within our 4KB limit. 
 *   We bump it up to 256 instruction bytes. This is a "factor of 32" memtable,
 *   i.e. takes 1/32 of the VAS range it covers. 
 *
 * - then we quadruple the size of the whole thing, to allow up to four
 *   different "allocation site spaces". Currently we use only three of them: 
 *   heap allocation sites (|0), stack frame vaddr ranges (|STACK_BEGIN)
 *   and static object base addresses (|STACK_BEGIN<<1).
 */
 
#include "vas.h"

#define allocsmt_entry_type          struct allocsite_entry *
#define allocsmt_entry_coverage      256
extern allocsmt_entry_type *__liballocs_allocsmt;
#define ALLOCSMT_FUN(op, ...)    (MEMTABLE_ ## op ## _WITH_TYPE(__liballocs_allocsmt, allocsmt_entry_type, \
    allocsmt_entry_coverage, (void*)0, (void*)(0x800000000000ul << 2), ## __VA_ARGS__ ))


#endif
