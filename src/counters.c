#define _GNU_SOURCE

#include <errno.h>
#include "liballocs.h"
#include "liballocs_private.h"

struct addrlist __liballocs_unrecognised_heap_alloc_sites = { 0, 0, NULL };

struct liballocs_err __liballocs_err_stack_walk_step_failure 
 = { "stack walk reached higher frame" };
struct liballocs_err __liballocs_err_stack_walk_reached_higher_frame 
 = { "stack walk reached higher frame" };
struct liballocs_err __liballocs_err_stack_walk_reached_top_of_stack 
 = { "stack walk reached top-of-stack" };
struct liballocs_err __liballocs_err_unknown_stack_walk_problem 
 = { "unknown stack walk problem" };
struct liballocs_err __liballocs_err_unindexed_heap_object
 = { "unindexed heap object" };
struct liballocs_err __liballocs_err_unindexed_alloca_object
 = { "unindexed alloca object" };
struct liballocs_err __liballocs_err_unrecognised_alloc_site
 = { "unrecognised alloc site" };
struct liballocs_err __liballocs_err_unrecognised_static_object
 = { "unrecognised static object" };
struct liballocs_err __liballocs_err_object_of_unknown_storage
 = { "object of unknown storage" };

/* Counters -- these are mostly liballocs-internal and therefore hidden,
 * but the ones to do with heap allocation might get ref'd from other
 * DSOs. Also we may find that we want ot inline some paths
 * into clients, in which case others may have to become more visible. */
unsigned long __liballocs_aborted_stack __attribute__((visibility("hidden")));;
unsigned long __liballocs_aborted_static __attribute__((visibility("hidden")));;
unsigned long __liballocs_aborted_unknown_storage __attribute__((visibility("hidden")));;
unsigned long __liballocs_hit_heap_case __attribute__((visibility("protected")));
unsigned long __liballocs_hit_alloca_case __attribute__((visibility("hidden")));;
unsigned long __liballocs_hit_stack_case __attribute__((visibility("hidden")));;
unsigned long __liballocs_hit_static_case __attribute__((visibility("hidden")));;
unsigned long __liballocs_aborted_unindexed_heap __attribute__((visibility("protected")));;
unsigned long __liballocs_aborted_unindexed_alloca __attribute__((visibility("hidden")));;
unsigned long __liballocs_aborted_unrecognised_allocsite __attribute__((visibility("protected")));;

__attribute__((visibility("hidden")))
void print_exit_summary(void)
{
	if (__liballocs_aborted_unknown_storage + __liballocs_hit_static_case + __liballocs_hit_stack_case
			 + __liballocs_hit_heap_case + __liballocs_hit_alloca_case > 0)
	{
		fprintf(get_stream_err(), "====================================================\n");
		fprintf(get_stream_err(), "liballocs summary: \n");
		fprintf(get_stream_err(), "----------------------------------------------------\n");
		fprintf(get_stream_err(), "queries aborted for unknown storage:       % 9ld\n", __liballocs_aborted_unknown_storage);
		fprintf(get_stream_err(), "queries handled by static case:            % 9ld\n", __liballocs_hit_static_case);
		fprintf(get_stream_err(), "queries handled by stack case:             % 9ld\n", __liballocs_hit_stack_case);
		fprintf(get_stream_err(), "queries handled by heap case:              % 9ld\n", __liballocs_hit_heap_case);
		fprintf(get_stream_err(), "queries handled by alloca case:            % 9ld\n", __liballocs_hit_alloca_case);
		fprintf(get_stream_err(), "----------------------------------------------------\n");
		fprintf(get_stream_err(), "queries aborted for unindexed heap:        % 9ld\n", __liballocs_aborted_unindexed_heap);
		fprintf(get_stream_err(), "queries aborted for unknown heap allocsite:% 9ld\n", __liballocs_aborted_unrecognised_allocsite);
		fprintf(get_stream_err(), "queries aborted for unindexed alloca:      % 9ld\n", __liballocs_aborted_unindexed_alloca);
		fprintf(get_stream_err(), "queries aborted for unknown stackframes:   % 9ld\n", __liballocs_aborted_stack);
		fprintf(get_stream_err(), "queries aborted for unknown static obj:    % 9ld\n", __liballocs_aborted_static);
		fprintf(get_stream_err(), "====================================================\n");
		for (unsigned i = 0; i < __liballocs_unrecognised_heap_alloc_sites.count; ++i)
		{
			if (i == 0)
			{
				fprintf(get_stream_err(), "Saw the following unrecognised heap alloc sites: \n");
			}
			fprintf(get_stream_err(), "%p (%s)\n", __liballocs_unrecognised_heap_alloc_sites.addrs[i], 
					format_symbolic_address(__liballocs_unrecognised_heap_alloc_sites.addrs[i]));
		}
	}
	
	if (getenv("LIBALLOCS_DUMP_SMAPS_AT_EXIT"))
	{
		char buffer[4096];
		size_t bytes;
		FILE *smaps = fopen("/proc/self/smaps", "r");
		if (smaps)
		{
			while (0 < (bytes = fread(buffer, 1, sizeof(buffer), smaps)))
			{
				fwrite(buffer, 1, bytes, get_stream_err());
			}
		}
		else fprintf(get_stream_err(), "Couldn't read from smaps!\n");
	}
}
