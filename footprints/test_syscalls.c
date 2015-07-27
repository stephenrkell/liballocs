#define _GNU_SOURCE

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <dwarfidl/parser_includes.h>
#include "liballocs.h"
#include "footprints.h"
#include "perform_syscall.h"

typedef ANTLR3_TOKEN_SOURCE TokenSource;
typedef ANTLR3_COMMON_TOKEN CommonToken;
typedef ANTLR3_INPUT_STREAM ANTLRInputStream;
typedef ANTLR3_COMMON_TOKEN_STREAM CommonTokenStream;
typedef ANTLR3_BASE_TREE Tree;
typedef ANTLR3_COMMON_TREE CommonTree;

void supply_syscall_footprint(struct syscall_state **state_ptr) {
	struct syscall_state *state = *state_ptr;
	while (!state->finished) {
		printf("================================================================================\n"
		       "STARTING PASS\n"
		       "================================================================================\n");
		// we have to give it some more data. hopefully
		assert(state->need_memory_extents != NULL);
		
		struct data_extent_node *data_nodes = NULL;
		struct extent_node *current = state->need_memory_extents;
		while (current != NULL) {

			// of course we're pretending to be getting our data from
			// a mysterious simulator rather than just memcpy
			void *data = malloc(current->extent.length);
			memcpy(data, (void*) current->extent.base, current->extent.length);
			
			data_nodes = data_extent_node_new_with(current->extent.base, current->extent.length, data, data_nodes);
			current = current->next;
		}

		state = continue_syscall(state, data_nodes);
	}

	*state_ptr = state;
}

int main(int argc, char **argv) {
	assert(argc == 2);
	const char *filename = argv[1];

	struct syscall_env syscall_env;
	
	if (!load_syscall_footprints_from_file(filename, &syscall_env)) {
		perror("could not load footprints");
		return 1;
	}

	size_t read_syscall_num = 0;
	size_t open_syscall_num = 2;
	size_t close_syscall_num = 3;
	
	// open() a file!
	char *cat = (char*)"/tmp/blah";
	struct syscall_state *open_state = start_syscall(&syscall_env, open_syscall_num,
	                                                 (long int[]) {(long int)cat, 0, 0, 0, 0, 0});
	supply_syscall_footprint(&open_state);
	assert(open_state->finished);
	int fd = (int) open_state->retval;
	
	printf("********************************** we got an FD! it's %d.\n", fd);

	char *buf = malloc(12);
	memset(buf, 0, 12);

	struct syscall_state *read_state = start_syscall(&syscall_env, read_syscall_num,
	                                                 (long int[]) {(long int)fd, (long int)buf, (long int)10, 0, 0, 0});
	supply_syscall_footprint(&read_state);
	assert(read_state->finished);
	
	printf("********************************** retval from read was %d, up to first 10 bytes are: %s\n", read_state->retval, buf);

	// close() the fd!
	struct syscall_state *close_state = start_syscall(&syscall_env, close_syscall_num, (long int[]) {(long int)fd, 0, 0, 0, 0, 0});
	// this shouldn't have had a memory footprint
	assert(close_state->finished);

	printf("********************************** close()ed the fd.\n");

	// hope it didn't crash!
	return 0;
}

