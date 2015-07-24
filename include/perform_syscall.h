#ifndef __SYSCALL__FUNCS__H__
#define __SYSCALL__FUNCS__H__

#include "footprints_types.h"

extern const char *syscall_names[];

struct syscall_env {
	struct footprint_node *footprints;
	struct env_node *defined_functions;
};

struct syscall_state {
	struct syscall_env *syscall_env;
	struct evaluator_state *eval;
	struct footprint_node *footprint;
	size_t syscall_num;
	long int syscall_args[6];
	char *syscall_name;
	long int retval;
	struct extent_node *need_memory_extents;
	_Bool finished;
};

struct syscall_state *syscall_state_new();
struct syscall_state *syscall_state_new_with(struct syscall_env *syscall_env, struct evaluator_state *eval, struct footprint_node *footprint, size_t syscall_num, long int syscall_args[6], char *syscall_name, long int retval, _Bool finished);
void syscall_state_free(struct syscall_state **state);

_Bool load_syscall_footprints_from_file(const char *filename, struct syscall_env *out);
struct syscall_state *start_syscall(struct syscall_env *env, size_t syscall_num, long int syscall_args[6]);
struct syscall_state *continue_syscall(struct syscall_state *state, struct data_extent_node *new_data);

#endif
