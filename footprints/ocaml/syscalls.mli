type state
type env

type extent = {
    base : nativeint;
    length : nativeint;
    data : ((char, Bigarray.int8_unsigned_elt, Bigarray.c_layout) Bigarray.Array1.t) option;
  }

type result =
  | Finished of (* retval : *) nativeint * (* write_footprint : *) extent list
  | MoreDataNeeded of state * (* read_footprint : *) extent list

val load_footprints_from_file : (* filename : *) string -> env option
val start_syscall : env -> (* syscall_num : *) nativeint -> (* syscall_args[0..6] : *) nativeint array -> result
val continue_syscall : state -> (* read_footprint : *) extent list -> result
