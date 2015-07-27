open Core.Std
open Ctypes
open PosixTypes
open Foreign

(***** Types *****)

type c_footprint_node
let c_footprint_node : c_footprint_node structure typ = structure "footprint_node"

type c_env_node
let c_env_node : c_env_node structure typ = structure "env_node"

type c_evaluator_state
let c_evaluator_state : c_evaluator_state structure typ = structure "evaluator_state"

type c_extent
let c_extent : c_extent structure typ = structure "extent"
let c_extent_base = field c_extent "base" nativeint
let c_extent_length = field c_extent "length" nativeint
let () = seal c_extent

type c_extent_node
let c_extent_node : c_extent_node structure typ = structure "extent_node"
let c_extent_node_extent = field c_extent_node "extent" c_extent
let c_extent_node_next = field c_extent_node "next" (ptr_opt c_extent_node)
let () = seal c_extent_node

type c_data_extent
let c_data_extent : c_data_extent structure typ = structure "data_extent"
let c_data_extent_base = field c_data_extent "base" nativeint
let c_data_extent_length = field c_data_extent "length" nativeint
let c_data_extent_data = field c_data_extent "data" (ptr char)
let () = seal c_data_extent

type c_data_extent_node
let c_data_extent_node : c_data_extent_node structure typ = structure "data_extent_node"
let c_data_extent_node_extent = field c_data_extent_node "extent" c_data_extent
let c_data_extent_node_next = field c_data_extent_node "next" (ptr_opt c_data_extent_node)
let () = seal c_data_extent_node
       
type c_syscall_env
let c_syscall_env : c_syscall_env structure typ = structure "syscall_env"
let c_syscall_env_footprints = field c_syscall_env "footprints" (ptr c_footprint_node)
let c_syscall_env_defined_functions = field c_syscall_env "defined_functions" (ptr c_env_node)
let () = seal c_syscall_env

type c_syscall_state
let c_syscall_state : c_syscall_state structure typ = structure "syscall_state"
let c_syscall_state_env = field c_syscall_state "syscall_env" (ptr c_syscall_env)
let c_syscall_state_eval = field c_syscall_state "eval" (ptr c_evaluator_state)
let c_syscall_state_footprint = field c_syscall_state "footprint" (ptr c_footprint_node)
let c_syscall_state_num = field c_syscall_state "syscall_num" nativeint
let c_syscall_state_args = field c_syscall_state "syscall_args" (array 6 nativeint)
let c_syscall_state_name = field c_syscall_state "syscall_name" string
let c_syscall_state_retval = field c_syscall_state "retval" nativeint
let c_syscall_state_need_extents = field c_syscall_state "need_memory_extents" (ptr_opt c_extent_node)
let c_syscall_state_write_extents = field c_syscall_state "write_extents" (ptr_opt c_data_extent_node)
let c_syscall_state_finished = field c_syscall_state "finished" bool
let () = seal c_syscall_state

let c_load_syscall_footprints_from_file = foreign "load_syscall_footprints_from_file" (string
                                                                                       @-> ptr c_syscall_env
                                                                                       @-> returning bool)

let c_start_syscall = foreign "start_syscall" (ptr c_syscall_env
                                               @-> nativeint
                                               @-> ptr nativeint
                                               @-> returning (ptr c_syscall_state))

let c_continue_syscall = foreign "continue_syscall" (ptr c_syscall_state
                                                     @-> ptr c_data_extent_node
                                                     @-> returning (ptr c_syscall_state))

let c_data_extent_node_new_with = foreign "data_extent_node_new_with" (nativeint
                                                                       @-> nativeint
                                                                       @-> ptr char
                                                                       @-> ptr c_data_extent_node
                                                                       @-> returning (ptr c_data_extent_node))

type state = c_syscall_state structure ptr
type env = c_syscall_env structure ptr

type extent = {
    base : nativeint;
    length : nativeint;
    data : ((char, Bigarray.int8_unsigned_elt, Bigarray.c_layout) Bigarray.Array1.t) option;
  }

type result =
  | Finished of (* retval : *) nativeint * (* write_footprint : *) extent list
  | MoreDataNeeded of state * (* read_footprint : *) extent list


(***** Utility functions *****)


let _marshal_from_read_extents c_extents =
  let rec marshal_one_extent = function
      | None -> []
      | Some (c_extent_node_ptr) ->
         let c_extent_node = !@ c_extent_node_ptr in
         let c_extent = getf c_extent_node c_extent_node_extent in {
             base = getf c_extent c_extent_base;
             length = getf c_extent c_extent_length;
             data = None;
           } :: marshal_one_extent (getf c_extent_node c_extent_node_next) in
  marshal_one_extent (Some c_extents)


let _marshal_to_read_extents extents =
  let rec marshal_one_extent = function
    | [] -> (from_voidp c_data_extent_node null)
    | x::xs -> match x.data with
               | None -> failwith "data extent provided with None in data field"
               | Some data -> (c_data_extent_node_new_with
                                 x.base
                                 x.length
                                 (bigarray_start array1 data)
                                 (marshal_one_extent xs)) in
  marshal_one_extent extents
    

let _marshal_from_write_extents c_data_extents =
  let rec marshal_one_extent = function
    | None -> []
    | Some (c_data_extent_node_ptr) ->
       let c_data_extent_node = !@ c_data_extent_node_ptr in
       let c_data_extent = getf c_data_extent_node c_data_extent_node_extent in {
           base = getf c_data_extent c_data_extent_base;
           length = getf c_data_extent c_data_extent_length;
           data = Some (bigarray_of_ptr array1
                                        (Nativeint.to_int_exn (getf c_data_extent c_data_extent_length))
                                        Bigarray.char
                                        (getf c_data_extent c_data_extent_data))
         } :: marshal_one_extent (getf c_data_extent_node c_data_extent_node_next) in 
  marshal_one_extent (Some c_data_extents)


let _check_c_retval state_ptr =
  let state = (!@ state_ptr) in
  if getf state c_syscall_state_finished then
    let retval = getf state c_syscall_state_retval in
    match getf state c_syscall_state_write_extents with
    | None -> Finished (retval, [])
    | Some (extents) -> Finished (retval, _marshal_from_write_extents extents)
  else
    match getf state c_syscall_state_need_extents with
    | None -> failwith "apparently we need some extents, but haven't been given any"
    | Some extents -> MoreDataNeeded (state_ptr, _marshal_from_read_extents extents)


(***** Public API *****)


let load_footprints_from_file filename =
  print_endline "entering load_footprints_from_file";
  let env_ptr = allocate_n ~count:1 c_syscall_env in
  let success = c_load_syscall_footprints_from_file filename env_ptr in
  if success then
    Some env_ptr
  else
    None


let start_syscall env num args =
  let args_length = Array.length args in
  if args_length  < 0 || args_length > 6 then
    raise (Invalid_argument "start_syscall args")
  else begin
    let arr = CArray.make nativeint ~initial:0n 6 in
    for i = 0 to (Array.length args) - 1 do
      CArray.set arr i args.(i)
    done;
    let state_ptr = c_start_syscall env num (CArray.start arr) in
    _check_c_retval state_ptr
    end


let continue_syscall state extents =
  let c_extents = _marshal_to_read_extents extents in
  let state_ptr = c_continue_syscall state c_extents in
  _check_c_retval state_ptr

