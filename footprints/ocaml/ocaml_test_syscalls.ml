open Ctypes
open Printf
open Core.Std
open Syscalls

let open_syscall_num = 2n
let close_syscall_num = 3n
let footprints = "/home/jf451/spec.idl"
let filename = "/bin/cat" (* just something I'm fairly sure exists *)

let rec supply_syscall_footprint state extents = 
  (* This represents whatever process you go through to
     acquire the footprint data from the simulator *)
  let supply_one_footprint extent = ({
      base = extent.base;
      length = extent.length;
      (* do horrible things with pointers for testing purposes *)
      data = Some (bigarray_of_ptr array1
                                   (Nativeint.to_int_exn extent.length)
                                   Bigarray.char
                                   (from_voidp char (ptr_of_raw_address extent.base)));
                                    }) in
  match Syscalls.continue_syscall state (List.map extents supply_one_footprint) with
  | Finished (retval, write_extents) -> Finished (retval, write_extents)
  | MoreDataNeeded (state, extents) -> supply_syscall_footprint state extents


let do_one_syscall env num args =
  let result = Syscalls.start_syscall env num args in
  match result with 
  | Finished (retval, _) -> retval
  | MoreDataNeeded (state, extents) ->
     match supply_syscall_footprint state extents with
     (* TODO: actually apply writes.
        write_extents : extent list
        is currently always [] because
        pointer rewriting not impl'ed yet
        but this will soon be rectified *)
     | Finished (retval, write_extents) -> retval 
     | MoreDataNeeded (_, _) -> failwith "supply_syscall_footprint returned MoreDataNeeded"
              

let main =
  match Syscalls.load_footprints_from_file footprints with
  | None -> failwith "couldn't open footprints"
  | Some env -> begin
      (* shouldn't have to use anything from ctypes once
         actually getting data from the simulator
         as you'll be passing the raw register values
         (as nativeints, if you please) *)
     print_endline "Got footprints." ;
     let filename_bigstring = Bigstring.of_string filename in begin
         printf "*** %s is the filename; %d is the length of the bigstring\n"
                filename
                (Bigarray.Array1.dim filename_bigstring);
         let ptr = raw_address_of_ptr
                     (to_voidp (bigarray_start array1 filename_bigstring)) in begin
             printf "*** 0x%nx is the address we got\n" ptr;
             let open_args = [| ptr |] in
             let retval = (do_one_syscall env open_syscall_num open_args) in begin
                 printf "Got FD retval from open(): %nd\n" retval;
                 printf "Closing it\n";
                 do_one_syscall env close_syscall_num [| retval |]
               end
           end
       end
    end
