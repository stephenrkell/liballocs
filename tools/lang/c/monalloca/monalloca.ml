(* Copyright (c) 2014,
 *  Stephen Kell        <stephen.kell@cl.cam.ac.uk>
 *
 * and based on logwrites.ml, which is 
 *
 * Copyright (c) 2001-2002, 
 *  George C. Necula    <necula@cs.berkeley.edu>
 *  Scott McPeak        <smcpeak@cs.berkeley.edu>
 *  Wes Weimer          <weimer@cs.berkeley.edu>
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * 3. The names of the contributors may not be used to endorse or promote
 * products derived from this software without specific prior written
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *)

open Unix
open List
open Str
open Cil
open Pretty
open Feature
open Cilallocs
module E = Errormsg
module H = Hashtbl

(* Basic idea for alloca:
 
 - dumpallocs prints them as usual, using the calling function defn's file/line/col
 
 - here we instrument alloca'ing functions s.t.
 
    -- they call out to __liballocs_pre_ and __liballocs_post_alloca functions
    -- they store base (and bound? depends on how we index them) in the stack frame itself
    ... NO, we can't do this, because we're allowed to alloca() in a loop, and on gcc
            when I try it, these all end up on the stack
    ... instead we have to treat the alloca "holes" as logically part of the heap
    ... we trailer them and pad them
    -- the post function indexes the alloca in the heap index
    -- the cleanup function is an inline that we declare locally
          ... that unindexes *all* alloca'd chunks that are lower in the stack than it
          ... by using the l0 index to find the end of the mapping we're in.

 - we want the dumptypes to somehow mark these frames?
      ... or just "detect the gap"?
 
 *)

let rec try_match vname pattern =
    try if (search_forward (regexp pattern) (vname) 0) >= 0
        then true
        else false
    with Not_found -> false
    
let rec findCleanupLocal (rest : varinfo list) = match rest with
    [] -> None
  | l::ll -> if l.vname = "__liballocs_alloca_cleanup_local" 
        then Some(l) 
        else findCleanupLocal ll 

let ensureCleanupLocal (fn : fundec) =
    (* val makeLocalVar : fundec -> ?insert:bool -> string -> typ -> varinfo *)
    match findCleanupLocal fn.slocals with 
        Some(s) -> s
      | None -> let v = makeLocalVar fn ~insert:true "__liballocs_alloca_cleanup_local" ulongType
        in v.vattr <- v.vattr @ [Attr("cleanup", [ACons("__liballocs_alloca_caller_frame_cleanup", [])])];
        (* trying to initialize this right here, by adding to fn.sbody.bstmts, doesn't work -- 
           likely because it gets clobbered by the visitor code. So we do it when visiting the function
           instead. *)
        fn.sbody.bstmts <- (mkStmtOneInstr (Set((Var(v), NoOffset), zero, v.vdecl)))
                           :: fn.sbody.bstmts; 
        v

class monAllocaExprVisitor = fun (fl: Cil.file) 
                            -> fun enclosingFunction
                            -> fun liballocsAllocaFun
                            -> fun liballocsAllocaCleanupFun
                            -> fun currentAllocsiteVar
                            -> object(self)
  inherit nopCilVisitor

  method vinst (i: instr) : instr list visitAction = 
    let isAllocaFun fe = match fe with
        Lval(Var(v), NoOffset) 
        when enclosingFunction.svar.vname <> "__liballocs_unindex_stack_objects_counted_by" 
            && enclosingFunction.svar.vname <> "__liballocs_alloca"
            && (v.vname = "alloca" || v.vname = "__builtin_alloca") -> true
      | _ -> false
    in
    match i with 
        Call(tgt, funExpr, args, l) when isAllocaFun funExpr -> begin
            (* We need to
             * - ensure we have a local in the function for recording 
                 the fact that this frame does alloca
             * - in that local's destructor, call 
                    __liballocs_unindex_stack_objects_below(frame_addr)
             * - before the call, create a fake call site for objdumpallocs to see...
             * - ... which we also use to store the return addr, i.e. the alloc site addr, 
             *       into __current_allocsite.
             
              callq UNIQUE_LABEL
            UNIQUE_LABEL: 
              pop %rax
              mov %rax, __current_allocsite
             
             *)
             let v = ensureCleanupLocal enclosingFunction
             in
             let mkLabel num = ".L__monalloca_alloca_label_" 
                ^ (identFromString l.file) ^ "_" 
                ^ (string_of_int l.line) ^ "_"
                ^ (string_of_int num)
             in
             let labelString1 = mkLabel 1
             in 
             let labelString2 = mkLabel 2
             in
             (* We also need a test for zeroness of the (weak, thread-local) &__current_allocsite.
              * This is pretty hairy. If a thread-local is weak, it doesn't resolve to zero;
              * it resolves to the current thread pointer. We really don't want to store
              * anything into that! So load %fs:0x0 and compare against that. *)
             ChangeTo([Asm([(* attrs *)], 
                           [(* template strings *)
                                "   callq "^ labelString1 ^"\n\
                                "^ labelString1 ^": \n\
                                    pop %%rax\n\
                                    movq %%fs:0x0,%%rbx\n\
                                    cmp %0,%%rbx\n\
                                    je "^ labelString2 ^"\n\
                                    mov %%rax, 0(%0)\n\
                                "^ labelString2 ^":"
                           ], 
                           [(* outputs: (string option * string * lval) *)
                                
                           ], 
                           [(* inputs: (string option * string * exp) *)
                                (None, "r", mkAddrOf (Var(currentAllocsiteVar), NoOffset))
                           ], 
                           [(* clobbers: string *)
                                "%rax"; "%rbx"
                           ],
                           (* location *) l ); 
                Call(tgt, Lval(Var(liballocsAllocaFun.svar), NoOffset), args @ [mkAddrOf (Var(v), NoOffset)], l)])
        end
    | _ -> SkipChildren 
end (* class monAllocaVisitor *)

class monAllocaFunVisitor = fun (fl: Cil.file) -> object(self)
    inherit nopCilVisitor

    val mutable liballocsAllocaFun = emptyFunction "__liballocs_alloca"
    val mutable liballocsAllocaCleanupFun = emptyFunction "__liballocs_alloca_caller_frame_cleanup"
    
    initializer
        liballocsAllocaFun <- findOrCreateExternalFunctionInFile
                        fl "__liballocs_alloca" (TFun(voidPtrType, 
                        Some [ ("sz", ulongType, []);
                               ("counter", ulongPtrType, []) ], 
                        false, [])) 
                        ;
        liballocsAllocaCleanupFun <- findOrCreateExternalFunctionInFile
                        fl "__liballocs_alloca_caller_frame_cleanup" (TFun(voidType, 
                        Some [ ("obj", voidPtrType, [])], 
                        false, []))
   
    method vfunc (f: fundec) : fundec visitAction = 
        let currentAllocsiteVar = 
            let rec findVar gs = match gs with
                [] -> None
              | g::gs -> match g with 
                GVarDecl(v, _) when v.vname = "__current_allocsite" -> Some(v)
              | _ -> findVar gs
            in 
            match findVar fl.globals with 
                Some(v) -> v
              | None -> failwith "no __current_allocsite global in file"
        in        
        
        (* fn.sbody.bstmts <- (mkStmtOneInstr (Set((Var(v), NoOffset), zero, v.vdecl)))
                           :: fn.sbody.bstmts; *)

        let maExprVisitor = new monAllocaExprVisitor fl f liballocsAllocaFun liballocsAllocaCleanupFun currentAllocsiteVar
        in
        let modifiedFunDec = visitCilFunction maExprVisitor f
        in 
        let cleanupLocal = findCleanupLocal modifiedFunDec.slocals
        in 
        match cleanupLocal with
            None -> ChangeTo(modifiedFunDec)
          | Some(v) -> 
                modifiedFunDec.sbody.bstmts <- 
                    (mkStmtOneInstr (Set((Var(v), NoOffset), zero, v.vdecl))) :: modifiedFunDec.sbody.bstmts;
                ChangeTo(modifiedFunDec)
                
end (* class monAllocaFunVisitor *)

let feature : Feature.t = 
  { fd_name = "monalloca";
    fd_enabled = false;
    fd_description = "add instrumention for monitoring alloca calls";
    fd_extraopt = [];
    fd_doit = (function (f: file) -> 
      let vis = new monAllocaFunVisitor f in
      visitCilFileSameGlobals vis f);
    fd_post_check = true;
  } 

let () = Feature.register feature
