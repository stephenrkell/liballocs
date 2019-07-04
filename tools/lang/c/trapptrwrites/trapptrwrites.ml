(* Copyright (c) 2019,
 *  Guillaume Bertholon <guillaume.bertholon@ens.fr>
 *
 * including works on logwrites.ml by
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

open Cil
open Feature

let constVoidPtrType = TPtr(TVoid([Attr("const", [])]), [])
let constVoidPtrPtrType = TPtr(constVoidPtrType, [])

let trapPtrWrites file =
  let notifyPtrWriteFun =
    makeGlobalVar "__notify_ptr_write" (TFun (voidType,
      Some [ ("dest", constVoidPtrPtrType, []) ; ("val", constVoidPtrType, []) ],
           false, [])) in

  let notifyCopyFun =
    makeGlobalVar "__notify_copy" (TFun (voidType,
      Some [ ("dest", voidPtrType, []) ; ("src", constVoidPtrType, []) ;
             ("count", !upointType, []) ], false, [])) in

  file.globals <- GVarDecl (notifyPtrWriteFun, locUnknown) ::
                  GVarDecl (notifyCopyFun, locUnknown) ::
                  file.globals;

  let visitor =
  object
    inherit nopCilVisitor

    val mutable curFunc = None

    method vfunc f =
      curFunc <- Some f;
      DoChildren

    method vinst i =
      let rec typNeedTrapCalls = function
      | TPtr _ | TFun _ -> true
      | TComp (c, _) ->
          List.fold_left (fun acc field -> acc || typNeedTrapCalls field.ftype)
              false c.cfields
      | TArray (eltyp, Some _, _) -> (* Sized arrays *)
          typNeedTrapCalls eltyp
      | TNamed _ as typ -> typNeedTrapCalls (unrollType typ)
      | _ -> false
      in

      let lvNeedTrapCalls lv = typNeedTrapCalls (typeOfLval lv) in

      let rec addTrapCallsForLval lv rv loc tail =
          match unrollType (typeOfLval lv) with
          | TPtr _ | TFun _ ->
              Call (None, Lval (var notifyPtrWriteFun),
                    [ mkCast (mkAddrOf lv) constVoidPtrPtrType ; Lval rv ], loc) :: tail
          | TComp (c, _) -> (* treat unions as structs, might not be a good idea... *)
              List.fold_left (fun acc field ->
                  let flv = addOffsetLval (Field(field, NoOffset)) lv in
                  let frv = addOffsetLval (Field(field, NoOffset)) rv in
                  addTrapCallsForLval flv frv loc acc)
              tail c.cfields
          | TArray (eltyp, Some length_exp, _) when typNeedTrapCalls eltyp ->
              (* TODO: Generate 'for' loop instead *)
              Call (None, Lval (var notifyCopyFun),
                    [ mkAddrOf lv ; StartOf rv ;
                    BinOp (Mult, length_exp, SizeOf eltyp, !upointType) ],
                    loc) :: tail
          | _ -> tail
      in

      match i with
      | Set (lv, _, _) | Call (Some lv, _, _, _) when not (lvNeedTrapCalls lv) ->
          SkipChildren
      | Set(lv, Lval rv, l) ->
          ChangeTo (addTrapCallsForLval lv rv l [Set(lv, Lval rv, l)])
      | Set(lv, e, l) ->
          let curFunc = match curFunc with
            | Some f -> f
            | None -> assert false
          in
          let tmpvar = var (makeTempVar curFunc (typeOfLval lv)) in
          ChangeTo (Set(tmpvar, e, l) ::
              addTrapCallsForLval lv tmpvar l [Set(lv, Lval tmpvar, l)])
      | Call(Some lv, f, args, l) ->
          let curFunc = match curFunc with
            | Some f -> f
            | None -> assert false
          in
          let tmpvar = var (makeTempVar curFunc (typeOfLval lv)) in
          ChangeTo (Call(Some tmpvar, f, args, l) ::
              addTrapCallsForLval lv tmpvar l [Set(lv, Lval tmpvar, l)])
      | _ -> SkipChildren
  end in

  visitCilFileSameGlobals visitor file

let feature =
  { fd_name = "trap-ptr-writes";
    fd_enabled = false;
    fd_description = "generation of code to log memory writes";
    fd_extraopt = [];
    fd_doit = trapPtrWrites;
    fd_post_check = true;
  }

let () = Feature.register feature
