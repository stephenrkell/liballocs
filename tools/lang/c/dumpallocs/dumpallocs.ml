(* Copyright (c) 2011,
 *  Stephen Kell        <stephen.kell@cs.ox.ac.uk>
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
open Pretty
open Cil
module E = Errormsg
module H = Hashtbl

(* HACKed realpath for now: *)
let abspath f =
   if String.get f 0 = '/' then f else (getcwd ()) ^ "/" ^ f

(* Return the typesig of the type that e is calculating (a multiple of) the size of,
   if any. 
   We understand multiplications. 
   We also want to detect buffer/string-size calculations, which do not use sizeof. 
*)
let rec sizeExprHasNoSizeof (e: exp) =
  match e with 
 | Const(c) -> true
 | Lval((Var(v),o)) -> true
 | Lval((Mem(ex),o)) -> sizeExprHasNoSizeof ex
 | SizeOf(t) -> false
 | SizeOfE(ex) -> false
 | SizeOfStr(s) -> false
 | AlignOf(t) -> true
 | AlignOfE(t) -> true
 | UnOp(u, e1, t) -> sizeExprHasNoSizeof e1
 | BinOp(b, e1, e2, t) -> (sizeExprHasNoSizeof e1) && (sizeExprHasNoSizeof e2)
 | CastE(t, ex) -> sizeExprHasNoSizeof ex
 | AddrOf((Var(v),o)) -> true
 | AddrOf((Mem(ex),o)) -> sizeExprHasNoSizeof ex
 | StartOf((Var(v),o)) -> true
 | StartOf((Mem(ex),o)) -> sizeExprHasNoSizeof ex

(* FIXME: split this into a "toplevel" that does the HasNoSizeof check,
   and a recursive part which recurses *without* recursively doing the
   HasNoSizeof check. *)
let rec getSizeExpr (e: exp) =
  if sizeExprHasNoSizeof e then Some(typeSig charType)
  else begin
  match e with
   |  BinOp(Mult, e1, e2, t) -> begin
         match (getSizeExpr e1) with
           | Some(s1) -> Some(s1)
           | None -> begin match (getSizeExpr e2) with
              | Some(s2) -> Some(s2)
              | None -> None
              end
         end
   |  SizeOf(t) -> Some(typeSig t)
   |  SizeOfE(e) -> Some(typeSig (typeOf e))
   |  SizeOfStr(s) -> Some(typeSig charType)
   | _ -> None
  end

(*   |  SizeOf(t) -> Some(Pretty.sprint 80 (d_typsig () (typeSig t)))
   |  SizeOfE(e) -> Some(Pretty.sprint 80 (d_typsig () (typeSig (typeOf e))))
   |  SizeOfStr(s) -> Some(Pretty.sprint 80 (d_typsig () (typeSig charType))) *)

let rec try_match vname pattern =
    try if (search_forward (regexp pattern) (vname) 0) >= 0
        then true
        else false
    with Not_found -> false

let rec warnIfLikelyAllocFn (i: instr) (f: varinfo) (arglist: exp list) =
 if try_match f.vname "[aA][lL][lL][oO][cC]" then begin (* we *might* want to output something *)
               if (length arglist) > 0 then 
                (* Some(f.vname, *)
                   if try_match f.vname "calloc" && (length arglist) > 1
                      then (* getSizeExpr (nth arglist 1) *)
                      output_string Pervasives.stderr ("call to function " ^ f.vname ^ " looks like an allocation, but does not match any in LIBCRUNCH_ALLOC_FNS\n")
                   else if try_match f.vname "realloc" && (length arglist) > 1
                      then (* getSizeExpr (nth arglist 1) *)
                      output_string Pervasives.stderr ("call to function " ^ f.vname ^ " looks like an allocation, but does not match any in LIBCRUNCH_ALLOC_FNS\n")
                      else (* getSizeExpr (nth arglist 0) *)
                         output_string Pervasives.stderr ("call to function " ^ f.vname ^ " looks like an allocation, but does not match any in LIBCRUNCH_ALLOC_FNS\n")
               else () (*  ) 
               else (* takes no arguments, so we output a "(none)" line. *)
                  Some(f.vname, None) (* We eliminate these lines in merge-allocs, rather than
                     here, so we can safely pass over the false positive from objdumpallocs. *)
         *)  end else (* None *)
      (output_string Pervasives.stderr ("call to function " ^ f.vname ^ " is not an allocation because of empty arglist\n"); (* None *) () )

let rec extractUserAllocMatchingSignature i f arglist signature = 
 (* destruct the signature string *)
 (output_string Pervasives.stderr ("Warning: matching against signature " ^ signature ^ "\n");
 let signatureFunction = 
       if string_match (regexp "[^\\(]+") signature 0 
       then (* (output_string Pervasives.stderr ("Info: signature " ^ signature ^ " did contain a function name\n"); *) matched_string signature (* ) *)
       else (* (output_string Pervasives.stderr ("Warning: signature " ^ signature ^ " did not contain a function name\n"); *) "" (* ) *)
 in if f.vname <> signatureFunction then (* (output_string Pervasives.stderr ("Warning: extracted function name " ^ signatureFunction ^ " from signature\n"); *) None (* ) *)
 else begin let signatureArgSpec = 
       if string_match (regexp "\\(.*\\)") signature (String.length signatureFunction) 
       then (* (output_string Pervasives.stderr ("Info: signature " ^ signature ^ " did contain a function arg spec\n"); ( *) matched_string signature (* ) ) *)
       else (output_string Pervasives.stderr ("Warning: signature " ^ signature ^ " did not contain an arg spec\n"); "")
 in let sizeArgPos = 
       if string_match (regexp "[^A-Z]*[A-Z]") signatureArgSpec 0 
       then Some((String.length (matched_string signatureArgSpec)) - 1 (* for the bracket*) - 1 (* because we want zero-based *))
       else (output_string Pervasives.stderr ("Warning: signature " ^ signature ^ " did not contain a capitalized arg spec element\n"); None)
 in match sizeArgPos with
    Some(s) -> if (length arglist) > s then Some(f.vname, getSizeExpr (nth arglist s))
     else (output_string Pervasives.stderr ("Warning: signature " ^ signature 
     ^ " wrongly predicts allocation function " ^ f.vname ^ " will have at least " 
     ^ (string_of_int s) ^ " arguments, where here it has only " ^ (string_of_int (length arglist)) ^"\n"); None)
   | None -> None
 end)

let rec getUserAllocExpr (i: instr) (f: varinfo) (arglist: exp list) = 
  let userVerdict = try begin
    let candidates = Str.split (regexp "[ \t]+") (Sys.getenv "LIBCRUNCH_ALLOC_FNS") in
    (* match f.vname with each candidate *) 
    let rec firstMatchingSignature cands =
      match cands with
        [] -> (* (output_string Pervasives.stderr ("Warning: exhausted candidate signatures in LIBCRUNCH_ALLOC_FNS matching function "  ^ f.vname ^ "\n"); *) None(* ) *)
      | s::ss -> begin match extractUserAllocMatchingSignature i f arglist s with
           None -> (* (output_string Pervasives.stderr ("Warning: signature " ^ s ^ " did not match function " ^ f.vname ^ "\n"); *) firstMatchingSignature ss (* ) *)
         | Some(s) -> Some(s)
        end
    in firstMatchingSignature candidates
  end with Not_found -> (output_string Pervasives.stderr ("Warning: function " ^ f.vname ^ " did not match any user allocation function descriptor\n"); None)
  in
  match userVerdict with
  |  None -> (warnIfLikelyAllocFn i f arglist; None)
  |  Some(s) -> Some(s)

(* Work out whether this call is an allocation call. If it is,
   return Some(fn, optionalTypeSig)
   where fn is the function varinfo
   and optionalTypeSig is the type signature we inferred was being allocated, if we managed it *)
let rec getAllocExpr (i: instr) (f: varinfo) (arglist: exp list) =
  match f.vname with
    | "malloc" -> Some (f.vname, getSizeExpr (nth arglist 0))
    | "calloc" -> Some (f.vname, getSizeExpr (nth arglist 1))
    | "realloc" -> Some (f.vname, getSizeExpr (nth arglist 1))
    | _ -> getUserAllocExpr i f arglist 

(* HACK: copied from trumptr *)
(* This effectively embodies our "default specification" for C code
 * -- it controls what we assert in "__is_a" tests, and
 * needs to mirror what we record for allocation sites in dumpallocs *)
let rec getEffectiveType tsig =
 match tsig with
   TSArray(tsig, optSz, attrs) -> getEffectiveType tsig
 | TSPtr(tsig, attrs) -> TSPtr(getEffectiveType tsig, []) (* stays a pointer, but discard attributes *)
 | TSComp(isSpecial, name, attrs) -> TSComp(isSpecial, name, [])
 | TSFun(returnTs, argsTss, isSpecial, attrs) -> TSFun(returnTs, argsTss, isSpecial, [])
 | TSEnum(enumName, attrs) -> TSEnum(enumName, [])
 | TSBase(TVoid(attrs)) -> TSBase(TVoid([]))
 | TSBase(TInt(kind,attrs)) -> TSBase(TInt(kind, []))
 | TSBase(TFloat(kind,attrs)) -> TSBase(TFloat(kind, []))
 | _ -> tsig
 
(* stolen from StackOverflow:  http://stackoverflow.com/questions/1584758/
   -- eventually want to change to use Ocaml Batteries Included *)
let trim str =   if str = "" then "" else   let search_pos init p next =
    let rec search i =
      if p i then raise(Failure "empty") else
      match str.[i] with
      | ' ' | '\n' | '\r' | '\t' -> search (next i)
      | _ -> i
    in
    search init   in   let len = String.length str in   try
    let left = search_pos 0 (fun i -> i >= len) (succ)
    and right = search_pos (len - 1) (fun i -> i < 0) (pred)
    in
    String.sub str left (right - left + 1)   with   | Failure "empty" -> "" ;;

let rec stringFromSig tsig = (* = Pretty.sprint 80 (d_typsig () (getEffectiveType ts)) *)
 match tsig with
   TSArray(tsig, optSz, attrs) -> "impossible"
 | TSPtr(tsig, attrs) -> "^" ^ (stringFromSig tsig)
 | TSComp(isSpecial, name, attrs) -> name
 | TSFun(returnTs, argsTss, isSpecial, attrs) -> "()=>" ^ (stringFromSig tsig)
 | TSEnum(enumName, attrs) -> enumName
 | TSBase(TVoid(attrs)) -> "void"
 | TSBase(TInt(kind,attrs)) -> trim (Pretty.sprint 80 (d_ikind () kind))
 | TSBase(TFloat(kind,attrs)) -> trim (Pretty.sprint 80 (d_fkind () kind))
 | _ -> "impossible"

(* I so do not understand Pretty.dprintf *)
let printAllocFn fileAndLine chan funvar allocExpr = 
   output_string Pervasives.stderr ("printing alloc for " ^ fileAndLine ^ ", funvar " ^ funvar.vname ^ "\n");
   output_string chan fileAndLine;
   let msg = Pretty.sprint 80 
       (Pretty.dprintf  "\t%a\t"
            d_lval (Var(funvar), NoOffset)) 
   in
   output_string chan (msg ^ allocExpr ^ "\n");
   flush chan
              
class dumpAllocsVisitor = fun (fl: Cil.file) -> object(self)
  inherit nopCilVisitor
  
  (* where we will write our alloc data *)
  val outChannel : out_channel option ref = ref None
  
  (* at construction time, open the output file *)
  initializer 
    let allocFileName = fl.fileName ^ ".allocs" in
    outChannel := try begin
         let chan = open_out allocFileName in
         (* output_string chan ("run initializer, opened " ^ allocFileName); *)
         Some(chan)
      end 
      with _ ->
        raise (Arg.Bad ("Cannot open file " ^ allocFileName))

  method vinst (i: instr) : instr list visitAction = 
    ( output_string Pervasives.stderr ("considering instruction " ^ (
       match i with 
          Call(_, _, _, l) -> "(call) at " ^ l.file ^ ", line: " ^ (string_of_int l.line)
        | Set(_, _, l) -> "(assignment) at " ^ l.file ^ ", line: " ^ (string_of_int l.line)
        | Asm(_, _, _, _, _, l) -> "(assembly) at " ^ l.file ^ ", line: " ^ (string_of_int l.line)
      ) ^ "\n");  
      match i with 
      Call(_, f, args, l) -> begin
        (* Check if we need to output *)
        match f with 
          Lval(Var(v), NoOffset) when v.vglob -> begin
              match v.vtype with
               | TFun(returnType, optParamList, isVarArgs, attrs) -> 
                   (* Where to write our output? We want the .allocs to be output 
                      right alongside the .c file (say) that does the allocation.
                      PROBLEM 1: this varies, because we're reading a .i file, i.e.
                      preprocessed temporary, that is NOT NECESSARILY IN THE SAME DIRECTORY
                      the C file.
                      PROBLEM 2: allocs might be in a header file, in which case we
                      won't have permission to write the output.
                      Our solution:
                      - tried: just write to where the .i file goes. This doesn't work because
                      e.g. git has ./builtin/bundle.c and ./bundle.c; the allocs for the latter
                      overwrite the former.
                      - next attempt: we find out which file is the toplevel input, and use that.
                      Problem: toplevel input was handled by cilly, our parent process.
                      
                      
                      This makes sense because our allocs data is a per translation unit thing
                      (e.g. could conceivably be different for two different compilations
                      both including the same header file, so can't write a single ".allocs"
                      for that header).
                    *)
                   (* (output_string Pervasives.stderr ("processing a function " ^ v.vname ^ "\n"); *)
                   let chan = match !outChannel with
                    | Some(s) -> s
                    | None    -> Pervasives.stderr
                   in
                   let fileAndLine = (abspath l.file) ^ "\t" ^ (string_of_int l.line) 
                   in
                   begin
                      (* Here we need to identify the size argument and
                         then do either some hacky pattern matching
                         or a recursive function on the expr structure:
                         Sizeof T lets us terminate
                         Sizeof V also lets us terminate
                         Mul where an arg is a Sizeof lets us terminate *)
                     match (getAllocExpr i v args) with
                        Some(fn1, Some(ts)) -> 
                         printAllocFn fileAndLine chan v (stringFromSig ts); SkipChildren
                     |  Some(fn2, None) -> 
                         let placeholder = if (length args) > 0 then "(unknown)" else "(none)"
                         in printAllocFn fileAndLine chan v placeholder; SkipChildren
                     |  _ -> 
                         (output_string Pervasives.stderr (
                            "skipping call to function " ^ v.vname ^ " since getAllocExpr returned None\n"
                         ) ; SkipChildren) (* this means it's not an allocation function *)
                   end (* ) *)
                | _ (* match v.vtype *) -> (output_string Pervasives.stderr ("skipping call to non-function var " ^ v.vname ^ "\n"); SkipChildren)
             end
        | _ (* match f *) -> (output_string Pervasives.stderr ("skipping call to non-lvalue at " ^ l.file ^ ":" ^ (string_of_int l.line) ^ "\n"); SkipChildren)
      end 
    | Set(lv, e, l) -> (output_string Pervasives.stderr ("skipping assignment at " ^ l.file ^ ":" ^ (string_of_int l.line) ^ "\n" ); SkipChildren )
    | Asm(_, _, _, _, _, l) -> (* (output_string Pervasives.stderr ("skipping assignment at " ^ l.file ^ ":" ^ (string_of_int l.line) ^ "\n" ); *) SkipChildren (* ) *)
    )
end (* class dumpAllocsVisitor *)

let feature : featureDescr = 
  { fd_name = "dumpallocs";
    fd_enabled = ref false;
    fd_description = "print information about allocation sites";
    fd_extraopt = [];
    fd_doit = 
    (function (f: file) -> 
      let daVisitor = new dumpAllocsVisitor f in
      (* Cfg.computeFileCFG f;
      computeAEs f; *)
      visitCilFileSameGlobals daVisitor f);
    fd_post_check = true;
  } 

