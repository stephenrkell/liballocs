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

let rec decayArrayInTypesig ts = match ts with
   TSArray(tsig, optSz, attrs) -> decayArrayInTypesig tsig (* recurse for multidim arrays *)
 | _ -> ts

type sz = 
    Undet
  | Existing of typsig
  | Synthetic of typsig list

let maybeDecayArrayTypesig maybeTs = match maybeTs with
    Existing(ts) -> Existing(decayArrayInTypesig ts)
  | _ -> Undet

let rec getSizeExpr (ex: exp) (env : (int * typsig) list) = 
  output_string Pervasives.stderr ("Hello from getSizeExpr(" ^ (Pretty.sprint 80 (Pretty.dprintf "%a" d_exp ex)) ^ ")\n");  flush Pervasives.stderr; 
  match ex with
   |  BinOp(Mult, e1, e2, t) -> begin
         let sz1 = getSizeExpr e1 env in
         let sz2 = getSizeExpr e2 env in
         match (sz1, sz2) with
             (Undet, Undet) -> Undet
           | (Undet, _) -> sz2
           | (_, Undet) -> sz1
           | (_, _)     ->  
                    (* Multiplying two sizeofnesses together is weird. Just 
                       go with the first one. *)
                    sz1
         end
   |  BinOp(PlusA, e1, e2, t) -> begin
         let sz1 = getSizeExpr e1 env in
         let sz2 = getSizeExpr e2 env in
         match (sz1, sz2) with
             (Undet, Undet) -> Undet
           | (Undet, _) -> sz2 (* a bit weird, pre-padding but okay *) 
           | (_, Undet) -> sz1 (* character padding *)
           | (Existing(s1), Existing(s2)) ->
                 (* If we're adding Xs to Xs, OR array of Xs to some more sizeof X, the whole
                    expr has sizeofness X *)
                 let decayedS1 = decayArrayInTypesig s1 in 
                 let decayedS2 = decayArrayInTypesig s2 in 
                 if decayedS1 = decayedS2 then Existing(decayedS1)
                 else 
                    (* GAH. Arrays! we often do 
                           
                           sizeof S + n * sizeof T
                           
                       in which case our last element is a variable-length thing.
                       Is it enough to interpret 
                    *)
                    Synthetic([s1; s2])
           | (Synthetic(l1), Existing(s2)) -> Synthetic(l1 @ [s2])
           | (Existing(s1), Synthetic(l2)) -> Synthetic(s1 :: l2)
           | (Synthetic(l1), Synthetic(l2)) -> Synthetic(l1 @ l2)
        end
   |  BinOp(Div, e1, e2, t) -> begin
         (* We can "divide away" sizeofness e.g. by dividing sizeof (array_of_X) / (sizeof (X)) *)
         let maybeDecayedS1 = (maybeDecayArrayTypesig (getSizeExpr e1 env))
         in 
         let maybeDecayedS2 = (maybeDecayArrayTypesig (getSizeExpr e2 env))
         in
         match (maybeDecayedS1, maybeDecayedS2) with 
             (Existing(decayed1), Existing(decayed2)) -> if decayed1 = decayed2 then Undet (* divided away *)
              else (* dimensionally incompatible division -- what to do? *) Existing(decayed1)
            | (Existing(s), Undet) -> Existing(s)
            | _ -> Undet (* this includes the Synthetic cases*)
         
      end
   |  SizeOf(t) -> Existing(typeSig t)
   |  SizeOfE(e) -> Existing(typeSig (typeOf e))
   |  SizeOfStr(s) -> Existing(typeSig charType)
   |  Lval(lhost, offset) -> begin
        (* output_string Pervasives.stderr ("Hello from Lval case in getSizeExpr\n");  flush Pervasives.stderr; *) 
        match lhost with 
           Var(v) -> begin
             if v.vglob then Undet else try 
               let found = Existing(assoc v.vid env) in 
               (* output_string Pervasives.stderr ("environment tells us that vid " ^ (string_of_int v.vid) ^ " has a sizeofness\n"); *)
               found 
             with Not_found -> Undet
           end
        |  Mem(_) -> Undet
      end
   | CastE(t, e) -> (getSizeExpr e env)
   | _ -> Undet
   
(* FIXME: split this into a "toplevel" that does the HasNoSizeof check,
   and a recursive part which recurses *without* recursively doing the
   HasNoSizeof check. *)
let getSizeExprElseDefault (e: exp) (env : (int * typsig) list) = 
  (* output_string Pervasives.stderr ("Hello from getSizeExprElseDefault\n");  flush Pervasives.stderr;  *)
  let explicitSizeExpr = getSizeExpr e env in
  match explicitSizeExpr with
    Undet -> Some(typeSig voidType)
  | Existing(t) -> Some(t)
  | Synthetic(ts) -> (* FIXME *) None

(*   |  SizeOf(t) -> Some(Pretty.sprint 80 (d_typsig () (typeSig t)))
   |  SizeOfE(e) -> Some(Pretty.sprint 80 (d_typsig () (typeSig (typeOf e))))
   |  SizeOfStr(s) -> Some(Pretty.sprint 80 (d_typsig () (typeSig charType))) *)

let rec try_match vname pattern =
    try if (search_forward (regexp pattern) (vname) 0) >= 0
        then true
        else false
    with Not_found -> false

let rec warnIfLikelyAllocFn (i: instr) (maybeFunName: string option) (arglist: exp list) = 
 match maybeFunName with 
   Some(funName) -> 
     if try_match funName "[aA][lL][lL][oO][cC]" then begin (* we *might* want to output something *)
       if (length arglist) > 0 then 
       (* Some(f.vname, *)
          if try_match funName "calloc" && (length arglist) > 1
             then (* getSizeExpr (nth arglist 1) *)
             output_string Pervasives.stderr ("call to function " ^ funName ^ " looks like an allocation, but does not match any in LIBCRUNCH_{SUB,}ALLOC_FNS\n")
          else if try_match funName "realloc" && (length arglist) > 1
             then (* getSizeExpr (nth arglist 1) *)
             output_string Pervasives.stderr ("call to function " ^ funName ^ " looks like an allocation, but does not match any in LIBCRUNCH_{SUB,}ALLOC_FNS\n")
             else (* getSizeExpr (nth arglist 0) *)
                output_string Pervasives.stderr ("call to function " ^ funName ^ " looks like an allocation, but does not match any in LIBCRUNCH_{SUB,}ALLOC_FNS\n")
      else () (*  ) 
      else (* takes no arguments, so we output a "(none)" line. *)
         Some(f.vname, None) (* We eliminate these lines in merge-allocs, rather than
            here, so we can safely pass over the false positive from objdumpallocs. *)
*)  end else (* None *)
      (* (output_string Pervasives.stderr ("call to function " ^ funName ^ " is not an allocation because of empty arglist\n"); (* None *) *) () (* ) *)
| None -> ()

let matchUserAllocArgs i arglist signature env maybeFunNameToPrint calledFunctionType : Cil.typsig option =
 let signatureArgSpec = try (
     let nskip = search_forward (regexp "(.*)") signature 0
     in
     let fragment = (* string_after *) (matched_string signature) (* nskip *)
     in 
     (output_string Pervasives.stderr ("Info: signature " ^ signature ^ " did contain a function arg spec (" ^ fragment ^ " a.k.a. signature + "^ (string_of_int nskip) ^")\n"); flush Pervasives.stderr);
     fragment
 )
 with Not_found -> (
       (output_string Pervasives.stderr ("Warning: signature " ^ signature ^ " did not contain an arg spec\n"); flush Pervasives.stderr); 
       ""
 )
 in let sizeArgPos = 
       if string_match (regexp "[^A-Z]*[A-Z]") signatureArgSpec 0 
       then Some((String.length (matched_string signatureArgSpec)) - 1 (* for the bracket*) - 1 (* because we want zero-based *))
       else (output_string Pervasives.stderr ("Warning: signature " ^ signature ^ " did not contain a capitalized arg spec element\n"); flush Pervasives.stderr; None)
 in match sizeArgPos with
  Some(s) -> 
     if (length arglist) > s then 
       let szEx = 
          (output_string Pervasives.stderr ("Looking at arg expression number " ^ (string_of_int s) ^ "\n"); flush Pervasives.stderr); 
          getSizeExpr (nth arglist s) env 
       in 
       match szEx with
         Existing(szType) -> (output_string Pervasives.stderr ("Inferred that we are allocating some number of " ^ (Pretty.sprint 80 (Pretty.dprintf  "\t%a\t" d_typsig szType)) ^ "\n"); flush Pervasives.stderr );
               Some(szType)
       | Undet -> output_string Pervasives.stderr ("Could not infer what we are allocating\n"); flush Pervasives.stderr; None
       | Synthetic(_) -> output_string Pervasives.stderr ("We are allocating a composite: FIXME\n"); flush Pervasives.stderr; None
     else (match maybeFunNameToPrint with 
         Some(fnname) -> 
               ((output_string Pervasives.stderr ("Warning: signature " ^ signature 
               ^ " wrongly predicts allocation function " ^ fnname ^ " will have at least " 
               ^ (string_of_int s) ^ " arguments, where call site it has only " ^ (string_of_int (length arglist)) ^"\n"); 
               flush Pervasives.stderr); None)
       | None -> (output_string Pervasives.stderr ("Warning: spec argument count (" ^ (string_of_int s) ^ ") does not match call-site argument count (" ^ (string_of_int (length arglist)) ^ ")")); None)
 | None -> 
      (* If we have no sizearg pos, use the return type of the function: 
         if it is a pointer to non-void, we assume the pointer target type is the allocated type. *)
      match calledFunctionType with 
        TSFun(returnTs, paramTss, isVarArgs, attrs) -> begin
            match returnTs with
            TSBase(TVoid(_)) -> None
         |  TSPtr(targetTs, _) -> Some(targetTs)
         |  _ -> None (* it returns something else *)
         end
      | _ -> raise (Failure "impossible function type")

let rec extractUserAllocMatchingSignature i maybeFunName arglist signature env calledFunctionType : Cil.typsig option = 
 (* destruct the signature string *)
 (* (output_string Pervasives.stderr ("Warning: matching against signature " ^ signature ^ "\n"); flush Pervasives.stderr;  *)
 let signatureFunction = 
       if string_match (regexp "[^\\(]+") signature 0 
       then (output_string Pervasives.stderr ("Info: signature " ^ signature ^ " did contain a function name: " ^ (matched_string signature) ^ "\n"); flush Pervasives.stderr; matched_string signature )
       else (output_string Pervasives.stderr ("Warning: signature " ^ signature ^ " did not contain a function name\n"); flush Pervasives.stderr; "" )
 in 
 match maybeFunName with 
   Some(fname) -> (if fname <> signatureFunction then (* (output_string Pervasives.stderr ("Warning: extracted function name " ^ signatureFunction ^ " from signature\n"); *) None (* ) *)
                  else (matchUserAllocArgs i arglist signature env (Some(fname)) calledFunctionType))
 | None -> (matchUserAllocArgs i arglist signature env None calledFunctionType)
 (* ) *)

let userAllocFunctions () : string list = 
  let wrappers = try begin 
    (Str.split (regexp "[ \t]+") (Sys.getenv "LIBCRUNCH_ALLOC_FNS"))
  end with Not_found -> []
  in
  let suballocs = try begin
    (Str.split (regexp "[ \t]+") (Sys.getenv "LIBCRUNCH_SUBALLOC_FNS")) 
  end with Not_found -> []
  in
  let sizeOnlyAllocs = try begin
    (Str.split (regexp "[ \t]+") (Sys.getenv "LIBCRUNCH_ALLOCSZ_FNS")) 
  end with Not_found -> []
  in
  wrappers @ suballocs @ sizeOnlyAllocs

(* FIXME: distinguish "it is an allocation function, but I couldn't identify what it's allocating"
   from "it doesn't appear to be an allocation function". *)
let rec getUserAllocExpr (i: instr) (maybeFunName: string option) (arglist: exp list) env candidates calledFunctionType : Cil.typsig option = 
  (* output_string Pervasives.stderr "Looking for user alloc expr\n"; flush Pervasives.stderr; *)
  let userVerdict = try begin
    (* match f.vname with each candidate *) 
    (* output_string Pervasives.stderr ("Got " ^ (string_of_int (List.length candidates)) ^ "candidate signatures\n"); flush Pervasives.stderr;  *)
    let rec firstMatchingSignature cands = 
      let funNameString = match maybeFunName with Some(s) -> s | None -> "(indirect call)"
      in
      match cands with
        [] -> output_string Pervasives.stderr ("Warning: exhausted candidate signatures in matching function "  ^ funNameString ^ "\n"); None
      | s::ss -> begin match extractUserAllocMatchingSignature i maybeFunName arglist s env calledFunctionType with
           None -> (output_string Pervasives.stderr ("Warning: signature " ^ s ^ " did not match function " ^ funNameString ^ "\n"); firstMatchingSignature ss )
         | Some(s) -> Some(s)
        end
    in firstMatchingSignature candidates
  end with Not_found -> (match maybeFunName with 
     Some(funName) -> (output_string Pervasives.stderr 
          ("Warning: function " ^ funName ^ " did not match any allocation function descriptor\n"))
  | None -> ()); None
  in
  match userVerdict with
  |  None -> (warnIfLikelyAllocFn i maybeFunName arglist; None)
  |  Some(s) -> Some(s)

(* Work out whether this call is an allocation call. If it is,
   return Some(fn, optionalTypeSig)
   where fn is the function varinfo
   and optionalTypeSig is the type signature we inferred was being allocated, if we managed it *)
let rec getAllocExpr (i: instr) (maybeFun: varinfo option) (arglist: exp list) env calledFunctionType = 
  let maybeFunName = match maybeFun with 
    Some(f) -> Some(f.vname)
  | None -> None
  in 
  getUserAllocExpr i maybeFunName arglist env (["malloc(Z)p"; "calloc(zZ)p"; "realloc(pZ)p"; "posix_memalign(pzZ)p"] @ (userAllocFunctions ())) calledFunctionType

(* HACK: copied from trumptr *)
let rec canonicalizeBaseTypeStr s = 
 (* generated from a table maintained in srk's libcxxgen  *)
if (s = "signed char" or s = "char" or s = "char signed" or  false) then "signed char"
else if (s = "unsigned char" or s = "char unsigned" or  false) then "unsigned char"
else if (s = "short int" or s = "short" or s = "int short" or  false) then "short int"
else if (s = "short unsigned int" or s = "unsigned short" or s = "short unsigned" or s = "unsigned short int" or s = "int unsigned short" or s = "int short unsigned" or s = "unsigned int short" or s = "short int unsigned" or  false) then "short unsigned int"
else if (s = "int" or s = "signed" or s = "signed int" or s = "int signed" or  false) then "int"
else if (s = "unsigned int" or s = "unsigned" or s = "int unsigned" or  false) then "unsigned int"
else if (s = "long int" or s = "long" or s = "int long" or s = "signed long int" or s = "int signed long" or s = "int long signed" or s = "long signed int" or s = "signed int long" or s = "long signed" or s = "signed long" or  false) then "long int"
else if (s = "unsigned long int" or s = "int unsigned long" or s = "int long unsigned" or s = "long unsigned int" or s = "unsigned int long" or s = "long unsigned" or s = "unsigned long" or  false) then "unsigned long int"
else if (s = "long long int" or s = "long long" or s = "long int long" or s = "int long long" or s = "long long signed" or s = "long signed long" or s = "signed long long" or s = "long long int signed" or s = "long long signed int" or s = "long signed long int" or s = "signed long long int" or s = "long int long signed" or s = "long int signed long" or s = "long signed int long" or s = "signed long int long" or s = "int long long signed" or s = "int long signed long" or s = "int signed long long" or s = "signed int long long" or  false) then "long long int"
else if (s = "long long unsigned int" or s = "long long unsigned" or s = "long unsigned long" or s = "unsigned long long" or s = "long long int unsigned" or s = "long unsigned long int" or s = "unsigned long long int" or s = "long int long unsigned" or s = "long int unsigned long" or s = "long unsigned int long" or s = "unsigned long int long" or s = "int long long unsigned" or s = "int long unsigned long" or s = "int unsigned long long" or s = "unsigned int long long" or  false) then "long long unsigned int"
else if (s = "float" or  false) then "float"
else if (s = "double" or  false) then "double"
else if (s = "long double" or s = "double long" or  false) then "long double"
else if (s = "bool" or  false) then "bool"
else if (s = "wchar_t" or  false) then "wchar_t"
  else s
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

(* HACK: pasted from trumptr *)
           (* The string representation needs tweaking to make it a symname:
               - prepend "__uniqtype_" 
               - insert the defining header file, with the usual munging for slashes, hyphens, dots, and spaces
               - FIXME: fix up base types specially!
               - replace '^' with '__PTR_' 
               - replace '()=>' with '__FUN_'.
               NOTE that arrays probably shouldn't come up here.

               We can't get the declaring file/line ("location" in CIL-speak) from a typesig,
               nor from its type -- we need the global.  *)

(* WORKAROUND for CIL's anonymous structure types: 
   we undo the numbering (set to 1) and hope for the best. *)
let hackTypeName s = (*if (string_match (regexp "__anon\\(struct\\|union\\|enum\\)_.*_[0-9]+$") s 0)
   then Str.global_replace (Str.regexp "_[0-9]+$") "_1" s
   else *) s

let rec barenameFromSig ts = 
 let rec labelledArgTs ts startAt =
   match ts with
     [] -> ""
  | t :: morets -> 
      let remainder = (labelledArgTs morets (startAt + 1))
      in
      "__ARG" ^ (string_of_int startAt) ^ "_" ^ (barenameFromSig t) ^ remainder
 in
 let baseTypeStr ts = 
   let rawString = match ts with 
     TInt(kind,attrs) -> (Pretty.sprint 80 (d_ikind () kind))
   | TFloat(kind,attrs) -> (Pretty.sprint 80 (d_fkind () kind))
   | TBuiltin_va_list(attrs) -> "__builtin_va_list"
   | _ -> raise(Failure ("bad base type: " ^ (Pretty.sprint 80 (Pretty.dprintf "%a" d_type ts))))
   in 
   Str.global_replace (Str.regexp "[. /-]") "_" (canonicalizeBaseTypeStr (trim rawString))
 in
 match ts with
   TSArray(tNestedSig, optSz, attrs) -> "__ARR" ^ (match optSz with Some(s) -> (string_of_int (i64_to_int s)) | None -> "0") ^ "_" ^ (barenameFromSig tNestedSig)
 | TSPtr(tNestedSig, attrs) -> "__PTR_" ^ (barenameFromSig tNestedSig)
 | TSComp(isSpecial, name, attrs) -> (hackTypeName name)
 | TSFun(returnTs, argsTss, isSpecial, attrs) -> 
      "__FUN_FROM_" ^ (labelledArgTs argsTss 0) ^ (if isSpecial then "__VA_" else "") ^ "__FUN_TO_" ^ (barenameFromSig returnTs) 
 | TSEnum(enumName, attrs) -> enumName
 | TSBase(TVoid(attrs)) -> "void"
 | TSBase(tbase) -> baseTypeStr tbase

let symnameFromSig ts = "__uniqtype_" ^ "" ^ "_" ^ (barenameFromSig ts)


(* I so do not understand Pretty.dprintf *)
let printAllocFn fileAndLine chan maybeFunvar allocExpr = 
   (* output_string Pervasives.stderr ("printing alloc for " ^ fileAndLine ^ ", funvar " ^ funvar.vname ^ "\n"); *)
   output_string chan fileAndLine;
   let msg = match maybeFunvar with 
     Some(funvar) -> Pretty.sprint 80 
       (Pretty.dprintf  "\t%a\t"
            d_lval (Var(funvar), NoOffset)) 
   | None -> "\t(indirect)\t"
   in
   output_string chan (msg ^ allocExpr ^ "\n");
   flush chan

(* Currently our visitor visits each instruction, 
   and for those that are calls, 
   uses getAllocExpr to match those that are allocation function calls, 
   extracting the sizeof subexpression from their argument list
   in the process (getAllocExpr calls getSizeExpr). 
   
   PROBLEM: address-taken allocation functions?
   We can perhaps conservatively overapproximate these. TODO.
   
   What we want it to do instead is:
   - an intraprocedural analysis
   - each SSA local is labelled with Maybe sizeExpr
   - initially all labels are None
   - ... except SSAs taking the value of a sizeof operator
   - we then propagate (til a fixed point) as follows:
   -- assignment propagates
   -- multiplication propagates
   -- addition should create/lookup a new type, but just output a warning for now
   -- subtraction?
   -- memory operations: warn if we write a sizeof to memory (see below).
   
   How do we interpret the CIL tree as SSA values?
   -- recall: we have instructions, expressions and statements
   -- expressions are trees, and have no effect
   -- instructions have a single effect (and may contain one or more expressions)
   -- statement have control flow [only].
   
   So we have to
   -- visit whole functions, not instructions
   -- recursively consider expressions
   -- for a single instruction, update an environment of local variables
   -- propagate this environment across control flow sequencing/branching
   -- merge this environment across control flow joins
   ... noting that any stmt may be a join; need to check its preds to see
   
   PROBLEM: helper functions which calculate a sizeof?
   -- we can identify which functions *return* a sizeof
   -- hmm, but what about writing a sizeof into a shared object?
   -- okay -- we can identify which functions *output* a sizeof (i.e write it into non-local storage)

 *)
let rec untilFixedPoint f initialValue = begin
  let printEl (vnum, ts) = "(" ^ string_of_int (vnum) ^ ", " ^ (Pretty.sprint 80 (d_typsig () ts)) ^ ") "
  in 
  let listAsString = "[" ^ (fold_left (^) "" (map printEl initialValue)) ^ "]"
  in
  output_string Pervasives.stderr ("hello from untilFixedPoint with initialValue " ^ listAsString ^ "\n"); 
  let newValue = f initialValue in
  if newValue = initialValue then initialValue else untilFixedPoint f newValue
end

let rec accumulateOverStatements acc (stmts: Cil.stmt list) =
(* Our input is an environment mapping local variables to sizeofness, 
   and a collection of statements. 
   We propagate sizeofness from predecessor statements to successor statements, 
   but how? 
   We could take a completely flow-insensitive approach 
   and simply ignore the pred/succ structure in stmts, 
   instead just considering each instruction across all stmts. 
   Let's try this. *)
   let rec accumulateOverOneInstr acc i = (* output_string Pervasives.stderr "hello from accumulateOverOneInstr\n"; flush Pervasives.stderr; *)
       match i with
         Call(_, f, args, l) -> acc
       | Set((host, off), e, l) -> begin 
           match host with
            Var(v) -> if v.vglob then acc else begin
               match getSizeExpr e acc with
                 Existing(t) -> (
                 (* output_string Pervasives.stderr ("found some sizeofness in assignment to: " ^ (Pretty.sprint 80 (Pretty.dprintf  "\t%a\t" d_lval (host, off))) ^ " (vid " ^ (string_of_int v.vid) ^ ", sizeofTypsig " ^ (Pretty.sprint 80 (Pretty.dprintf "%a" d_typsig t)) ^  ")\n")
                 ; flush Pervasives.stderr; *) (v.vid, t) :: (remove_assoc v.vid acc))
              |  _ -> acc
            end
          | Mem(e) -> acc
         end 
       | Asm(_, _, _, _, _, l) -> acc
   in
   let rec accumulateOverInstrs acc instrs = 
     (* output_string Pervasives.stderr "hello from accumulateOverInstrs\n"; flush Pervasives.stderr; *)
     match instrs with 
            [] -> acc
    |  i :: is -> accumulateOverInstrs (accumulateOverOneInstr acc i) is
   in
   let rec accumulateOneStatement acc s = 
      (* output_string Pervasives.stderr (Pretty.sprint 80 
       (Pretty.dprintf  "Hello from accumulateOneStatement\n\t%a\t\n" d_stmt s)); 
      flush Pervasives.stderr; *)
      match s.skind with
        Instr(is: instr list) -> accumulateOverInstrs acc is
   (*
   |    Return(e : exp option, l : location) ->
   |    Goto(s: stmt ref, l : location) ->
   |    Break(l : location) ->
   |    Continue (l : location) ->
    *) 
   |    Block(b) -> (* recurse over the block's stmts *) accumulateOverStatements acc b.bstmts
   |    If (e, b1, b2, l) -> accumulateOverStatements (accumulateOverStatements acc b2.bstmts) b1.bstmts
   |    Switch (e, b, ss, l) -> accumulateOverStatements (accumulateOverStatements acc ss) b.bstmts
   |    Loop (b, l, continueLabel, breakLabel) -> accumulateOverStatements acc b.bstmts
   |    TryFinally (tryBlock, finallyBlock, l) -> accumulateOverStatements (accumulateOverStatements acc tryBlock.bstmts) finallyBlock.bstmts 
   |    TryExcept (tryBlock, _, exceptBlock, l)
         -> accumulateOverStatements (accumulateOverStatements acc tryBlock.bstmts) exceptBlock.bstmts (* FIXME: instr list doesn't get handled*) 
   | _ -> acc
   in 
   match stmts with 
     [] -> acc
  |  s :: ss -> accumulateOverStatements (accumulateOneStatement acc s) ss


let rec propagateSizeEnv stmts env = accumulateOverStatements env stmts

class dumpAllocsVisitor = fun (fl: Cil.file) -> object(self)
  inherit nopCilVisitor
  
  (* where we will write our alloc data *)
  val outChannel : out_channel option ref = ref None
  
  (* the mapping of local variables to their sizeofness *)
  val sizeEnv : (int * typsig) list ref = ref []
  
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
   

  method vfunc (f: fundec) : fundec visitAction = 
    Cil.prepareCFG(f);
    Cil.computeCFGInfo f false; 
    sizeEnv := untilFixedPoint (propagateSizeEnv f.sallstmts) []; 
    (* now we know which locals are sizes, we can visit calls -- in vinstr *)
    DoChildren

  method vinst (i: instr) : instr list visitAction = 
    ( output_string Pervasives.stderr ("considering instruction " ^ (
       match i with 
          Call(_, _, _, l) -> "(call) at " ^ l.file ^ ", line: " ^ (string_of_int l.line)
        | Set(_, _, l) -> "(assignment) at " ^ l.file ^ ", line: " ^ (string_of_int l.line)
        | Asm(_, _, _, _, _, l) -> "(assembly) at " ^ l.file ^ ", line: " ^ (string_of_int l.line)
      ) ^ "\n"); flush Pervasives.stderr);
      match i with 
      Call(_, funExpr, args, l) -> begin
         let handleCall maybeFunvar functionTs = begin
          match functionTs with 
          | TSFun(returnType, optParamList, isVarArgs, attrs) -> begin
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
              match (getAllocExpr i maybeFunvar args !sizeEnv functionTs) with
                 Some(ts) -> printAllocFn fileAndLine chan maybeFunvar (symnameFromSig ts); SkipChildren
              |  _ -> 
                  (* (output_string Pervasives.stderr (
                     "skipping call to function " ^ v.vname ^ " since getAllocExpr returned None\n"
                  ) ; flush Pervasives.stderr;  *) SkipChildren(* ) *) (* this means it's not an allocation function *)
            end (* ) *)
          end
        | _ -> raise(Failure "impossible function type")
        end
        in
        let getCalledFunctionOrFunctionPointerTypeSig fexp : Cil.typsig * Cil.varinfo option = 
           match fexp with 
             Lval(Var(v), NoOffset) -> ((typeSig v.vtype), Some(v))
         |   _ -> (typeSig (typeOf fexp), None)
        in 
        let (functionTs, maybeVarinfo) = getCalledFunctionOrFunctionPointerTypeSig funExpr
        in
        match functionTs with
          TSFun(returnTs, paramTss, isVarArgs, attrs) -> handleCall maybeVarinfo functionTs
        | TSPtr(fts, ptrAttrs) -> handleCall (None) fts
        | _ -> raise (Failure("impossible called function typesig" ^ (Pretty.sprint 80 (d_typsig () functionTs))))
        
        (* TSPtr(TSFun(returnTs, paramTss, isVarArgs, funAttrs), ptrAttrs) -> handleCall None returnTs paramTss isVarArgs funAttrs
               | _ (* match v.vtype *) -> (output_string Pervasives.stderr ("skipping call to non-function var " ^ v.vname ^ "\n"); flush Pervasives.stderr; SkipChildren)
             end
        | _ (* match f *) -> (output_string Pervasives.stderr ("skipping call to non-lvalue at " ^ l.file ^ ":" ^ (string_of_int l.line) ^ "\n"); flush Pervasives.stderr; SkipChildren)
        *)
      end 
    | Set(lv, e, l) -> (* (output_string Pervasives.stderr ("skipping assignment at " ^ l.file ^ ":" ^ (string_of_int l.line) ^ "\n" ); flush Pervasives.stderr; *) SkipChildren (* ) *)
    | Asm(_, _, _, _, _, l) -> (* (output_string Pervasives.stderr ("skipping assignment at " ^ l.file ^ ":" ^ (string_of_int l.line) ^ "\n" ); *) SkipChildren (* ) *)
   (* ) *)
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

