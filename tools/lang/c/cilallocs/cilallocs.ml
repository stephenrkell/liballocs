(* Copyright (c) 2011--14,
 *  Stephen Kell        <stephen.kell@cl.cam.ac.uk>
 *
 * with portions taken from logwrites.ml, which is 
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
open Map
open Cil
open Hashtbl
module NamedTypeMap = Map.Make(String)

let list_empty l = not (List.exists (fun x -> true) l)

let expToString e      = (Pretty.sprint 80 (Pretty.dprintf "%a" d_exp e))
let instToString i     = (Pretty.sprint 80 (Pretty.dprintf "%a" d_instr i))
let instToCilString i  = (Pretty.sprint 80 (printInstr (new plainCilPrinterClass) () i))
let lvalToString lv    = (Pretty.sprint 80 (Pretty.dprintf "%a" d_lval lv))
let offsetToString o   = (Pretty.sprint 80 (Pretty.dprintf "%a" (d_offset (d_formatarg () (Fg("")))) o))
let typToString t      = (Pretty.sprint 80 (Pretty.dprintf "%a" d_type t))
let typsigToString ts  = (Pretty.sprint 80 (Pretty.dprintf "%a" d_typsig ts))
let expToCilString e   = (Pretty.sprint 80 (printExp  (new plainCilPrinterClass) () e))
let lvalToCilString lv = (Pretty.sprint 80 (printLval (new plainCilPrinterClass) () lv))
let attrsToString atts = (Pretty.sprint 80 (Pretty.dprintf "%a" d_attrlist atts))

(* Bitfield utilities borrowed from logwrites.ml *)
let rec isBitfieldOffset lo = match lo with
  | NoOffset -> false
  | Field(fi,NoOffset) -> not (fi.fbitfield = None)
  | Field(_,lo) -> isBitfieldOffset lo
  | Index(_,lo) -> isBitfieldOffset lo
(* Return an expression that evaluates to the address of the given lvalue.
 * For most lvalues, this is merely AddrOf(lv). However, for bitfields
 * we do some offset gymnastics. 
 *)
let addrOfLv (lv: lval) = 
  let lh, lo = lv in 
  if not (isBitfieldOffset lo) then mkAddrOf lv
  else begin
    (* we figure out what the address would be without the final bitfield
     * access, and then we add in the offset of the bitfield from the
     * beginning of its enclosing comp *) 
    let rec splitOffsetAndBitfield lo = match lo with 
      | NoOffset -> failwith "logwrites: impossible" 
      | Field(fi,NoOffset) -> (NoOffset,fi)
      | Field(e,lo) ->  let a,b = splitOffsetAndBitfield lo in 
                        ((Field(e,a)),b)
      | Index(e,lo) ->  let a,b = splitOffsetAndBitfield lo in
                        ((Index(e,a)),b)
    in 
    let new_lv_offset, bf = splitOffsetAndBitfield lo in
    let new_lv = (lh, new_lv_offset) in 
    let enclosing_type = TComp(bf.fcomp, []) in 
    let bits_offset, bits_width = 
      bitsOffset enclosing_type (Field(bf,NoOffset)) in
    let bytes_offset = bits_offset / 8 in
    let lvPtr = mkCast ~e:(mkAddrOf (new_lv)) ~newt:(charPtrType) in
    (BinOp(PlusPI, lvPtr, (integer bytes_offset), ulongType))
  end

(* Module-ify Cil.typSig *)
module CilTypeSig = struct
   type t = Cil.typsig
   let compare ts1 ts2 = String.compare (Pretty.sprint 80 (d_typsig () ts1)) (Pretty.sprint 80 (d_typsig () ts2))
end

module UniqtypeMap = Map.Make(CilTypeSig)

(* Module-ify Cil.varinfo *)
module CilVarinfo = struct
   type t = Cil.varinfo
   let compare vi1 vi2 = String.compare vi1.vname vi2.vname
end

module VarinfoMap = Map.Make(CilVarinfo)

(* Module-ify Cil.lval *)
module CilLval = struct
   type t = Cil.lval
   (* HACK *)
   let compare lv1 lv2 = String.compare (lvalToCilString lv1) (lvalToCilString lv2)
end

module LvalMap = Map.Make(CilLval)

let rec offsetToList (o : offset) = 
    match o with
        NoOffset -> []
      | Field(fi, rest) -> Field(fi, NoOffset) :: (offsetToList rest)
      | Index(intExp, rest) -> Index(intExp, NoOffset) :: (offsetToList rest)

let rec offsetFromList (ol : offset list) = 
    match ol with
        [] -> NoOffset
      | Field(fi, _) :: rest -> Field(fi, offsetFromList rest)
      | Index(intExp, _) :: rest -> Index(intExp, offsetFromList rest)
      | NoOffset :: rest -> offsetFromList rest

let rec offsetPrefixAsList (o : offset) (suffix : offset) = 
    match o with
        _ when o = suffix -> []
      | NoOffset -> failwith "didn't find offset suffix"
      | Field(fi, rest) -> Field(fi, NoOffset) :: (offsetPrefixAsList rest suffix)
      | Index(intExp, rest) -> Index(intExp, NoOffset) :: (offsetPrefixAsList rest suffix)

let rec offsetPrefix (o : offset) (suffix : offset) = 
    match o with
        _ when o = suffix -> NoOffset
      | NoOffset -> failwith "didn't find offset suffix"
      | Field(fi, rest) -> Field(fi, (offsetPrefix rest suffix))
      | Index(intExp, rest) -> Index(intExp, (offsetPrefix rest suffix))

let offsetAppend off rest = offsetFromList ((offsetToList off) @ (offsetToList rest))

let stringEndsWith (s : string) (e : string) : bool = 
    (String.length s) >= (String.length e) &&
    String.sub s ((String.length s) - (String.length e)) (String.length e) = e

(* Zip two lists (possibly unequal lengths) into a tuple *)
let rec zip lst1 lst2 = match lst1,lst2 with
  | [],_ -> []
  | _, []-> []
  | (x::xs),(y::ys) -> (x,y) :: (zip xs ys)
(* unzip -- thank you StackOverflow http://stackoverflow.com/questions/21627749/recursion-in-ocaml *)
let unzip l = 
  let rec unzip_aux (l1,l2) = function
    | [] -> List.rev l1, List.rev l2
    | (x,y)::tl -> unzip_aux (x::l1, y::l2) tl
  in 
  unzip_aux ([],[]) l

let foldConstants e = visitCilExpr (Cil.constFoldVisitor true) e

let makeIntegerConstant n = Const(CInt(n, IInt, None))

let isStaticallyZero e = isZero (foldConstants e) 

let rec isStaticallyNullPtr e = match (typeSig (typeOf e)) with
    TSPtr(_) -> begin match e with
            CastE(targetT, subE) ->
                if isPointerType (typeOf subE) then isStaticallyNullPtr subE
                else isStaticallyZero subE
          | _ -> isStaticallyZero e
        end
  | _ -> false

let rec isStaticallyNull e = isStaticallyZero e || isStaticallyNullPtr e

let constInt64ValueOfExprNoChr (intExp: Cil.exp) : int64 option =
    match (foldConstants intExp) with
        Const(CInt(intValue, _, _)) ->
            Some(int64_of_cilint intValue)
      | _ -> None
  
let constInt64ValueOfExpr (intExp: Cil.exp) : int64 option =
    match (foldConstants intExp) with
      | Const(CChr(chrValue)) -> constInt64ValueOfExprNoChr (Const(charConstToInt chrValue))
      | _ -> constInt64ValueOfExprNoChr intExp

let nullPtr = CastE( TPtr(TVoid([]), []) , zero )
let one = Const(CInt((cilint_of_int64 (Int64.of_int 1)), IInt, None))
let onePtr = CastE( TPtr(TVoid([]), []) , one )
let negativeOne = Const(CInt(cilint_of_int64 (Int64.of_int (0-1)), IInt, None))
let negativeOnePtr = CastE( TPtr(TVoid([]), []) , negativeOne )

let debug_print lvl s = 
  let level = try begin 
    let levelString = (Sys.getenv "DEBUG_CC")
    in
    int_of_string levelString
  end with Not_found -> 0 | Failure(_) -> 0
  in
  if level >= lvl then (output_string Out_channel.stderr s; flush Out_channel.stderr) else ()

(* HACKed realpath for now: *)
let abspath f =
   if String.get f 0 = '/' then f else (getcwd ()) ^ "/" ^ f

exception Empty

(* stolen from StackOverflow:  http://stackoverflow.com/questions/1584758/ *)
let trim str =   
    if str = "" then "" 
    else   
        let search_pos init p next =
            let rec search i = if p i then raise Empty else match str.[i] with
              | ' ' | '\n' | '\r' | '\t' -> search (next i)
              | _ -> i
            in
            search init   
        in   
        let len = String.length str in   
        try
            let left = search_pos 0 (fun i -> i >= len) (Stdlib.succ)
            and right = search_pos (len - 1) (fun i -> i < 0) (Stdlib.pred)
            in
            String.sub str left (right - left + 1)   
        with Empty -> ""

(* NOTE: this needs to match the escaping done by mangle_string
 * in liballocstool's uniqtypes.hpp. *)
let identFromString s =
   let dollarDoubled = Str.global_replace (Str.regexp "\\$") "$$" s in
   Str.global_substitute (Str.regexp "[^a-zA-Z0-9_\\$]") (fun wholeStr ->
     let c = (Str.matched_string wholeStr).[0] in
     ("$" ^ (Printf.sprintf "%02x" (int_of_char c)))
   ) dollarDoubled

let rec canonicalizeBaseTypeStr s = 
 (* 'generated' from a table maintained in srk's libcxxgen  *)
if (s = "signed char" || s = "char" || s = "char signed" ||  false) then "signed char"
else if (s = "unsigned char" || s = "char unsigned" ||  false) then "unsigned char"
else if (s = "short int" || s = "short" || s = "int short" ||  false) then "short int"
else if (s = "short unsigned int" || s = "unsigned short" || s = "short unsigned" || s = "unsigned short int" || s = "int unsigned short" || s = "int short unsigned" || s = "unsigned int short" || s = "short int unsigned" ||  false) then "short unsigned int"
else if (s = "int" || s = "signed" || s = "signed int" || s = "int signed" ||  false) then "int"
else if (s = "unsigned int" || s = "unsigned" || s = "int unsigned" ||  false) then "unsigned int"
else if (s = "long int" || s = "long" || s = "int long" || s = "signed long int" || s = "int signed long" || s = "int long signed" || s = "long signed int" || s = "signed int long" || s = "long signed" || s = "signed long" ||  false) then "long int"
else if (s = "unsigned long int" || s = "int unsigned long" || s = "int long unsigned" || s = "long unsigned int" || s = "unsigned int long" || s = "long unsigned" || s = "unsigned long" ||  false) then "unsigned long int"
else if (s = "long long int" || s = "long long" || s = "long int long" || s = "int long long" || s = "long long signed" || s = "long signed long" || s = "signed long long" || s = "long long int signed" || s = "long long signed int" || s = "long signed long int" || s = "signed long long int" || s = "long int long signed" || s = "long int signed long" || s = "long signed int long" || s = "signed long int long" || s = "int long long signed" || s = "int long signed long" || s = "int signed long long" || s = "signed int long long" ||  false) then "long long int"
else if (s = "long long unsigned int" || s = "long long unsigned" || s = "long unsigned long" || s = "unsigned long long" || s = "long long int unsigned" || s = "long unsigned long int" || s = "unsigned long long int" || s = "long int long unsigned" || s = "long int unsigned long" || s = "long unsigned int long" || s = "unsigned long int long" || s = "int long long unsigned" || s = "int long unsigned long" || s = "int unsigned long long" || s = "unsigned int long long" ||  false) then "long long unsigned int"
else if (s = "float" ||  false) then "float"
else if (s = "double" ||  false) then "double"
else if (s = "long double" || s = "double long" ||  false) then "long double"
else if (s = "bool" ||  false) then "bool"
else if (s = "wchar_t" ||  false) then "wchar_t"
  else s

(* See DW_ATE_* in dwarf.h for these names (we strip "DW_ATE_" and
 * XXX need a special case for signed and unsigned int; see libdwarfpp's
 * base_type_die::canonical_name_for()  (in dies.cpp). FIXME: stop it from doing that?! *)
let dwarfEncodingForBaseType t = match t with
     TInt(IChar, attrs) -> if !(Machdep.theMachine).char_is_unsigned then "unsigned_char" else "signed_char"
   | TInt(ISChar, attrs) -> "signed_char"
   | TInt(IUChar, attrs) -> "unsigned_char"
   | TInt(IBool, attrs) -> "boolean"
   | TInt(IInt, attrs) -> "int"
   | TInt(IUInt, attrs) -> "uint"
   | TInt(IShort, attrs) -> "int"
   | TInt(IUShort, attrs) -> "uint"
   | TInt(ILong, attrs) -> "int"
   | TInt(IULong, attrs) -> "uint"
   | TInt(ILongLong, attrs) -> "int"
   | TInt(IULongLong, attrs) -> "uint"
   | TFloat(FFloat, attrs) -> "float"
   | TFloat(FDouble, attrs) -> "float"
   | TFloat(FLongDouble, attrs) -> "float"
   | _ -> raise(Failure ("bad base type: " ^ (Pretty.sprint 80 (Pretty.dprintf "%a" d_type t))))

let baseTypeRawStr t =
  match t with
     TBuiltin_va_list(attrs) -> "__builtin_va_list"
   | _ -> (dwarfEncodingForBaseType t) ^ "$" ^ string_of_int (Cil.bitsSizeOf t)

let baseTypeStr t = identFromString (baseTypeRawStr t)

(* dwarfidl has a latent escaping convention in its ident syntax, to allow 
 * idents to easily encode near-arbitrary strings. Yes, this is sane. *)
let dwarfidlIdent str = Str.global_replace (Str.regexp "\\([ :]\\)") "\\\\\\1" str

let rec barenameFromSig ts = 
 let rec labelledArgTs ts startAt =
   match ts with
     [] -> ""
  | t :: morets -> 
      let remainder = (labelledArgTs morets (startAt + 1))
      in
      "__ARG" ^ (string_of_int startAt) ^ "_" ^ (barenameFromSig t) ^ remainder
 in
 match ts with
   TSArray(tNestedSig, optSz, attrs) -> "__ARR" ^ (match optSz with Some(s) -> (string_of_int (i64_to_int (int64_of_cilint s))) | None -> "0") ^ "_" ^ (barenameFromSig tNestedSig)
 | TSPtr(tNestedSig, attrs) -> "__PTR_" ^ (barenameFromSig tNestedSig)
 | TSComp(isSpecial, name, attrs) -> name
 | TSFun(returnTs, Some(argsTss), false, attrs) -> 
       "__FUN_FROM_" ^ (labelledArgTs argsTss 0) ^ "__FUN_TO_" ^ (barenameFromSig returnTs)
 | TSFun(returnTs, Some(argsTss), true, attrs) -> 
       "__FUN_FROM_" ^ (labelledArgTs argsTss 0) ^ "__VA___FUN_TO_" ^ (barenameFromSig returnTs)
 | TSFun(returnTs, None, true, attrs) -> 
        "__FUN_FROM___VA___FUN_TO_" ^ (barenameFromSig returnTs)
 | TSFun(returnTs, None, false, attrs) -> 
        "__FUN_FROM___FUN_TO_" ^ (barenameFromSig returnTs)
 | TSEnum(enumName, attrs) -> enumName
 | TSBase(TVoid(attrs)) -> "void"
 | TSBase(tbase) -> baseTypeStr tbase

let rec dwarfidlFromSig ts = 
 let rec dwarfidlLabelledArgTs ts startAt =
   match ts with
     [] -> ""
  |  [t] -> dwarfidlFromSig t
  | t :: morets -> 
      let remainder = (dwarfidlLabelledArgTs morets (startAt + 1))
      in
      (dwarfidlFromSig t) ^ ", " ^ remainder
 in
 match ts with
   TSArray(tNestedSig, optSz, attrs)
     -> "(array_type [type = " ^ (dwarfidlFromSig tNestedSig) ^ "] {" 
        ^ (match optSz with Some(s) -> ("subrange_type [upper_bound = " ^ (string_of_int (i64_to_int (int64_of_cilint s))) ^ "];") | None -> "") ^ " })"
 | TSPtr(tNestedSig, attrs) -> "(pointer_type [type = " ^ (dwarfidlFromSig tNestedSig) ^ "];)" 
 | TSComp(isSpecial, name, attrs) -> name
 | TSFun(returnTs, Some(argsTss), false, attrs) -> 
       "(" ^ (dwarfidlLabelledArgTs argsTss 0) ^ ") => " ^ (dwarfidlFromSig returnTs)
 | TSFun(returnTs, Some(argsTss), true, attrs) -> 
       "(" ^ (dwarfidlLabelledArgTs argsTss 0) ^ ", ...)" ^ (dwarfidlFromSig returnTs)
 | TSFun(returnTs, None, true, attrs) -> 
        "(...) => " ^ (barenameFromSig returnTs)
 | TSFun(returnTs, None, false, attrs) -> 
        "() => " ^ (barenameFromSig returnTs)
 | TSEnum(enumName, attrs) -> enumName
 | TSBase(TVoid(attrs)) -> "(unspecified_type)"
 | TSBase(tbase) -> dwarfidlIdent (baseTypeRawStr tbase)

let userTypeNameToBareName s = identFromString (canonicalizeBaseTypeStr (trim s))

let symnameFromSig ts = "__uniqtype_" ^ "" ^ "_" ^ (barenameFromSig ts)

(* CIL doesn't give us a const void * type builtin, so we define one. *)
let voidConstPtrType = TPtr(TVoid([Attr("const", [])]),[])
let voidConstPtrPtrType = TPtr(TPtr(TVoid([Attr("const", [])]),[]), [])
(* ditto for some more * *)
let ulongPtrType = TPtr(TInt(IULong, []),[])
let voidPtrPtrType = TPtr(TPtr(TVoid([]),[]),[])
let boolType = TInt(IBool, [])

(* This effectively embodies our "default specification" for C code
 * -- it controls what we assert in "__is_a" tests, and
 * needs to mirror what we record for allocation sites in dumpallocs *)
let rec getConcreteType ts =
 match ts with
   TSArray(tsig, optSz, attrs) -> getConcreteType tsig
 | TSPtr(tsig, attrs) -> TSPtr(getConcreteType tsig, []) (* stays a pointer, but discard attributes *)
 | TSComp(isSpecial, name, attrs) -> TSComp(isSpecial, name, [])
 | TSFun(returnTs, argsTss, isSpecial, attrs) -> TSFun(returnTs, argsTss, isSpecial, [])
 | TSEnum(enumName, attrs) -> TSEnum(enumName, [])
 | TSBase(TVoid(attrs)) -> TSBase(TVoid([]))
 | TSBase(TInt(kind,attrs)) -> TSBase(TInt(kind, []))
 | TSBase(TFloat(kind,attrs)) -> TSBase(TFloat(kind, []))
 | _ -> ts

(* This will turn "array of [array of...] X" into "X". *)
let rec decayArrayInTypesig ts = match ts with
   TSArray(tsig, optSz, attrs) -> decayArrayInTypesig tsig (* recurse for multidim arrays *)
 | _ -> ts

(* This will turn "array of [array of...] X" into "(X, maybe numXs)". *)
let rec accumulateArrayDimensionsInTypesig ts = match ts with
   TSArray(tsig, Some(sz), attrs) ->  (* recurse for multidim arrays *)
        (match accumulateArrayDimensionsInTypesig tsig with
            (ts, Some(subN)) -> (ts, Some(Int64.mul (int64_of_cilint sz) subN))
          | (ts, None) -> (ts, None)
        )
 | TSArray(tsig, None, attrs) -> (* recurse for multidim arrays *)
    (decayArrayInTypesig tsig, None)
 | _ -> (ts, None)

(* This will turn "array of array of [array of...] X" into "array of X",
 * tweaking the dimension if we have one. *)
let rec collapseArrayDimensionsInTypesig ts = match ts with
   TSArray(tsig, _, attrs) when (match tsig with (TSArray(_, _, _)) -> true | _ -> false)
     -> (* tsig is also an array, so ... *)
        let ts, maybeSz = accumulateArrayDimensionsInTypesig ts
        in
        TSArray(ts, Option.map cilint_of_int64 maybeSz, attrs)
 | _ -> ts

(* This will make a "pointer to array of X" typesig into a "pointer to X" typesig.
 * And similarly for "pointer to array of pointer to array of X" -- 
 *      it becomes "pointer to pointer to X".
 * And similarly for "pointer to array of array of... X" -- it becomes "pointer to X". *)
let rec decayArrayInPointeeTypesig ts = match ts with
   TSPtr(TSArray(tsig, optSz, arrAttrs), ptrAttrs)
    -> TSPtr(decayArrayInPointeeTypesig (collapseArrayDimensionsInTypesig tsig), ptrAttrs)
 | TSPtr(tsig, attrs) -> TSPtr(decayArrayInPointeeTypesig tsig, attrs)
 | _ -> ts

(* This will turn "array of [array of...] X" into "pointer to X". 
 * And for any pointed-to arrays within X, will do the same. *)
let rec decayArrayToCompatiblePointer ts = match ts with
   TSArray(tsig, optSz, attrs) -> TSPtr(decayArrayToCompatiblePointer(decayArrayInTypesig tsig), attrs)
 | TSPtr(tsig, attrs) -> TSPtr(decayArrayToCompatiblePointer tsig, attrs)
 | _ -> ts

let exprConcreteType e = getConcreteType (Cil.typeSig (Cil.typeOf e))

(* This function's name is plural because it simplifies nested expressions too. *)
let rec simplifyPtrExprs someE =
  (* Try to see through AddrOf and Mems to get down to a local lval if possible. 
   * Here we are applying the equivalences from the CIL documentation.
   * We first simplify any nested pointer expressions
   * (which may nest inside *non*-pointer expressions!)
   * then simplify the whole. This is necessary to, say, turn
   * "*&*&*&*&p" into "p". *)
  let rec simplifyOffset offs = match offs with
      NoOffset -> NoOffset
    | Field(fi, rest) -> Field(fi, simplifyOffset rest)
    | Index(intExp, rest) -> Index(simplifyPtrExprs intExp, simplifyOffset rest)
  in
  let withSubExprsSimplified = match someE with
    |Lval(Var(vi), offs) -> Lval(Var(vi), simplifyOffset offs)
    |Lval(Mem(subE), offs) -> Lval(Mem(simplifyPtrExprs subE), simplifyOffset offs)
    |UnOp(op, subE, subT) -> UnOp(op, simplifyPtrExprs subE, subT)
    |BinOp(op, subE1, subE2, subT) -> BinOp(op, simplifyPtrExprs subE1, simplifyPtrExprs subE2, subT)
    |CastE(subT, subE) -> 
        let simplifiedSubE = simplifyPtrExprs subE
        in
        if getConcreteType (Cil.typeSig subT) = getConcreteType (Cil.typeSig (Cil.typeOf simplifiedSubE))
        then simplifiedSubE else CastE(subT, simplifiedSubE)
    |AddrOf(Var(vi), offs) -> AddrOf(Var(vi), simplifyOffset offs)
    |AddrOf(Mem(subE), offs) -> AddrOf(Mem(simplifyPtrExprs subE), simplifyOffset offs)
    |StartOf(Var(vi), offs) -> StartOf(Var(vi), simplifyOffset offs)
    |StartOf(Mem(subE), offs) -> StartOf(Mem(simplifyPtrExprs subE), simplifyOffset offs)
    |_ -> someE
  in
  match withSubExprsSimplified with
     (* e.g.  (&p->foo)->bar           is   p->foo.bar      *)
     Lval(Mem(AddrOf(Mem a, aoff)), off) -> 
        Lval(Mem a, offsetFromList((offsetToList aoff) @ (offsetToList off)))
     (* e.g.  (&v.baz)->bum            is   v.baz.bum       *)
   | Lval(Mem(AddrOf(Var v, aoff)), off) -> 
        Lval(Var v, offsetFromList((offsetToList aoff) @ (offsetToList off)))
     (* e.g.  &*p                      is   p               *)
   | AddrOf (Mem a, NoOffset)            -> a
     (* note that unlike &( *p ),
              &p->f   (i.e. with some offset)  cannot be simplified          *)
   | StartOf (Mem s, NoOffset) ->
     (* only NoOffset because unlike *p    (where p is of pointer-to-array type),
              p->arr  (i.e. some offset) cannot be simplified      *)
     (* PROBLEM: we want to yield just "s", but this changes the type.
      * What's simpler: StartOf(Mem x, NoOffset) or CastE(t, x)?
      * We say the latter. *)
        CastE(Cil.typeOf withSubExprsSimplified, s)
   | _ -> withSubExprsSimplified

let matchIgnoringLocation g1 g2 = match g1 with 
    GType(ti, loc) ->        begin match g2 with GType(ti2, _)        -> ti = ti2 | _ -> false end
  | GCompTag(ci, loc) ->     begin match g2 with GCompTag(ci2, _)     -> ci = ci2 | _ -> false end
  | GCompTagDecl(ci, loc) -> begin match g2 with GCompTagDecl(ci2, _) -> ci = ci2 | _ -> false end
  | GEnumTag(ei, loc) ->     begin match g2 with GEnumTag(ei2, _)     -> ei = ei2 | _ -> false end
  | GEnumTagDecl(ei, loc) -> begin match g2 with GEnumTagDecl(ei2, _) -> ei = ei2 | _ -> false end
  | GVarDecl(vi, loc) ->     begin match g2 with GVarDecl(vi2, loc)   -> vi = vi2 | _ -> false end
  | GVar(vi, ii, loc) ->     begin match g2 with GVar(vi2, ii2, loc)  -> ((vi = vi2) (* and (ii = ii2) *)) | _ -> false end
  | GFun(f, loc) ->          begin match g2 with GFun(f2, loc)        -> f  = f2  | _ -> false end
  | GAsm(s, loc) ->          begin match g2 with GAsm(s2, loc)        -> s  = s2  | _ -> false end
  | GPragma(a, loc) ->       begin match g2 with GPragma(a2, loc)     -> a  = a2  | _ -> false end
  | GText(s) ->              begin match g2 with GText(s2)            -> s  = s2  | _ -> false end
  | GStaticAssert(e,s,l) ->  begin match g2 with GStaticAssert(e2,s2,_)-> e=e2 && s=s2 | _ -> false end

let isFunction g = match g with
  GFun(_, _) -> true
| _ -> false

let isNonVoidPointerType t = match (getConcreteType (typeSig t)) with
    TSPtr(TSBase(TVoid(_)), _) -> false
  | TSPtr(_) -> true
  | _ -> false

let isPointerType t = match (getConcreteType (typeSig t)) with
    TSPtr(_, _) -> true
  | _ -> false

let isVoidPointerType t = match (getConcreteType (typeSig t)) with
    TSPtr(TSBase(TVoid(_)), _) -> true
  | _ -> false

let rec indirectionLevel someTs = match someTs with
    TSPtr(subTs, _) -> 1 + indirectionLevel subTs
  | _ -> 0

let rec ultimatePointeeTs someTs = match someTs with
    TSPtr(TSPtr(subTs, attrs), _) -> ultimatePointeeTs (TSPtr(subTs, attrs))
  | TSPtr(subTs, _) -> subTs
  | _ -> raise Not_found


let isGenericPointerTypesig ts = 
    indirectionLevel ts >= 1 &&
    let upts = ultimatePointeeTs (getConcreteType(ts))
    in
    upts = Cil.typeSig(voidType)
     || upts = Cil.typeSig(charType)

let isGenericPointerType (t : Cil.typ) =
    isGenericPointerTypesig (Cil.typeSig t)
    
let isSinglyIndirectGenericPointerTypesig ts = 
    indirectionLevel ts = 1 && isGenericPointerTypesig ts

let isSingleIndirectGenericPointerType (t : Cil.typ) =
    let ts = Cil.typeSig t
    in
    indirectionLevel ts = 1 && isGenericPointerTypesig ts

let newGlobalsList globals toAdd insertBeforePred = 
  let (preList, postList) = 
      let rec buildPre l accumPre = match l with 
          [] -> (accumPre, [])
       |  x::xs -> if (insertBeforePred x) then (accumPre, x :: xs) else buildPre xs (accumPre @ [x])
      in 
      buildPre globals []
  in
  preList @ toAdd @ postList

let rec findStructTypeByName gs n = match gs with 
    [] -> raise Not_found
  | g :: rest -> match g with 
        GCompTagDecl(c, _) when c.cstruct && c.cname = n -> TComp(c, [])
      | GCompTag(c, _) when c.cstruct && c.cname = n -> 
            (* debug_print 1 "strange; uniqtype is defined\n"; *) TComp(c, [])
      | _ -> findStructTypeByName rest n

let rec findUnionTypeByName gs n = match gs with 
    [] -> raise Not_found
  | g :: rest -> match g with 
        GCompTagDecl(c, _) when not c.cstruct && c.cname = n -> TComp(c, [])
      | GCompTag(c, _) when not c.cstruct && c.cname = n -> TComp(c, [])
      | _ -> findUnionTypeByName rest n

let getOrCreateUniqtypeGlobal m concreteType globals = 
  let typename = symnameFromSig concreteType
  in
  try 
      let found = UniqtypeMap.find concreteType m
      in
      let foundVar = match found with 
        GVarDecl(v, i) -> v
      | _ -> raise(Failure "unexpected state")
      in 
      (m, foundVar, globals)
  with Not_found -> 
     debug_print 1 ("Creating new uniqtype global for type named " ^ typename ^ "\n");
     let typeStructUniqtype = try findStructTypeByName globals "uniqtype" 
        with Not_found -> failwith "no struct uniqtype in file; why is libcrunch_cil_inlines not included?"
     in
     let newGlobal = 
       let tempGlobal = makeGlobalVar typename typeStructUniqtype; 
       in 
       tempGlobal.vstorage <- Extern;
       tempGlobal.vattr <- [Attr("weak", [])];
       tempGlobal
     in
     let newGlobalVarInfo = GVarDecl(newGlobal, {line = -1; file = "BLAH FIXME"; byte = 0; column = -1; endLine = -1; endByte = -1; endColumn = -1; synthetic = false })
     in 
     let newMap = (UniqtypeMap.add concreteType newGlobalVarInfo m)
     in 
     let newGlobals = newGlobalsList globals [newGlobalVarInfo] isFunction
     in
     (newMap, newGlobal, newGlobals)

let ensureUniqtypeGlobal concreteType enclosingFile (uniqtypeGlobals : Cil.global UniqtypeMap.t ref) = 
    debug_print 1 ("Ensuring we have uniqtype for " ^ (typsigToString concreteType) ^ "\n");
    let (updatedMap, uniqtypeGlobalVar, updatedGlobals)
     = getOrCreateUniqtypeGlobal !uniqtypeGlobals concreteType enclosingFile.globals
    in 
    enclosingFile.globals <- updatedGlobals; 
    uniqtypeGlobals := updatedMap;
    debug_print 1 ("Got uniqtype for " ^ (typsigToString concreteType) ^ "\n");
    uniqtypeGlobalVar

let findCompDefinitionInFile isStruct name wholeFile = 
    let rec findCompGlobal iss n globals = 
        match globals with
            []       -> None
        |   g :: gs  -> begin match g with
                GCompTag(ci, _) -> if ci.cstruct = isStruct && ci.cname = name then Some(g) else findCompGlobal iss n gs
              | _ -> findCompGlobal iss n gs
            end
    in
    findCompGlobal isStruct name wholeFile.globals

let findGlobalVarInFile name wholeFile = 
    let rec findGlobalVar n globals = 
        match globals with
            []       -> None
        |   g :: gs  -> begin match g with
                GVar(vi, _, _) -> if vi.vname = n then Some(vi) else 
                    findGlobalVar n gs
              | GVarDecl(vi, _) ->  if vi.vname = n then Some(vi) else 
                    findGlobalVar n gs
              | _ -> findGlobalVar n gs
            end
    in
    findGlobalVar name wholeFile.globals

let rec tsIsUndefinedType ts wholeFile = 
    let rec anyTsIsUndefined tss = match tss with
        []          -> false
      | ts1 :: more -> (tsIsUndefinedType ts1 wholeFile) || (anyTsIsUndefined more)
    in
    match ts with
        TSArray(tsig, optSz, attrs)                 -> tsIsUndefinedType tsig wholeFile
    |   TSPtr(tsig, attrs)                          -> tsIsUndefinedType tsig wholeFile
    |   TSComp(isStruct, name, attrs)               -> (findCompDefinitionInFile isStruct name wholeFile) = None
    |   TSFun(returnTs, Some(argsTss), isVarargs, attrs)  ->
            tsIsUndefinedType returnTs wholeFile || anyTsIsUndefined argsTss
    |   TSFun(returnTs, None, isVarargs, attrs)  ->
            tsIsUndefinedType returnTs wholeFile
    |   _                                           -> false

let tsIsIncompleteType ts wholeFile = tsIsUndefinedType ts wholeFile

let rec findFun nm gs = match gs with
  [] -> None
|  g :: gg -> match g with 
        GFun(dec, _) ->
            (* output_string stderr ("saw a function, name " ^ dec.svar.vname ^ "\n"); *)
            if dec.svar.vname = nm then Some(dec) else findFun nm gg
      | _ -> findFun nm gg

let rec findVarDecl nm gs = match gs with
  [] -> None
|  g :: gg -> match g with
        GVarDecl(svar, _) ->
            if svar.vname = nm then Some(svar) else findVarDecl nm gg
      | _ -> findVarDecl nm gg

let rec findFunOrFail nm gs = match findFun nm gs with
  None -> failwith ("findFun failed: " ^ nm)
| Some f -> f

let materialiseBuiltin nm =
    let (retT, argTs, isVa) = Hashtbl.find Cil.builtinFunctions nm
    in
    let f = emptyFunction nm
    in
    f.svar.vtype <- (TFun(retT, 
        Some(List.mapi (fun i -> fun t -> ("arg" ^ (string_of_int i), t, [])) argTs),
        isVa, 
        []));
    f

let findOrCreateExternalFunctionInFile fl nm proto : fundec = (* findOrCreateFunc fl nm proto *) (* NO! doesn't let us have the fundec *)
  match findFun nm fl.globals with 
    Some(d) -> d
  | None -> let funDec = emptyFunction nm in
        funDec.svar.vtype <- proto;
   let loc = {line = -1; file = "BLAH FIXME"; byte = 0; column = -1; endLine = -1; endByte = -1; endColumn = -1; synthetic = false } in
        funDec

let findOrCreateNewFunctionInFile fl nm proto l createBeforePred : fundec = (* findOrCreateFunc fl nm proto *) (* NO! doesn't let us have the fundec *)
  match findFun nm fl.globals with 
    Some(d) -> d
  | None -> let funDec = emptyFunction nm in
        funDec.svar.vtype <- proto;
        fl.globals <- newGlobalsList fl.globals [GFun(funDec, l)] 
        (* insert it after any -include'd definitions, but before any coming from the file itself. *)
            createBeforePred;
        funDec

let makeInlineFunctionInFile fl ourFun nm proto body referencedValues = begin
   let protoArgs = match proto with 
     TFun(_, Some l, _, _) -> l
   | _ -> []
   in
   let protoWithInlineAttrs = match proto with 
     TFun(retT, args, isVarargs, attrs) -> TFun(retT, args, isVarargs, attrs @ [Attr("gnu_inline", []); Attr("always_inline", [])])
   | _ -> proto
   in
   let arglist = List.map (fun (ident, typ, attrs) -> makeFormalVar ourFun ident typ) protoArgs in 
   let () = setFunctionType ourFun protoWithInlineAttrs in
   let nameFunc =  (fun n t -> makeTempVar ourFun ~name:n t) in
   let loc = {line = -1; file = "BLAH FIXME"; byte = 0; column = -1; endLine = -1; endByte = -1; endColumn = -1; synthetic = false } in
   let argPatternBindings = List.map (fun ((ident, typ, attrs), arg) -> (ident, Fv arg)) (List.combine protoArgs arglist) in 
   let extPatternBindings = (* List.map (fun (ident, v) -> (ident, Fv v)) *) referencedValues in
   let madeBody = mkBlock (Formatcil.cStmts body nameFunc loc (argPatternBindings @ extPatternBindings)) in
   ourFun.sbody <- madeBody;
   ourFun.svar.vinline <- true;
   ourFun.svar.vstorage <- Extern;
    (* Don't make it static -- inline is enough. Making it static
        generates lots of spurious warnings when used from a non-static 
        inline function. *)
    (* Actually, do make it static -- C99 inlines are weird and don't eliminate
       multiple definitions the way we'd like.*)
    (* inlineAssertFun.svar.vstorage <- Static; *)
    (* ACTUALLY actually, make it extern, which plus gnu_inline above, 
       should be enough to shut up the warnings and give us a link error if 
       any non-inlined calls creep through. *)
    ourFun
  end

let tsIsPointer testTs = match testTs with 
   TSPtr(_, _) -> true
 | _ -> false

let tsIsNonVoidPointer testTs = match testTs with 
   TSPtr(TSBase(TVoid(_)), _) -> false
 | TSPtr(_, _) -> true
 | _ -> false

let tsIsVoidPointer testTs = match testTs with 
   TSPtr(TSBase(TVoid(_)), _) -> true
 | _ -> false

let rec tIsPointer testT = match testT with 
   TPtr(_, _) -> true
 | TNamed(ti, _) -> tIsPointer ti.ttype
 | _ -> false
      
let tsIsFunction ts = 
    match ts with
        TSFun(_, _, _, _) -> true
      | _ -> false

let tsIsFunctionPointer ts = 
    match ts with
        TSPtr(nestedTs, _) when tsIsFunction nestedTs -> true
      | _ -> false

let rec tsMatchModuloSignedness ts1 ts2 =
    if ts1 = ts2 then true
    else 
    let makeUnsigned ik = match ik with
        IChar -> IUChar
      | ISChar -> IUChar
      | IInt -> IUInt
      | IShort -> IUShort
      | ILong -> IULong
      | ILongLong -> IULongLong
      | _ -> ik
    in
    match ts1, ts2 with
        (TSBase(TInt(tk1, _)), TSBase(TInt(tk2 , _)))
            when makeUnsigned tk1 = makeUnsigned tk2
            -> true
      | (TSPtr(ts1', _), TSPtr(ts2', _)) -> tsMatchModuloSignedness ts1' ts2'
      | (TSArray(ts1', bound1, _), TSArray(ts2', bound2, _))
            -> bound1 = bound2 && tsMatchModuloSignedness ts1' ts2'
        (* functions are a marginal case; omit for now *)
        (* comps are going too far *)
      | _ -> false
    

let rec ultimatePointeeT someT = match someT with
    TPtr(pt, _) when tIsPointer pt -> ultimatePointeeT pt
  | TNamed(ti, _) -> ultimatePointeeT ti.ttype
  | TPtr(pt, _) -> pt
  | _ -> raise Not_found

let instrLoc (maybeInst : Cil.instr option) =
   match maybeInst with 
   Some(i) -> Cil.get_instrLoc i
 | None -> locUnknown

let tsIsMultiplyIndirectedGenericPointer ts = 
    let upts = ultimatePointeeTs ts
    in (upts = Cil.typeSig(voidType) || upts = Cil.typeSig(charType))
         && (indirectionLevel ts) > 1

(* Do our own scan for AddrOf and StartOf. 
 * The CIL one is not trustworthy, because any array subexpression
 * has internally been tripped via a StartOf (perhaps now rewritten? FIXME)
 * meaning it contains false positives. *)
class addressTakenVisitor = fun (seenAddressTakenLocalNames : string list ref)
    -> object(self) 
    inherit nopCilVisitor
    method vexpr (e: exp) : exp visitAction = begin
        match e with
             AddrOf(Var(vi), _) when not vi.vglob ->
                seenAddressTakenLocalNames :=
                    if List.mem vi.vname !seenAddressTakenLocalNames
                    then !seenAddressTakenLocalNames
                    else vi.vname :: !seenAddressTakenLocalNames
                ; DoChildren
           | StartOf(Var(vi), _) when not vi.vglob -> 
                seenAddressTakenLocalNames :=
                    if List.mem vi.vname !seenAddressTakenLocalNames 
                    then !seenAddressTakenLocalNames
                    else vi.vname :: !seenAddressTakenLocalNames
                ; DoChildren
           | _ -> DoChildren
    end
end

(* A block is a sequence of statements.
 * A statement may be an Instrs, which is a sequence of Instrs.
 * Given a sequence of Instrs
 * and the stmt that contains it (an Instrs statement),
 * we create a new stmt
 * that is itself a Block,
 * containing many stmts,
 * each an element of  groupedInstrs.
 * NOTE that CIL represents Gotos by a statement ref,
 * so we MUST update-in-place rather than return a fresh stmt. *)
let restructureInstrsStatement
  (groupAndLabel : Cil.instr list -> (Cil.instr list * label option * attribute list) list)
  (stmt : Cil.stmt)
  : unit
= match stmt.skind with
   Instr(instrs) -> let groupedInstrs = groupAndLabel instrs in
   stmt.labels <- (match groupedInstrs with
        (* If we have only a single group and no attrs, we won't create a nested block,
         * so the labels go here if there are any to add *)
        [(theGroup, Some(newLabel), [])] ->
            newLabel :: stmt.labels
        (* ... otherwise we'll put it in the block *)
         | _ -> stmt.labels);
   stmt.skind <- (match groupedInstrs with
        [(theGroup, maybeLabel, [])] ->
            Instr(theGroup)
         | _ ->
            Block(
              let stmts = (List.map (fun (group, maybeLabel, attrs) ->
                  (* If attrs is nonempty, we can simply make an Instr stmt. *)
                  let stmtLabels = (match maybeLabel with Some(lbl) -> [lbl] | None -> []) in
                  let skind = if attrs = [] then Instr(group)
                    else Block ({ battrs = attrs;
                                  bstmts = [{ labels = [];
                                              skind = Instr(group);
                                              sid = 0;
                                              succs = [];
                                              preds = [];
                                              fallthrough = None
                                           }]
                                })
                  in
                  (* begin stmt *) {
                    labels = stmtLabels;
                    skind = skind;
                    sid = 0;
                    succs = [];
                    preds = [];
                    fallthrough = None
                  }
              ) groupedInstrs) in
              let b = mkBlock stmts in
              (* Cil.dumpBlock (new defaultCilPrinterClass) Pervasives.stderr 0 b; *)
              b
          ));
| _ -> failwith "not an Instrs statement"
