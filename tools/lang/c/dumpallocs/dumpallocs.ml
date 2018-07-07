(* Copyright (c) 2011--14,
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
open Pretty
open Cil
open Feature
open Cilallocs
module E = Errormsg
module H = Hashtbl

let rec sizeExprHasNoSizeof (e: exp) =
  match e with 
 | SizeOf(t) -> false
 | SizeOfE(ex) -> false
 | SizeOfStr(s) -> false
 | Lval((Mem(ex),o)) -> sizeExprHasNoSizeof ex
 | UnOp(u, e1, t) -> sizeExprHasNoSizeof e1
 | BinOp(b, e1, e2, t) -> (sizeExprHasNoSizeof e1) && (sizeExprHasNoSizeof e2)
 | CastE(t, ex) -> sizeExprHasNoSizeof ex
 | AddrOf((Var(v),o)) -> true
 | AddrOf((Mem(ex),o)) -> sizeExprHasNoSizeof ex
 | StartOf((Var(v),o)) -> true
 | StartOf((Mem(ex),o)) -> sizeExprHasNoSizeof ex
 | Const(c) -> true
 | Lval((Var(v),o)) -> true
 | AlignOf(t) -> true
 | AlignOfE(t) -> true
 | _ -> true

type sz = 
    Undet
  | Existing of typsig * bool (* complete? *)
  | Synthetic of typsig list

let dwarfIdlExprFromSynthetic tss ident : string = 
    (* we want to output a dwarfidl expression 
       which defines a new data type 
       comprising a sequence of members
       which are *packed*. The packed thing is the hardest but can be bodged for now. *)
    "structure_type " ^ ident ^ " { " ^ (List.fold_left ( fun s t -> s ^ "member : " ^ (dwarfidlFromSig t) ^ "; " ) "" tss) ^ "};"

let maybeDecayArrayTypesig maybeTs = match maybeTs with
    Existing(ts, isComplete) -> Existing(decayArrayInTypesig ts, isComplete)
  | _ -> Undet

let rec getSizeExpr (ex: exp) (env : (int * sz) list) (gs : Cil.global list) : sz = 
  debug_print 1 ("Hello from getSizeExpr(" ^ (Pretty.sprint 80 (Pretty.dprintf "%a" d_exp ex)) ^ ") ... ");  flush Pervasives.stderr; 
  let isTrailingField fi compinfo = 
    let reverseFields = rev compinfo.cfields
    in
    let head = hd reverseFields
    in
    fi == head
  in
  let arrayElementType ts = match ts with
        TSArray(t, _, _) -> t
      | _ -> failwith "impossible"
  in
  let pointerTargetType ts = match ts with 
        TSPtr(t, _) -> t
      | _ -> failwith "impossible"
  in
  (* does a given lvalue offset, applied to an lvalue host of a given type sig, 
   * yield a *trailing* field, and if so, what is the field's type sig?
   *
   * A trailing field is never an array member. E.g. 
   *      a.i[1] is not a trailing field even if i is a 2-element array.
   * BUT 
   *      &a.i[0]   a.k.a.  &a.i   a.k.a.    a.i
   * might be a trailing field, if i is the last field in the struct. *)
  let rec isTrailingFieldOffsetExpr ts off = 
    debug_print 1 ("Hello from isTrailingFieldOffsetExpr(" ^ (Pretty.sprint 80 (d_typsig () ts)) ^ (Pretty.sprint 80 (d_offset Pretty.nil () off)) ^ ") ");  flush Pervasives.stderr; 
    match off with
      NoOffset -> (debug_print 1 ("... no offset\n");  flush Pervasives.stderr; false)
    | Field(fi, NoOffset) when isTrailingField fi fi.fcomp 
        -> (debug_print 1 ("... trailing field + no offset\n");  flush Pervasives.stderr; true)
    | Field(fi, NoOffset)
        -> (debug_print 1 ("... non-trailing no-offset\n"); flush Pervasives.stderr; false)
    | Index(indexEx, maybeOffset)
        -> (debug_print 1 ("... index\n");  flush Pervasives.stderr; isTrailingFieldOffsetExpr (arrayElementType ts) maybeOffset)
    | Field(fi, someOffset)
        -> (debug_print 1 ("... residual field case\n");  flush Pervasives.stderr; isTrailingFieldOffsetExpr (typeSig fi.ftype) someOffset)

 (*   
    (getConcreteType (typeSig fi.ftype)) = (getConcreteType ts) -> 
        if isTrailingField fi fi.fcomp 
            then (debug_print 1 ("... type-matching trailing field + no offset\n");  flush Pervasives.stderr; Some(TSComp(fi.fcomp.cstruct, fi.fcomp.cname, [])))
            else (debug_print 1 ("... type-matching non-trailing field + no offset\n");  flush Pervasives.stderr; None)
    | Field(fi, Index(indexEx, NoOffset)) when (getConcreteType (typeSig fi.ftype)) = (getConcreteType ts) -> 
        if isTrailingField fi fi.fcomp 
            then (debug_print 1 ("... type-matching trailing indexed field + no offset\n");  flush Pervasives.stderr; Some(TSComp(fi.fcomp.cstruct, fi.fcomp.cname, [])))
            else (debug_print 1 ("... type-matching non-trailing indexed field + no offset\n");  flush Pervasives.stderr; None)
    | Field(fi, someOffset) -> (debug_print 1 ("... non-type-matching field\n");  flush Pervasives.stderr; containingTypeSigForTrailingFieldOffsetExpr (typeSig fi.ftype) someOffset)
    | Index(indexEx, maybeOffset) -> (debug_print 1 ("... index\n");  flush Pervasives.stderr; containingTypeSigForTrailingFieldOffsetExpr (arrayElementType ts) maybeOffset)
    *)
  in
  let containingTypeSigInTrailingFieldOffsetFromNullPtrExpr lv = begin
    debug_print 1 ("Hello from containingTypeSigInTrailingFieldOffsetFromNullPtrExpr(" ^ (Pretty.sprint 80 (Pretty.dprintf "%a" d_lval lv)) ^ ")\n");  flush Pervasives.stderr; 
    match lv with
      (* Does it make sense to have complex expressions when doing 
         an offsetof-based size calculation? e.g.
         
         &((T * )0)->a.b[x].c[y].d?
         
         potentially YES
         if we're padding in a non-toplevel part of the struct.
         The size type of such an expression is T.
         But we want to check that we're padding a tail element.
         
         What does the above expression look like?
         AddrOf(
             Mem( cast-of-nullptr, 
                Field(a-fieldinfo, 
                    Field(b-fieldinfo, 
                        Index(x-exp, 
                            Field(c-fieldinfo, 
                                Index(y-exp, 
                                    Field(d-fieldinfo, 
                                        NoOffset)))))))
       *) 
    (Mem(e), off) -> debug_print 1 ("Saw Mem case\n"); flush Pervasives.stderr; 
        if isStaticallyNullPtr e 
            then (
                debug_print 1 ("Saw statically-null case\n"); 
                flush Pervasives.stderr; 
                let targetTs = pointerTargetType (typeSig (typeOf e))
                in
                if isTrailingFieldOffsetExpr targetTs off 
                    then Some(targetTs)
                    else None
            )
            else (debug_print 1 ("Saw non-statically-null case\n"); flush Pervasives.stderr; None)
   | _ -> None
  end
  in
  let res = match ex with
   |  BinOp(Mult, e1, e2, t) -> begin
         let sz1 = getSizeExpr e1 env gs in
         let sz2 = getSizeExpr e2 env gs in
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
         let sz1 = getSizeExpr e1 env gs in
         let sz2 = getSizeExpr e2 env gs in
         match (sz1, sz2) with
             (Undet, Undet) -> Undet
           | (Undet, _) -> sz2 (* a bit weird, pre-padding but okay *) 
           | (_, Undet) -> sz1 (* character padding *)
           | (Existing(s1, isComplete1), Existing(s2, isComplete2)) ->
                 (* If we're adding Xs to Xs, OR array of Xs to some more sizeof X, the whole
                    expr has sizeofness X *)
                 let decayedS1 = decayArrayInTypesig s1 in 
                 let decayedS2 = decayArrayInTypesig s2 in 
                 if decayedS1 = decayedS2 then Existing(decayedS1, isComplete1)
                 else 
                    (* GAH. Arrays! we often do 
                           
                           sizeof S + n * sizeof T
                           
                       in which case our last element is a variable-length thing.
                     *)
                    Synthetic([s1; TSArray(s2, None, [])])
           | (Synthetic(l1), Existing(s2, _)) -> Synthetic(l1 @ [s2])
           | (Existing(s1, _), Synthetic(l2)) -> Synthetic(s1 :: l2)
            (* HACK: if we have a loop that keeps adding up a size
             * calculated by some complex expression, we want to make sure
             * we get a fixed point in the sizeofness. *)
           | (Synthetic(l1), Synthetic(l2)) when l1 = l2 -> Synthetic(l1)
           | (Synthetic(l1), Synthetic(l2)) -> Synthetic(l1 @ l2)
        end
   |  BinOp(Div, e1, e2, t) -> begin
         (* We can "divide away" sizeofness e.g. by dividing sizeof (array_of_X) / (sizeof (X)) *)
         let maybeDecayedS1 = (maybeDecayArrayTypesig (getSizeExpr e1 env gs))
         in 
         let maybeDecayedS2 = (maybeDecayArrayTypesig (getSizeExpr e2 env gs))
         in
         match (maybeDecayedS1, maybeDecayedS2) with 
             (Existing(decayed1, isc1), Existing(decayed2, isc2)) -> if decayed1 = decayed2 then Undet (* divided away *)
              else (* dimensionally incompatible division -- what to do? *) Existing(decayed1, isc1)
            | (Existing(s, isc1), Undet) -> Existing(s, isc1)
            | _ -> Undet (* this includes the Synthetic cases*)
         
      end
   |  BinOp(MinusA, e1, e2, t) -> begin
         (* Subtracting one sizeof from another is like doing offsetof,
          * IFF the sizeofness of the second expr matches a trailing field (singular, for now)
          * in e1. *)
         let sz1 = getSizeExpr e1 env gs in
         let sz2 = getSizeExpr e2 env gs in
         match sz1, sz2 with
                (Existing(ts1, true), Existing(ts2, true)) ->
                    (* Is t2 a suffix of t1? This means t1 must be structured,
                     * and the last field of t1 must "match" t2, where "match"
                     * is equality modulo equivocating on arrays-of-one.
                     * FIXME: we should also support "- 2 * sizeof (long)" for an array long[2],
                     * say, but that gets more complicated. Similarly we should support
                     * dropping the last field from substructs within a struct, but currently
                     * we don't. *)
                    (match ts1 with
                        TSComp(true, cname, attrs) ->
                            let ci = (match 
                                (try findStructTypeByName  gs cname with
                                    Not_found -> failwith "impossible: did not find typesig struct"
                                ) with
                                TComp(ci, attrs) -> ci
                              | _ -> failwith "impossible: struct type is not a struct"
                            )
                            in
                            if ci.cstruct && List.length ci.cfields > 0 then
                                let fi = List.nth ci.cfields (List.length ci.cfields - 1)
                                in
                                let _ = (debug_print 1 ("Hello from field-subtracting (s - f) case in getSizeExpr (s is " ^ (typsigToString ts1) ^ ", f is " ^ (typToString fi.ftype) ^ " )\n");  flush Pervasives.stderr) in
                                let subtractingLastField =
                                    if fi.fbitfield <> None then false
                                    else
                                    (let tsf = Cil.typeSig fi.ftype in
                                     tsMatchModuloSignedness tsf ts2 ||
                                     (match tsf with
                                        TSArray(tsa, Some(bound), _) when bound = Int64.one ->
                                                tsMatchModuloSignedness tsa ts2
                                      | ts -> false)
                                    )
                                in
                                if subtractingLastField then
                                    (* behave like offsetof -- this means we use t1
                                     * but say it's incomplete*)
                                    Existing(ts1, false)
                                else
                                    Undet
                            else Undet
                      | _ -> Undet
                      )
              | _ -> Undet
      end
   |  SizeOf(t) -> Existing(typeSig t, isCompleteType t (* should always be true *)) 
   |  SizeOfE(e) -> Existing(typeSig (typeOf e), isCompleteType (typeOf e) (* should always be true *))
   |  SizeOfStr(s) -> Existing(typeSig charType, true)
   |  Lval(lhost, offset) -> begin
        (* debug_print 1 ("Hello from Lval case in getSizeExpr\n");  flush Pervasives.stderr; *) 
        match lhost with 
           Var(v) -> begin
             if v.vglob then Undet else try 
               let found = assoc v.vid env in 
               (* debug_print 1 ("environment tells us that vid " ^ (string_of_int v.vid) ^ " has a sizeofness\n"); *)
               found 
             with Not_found -> Undet
           end
        |  Mem(_) -> Undet
      end
   | CastE(t, e) -> (getSizeExpr e env gs) (* i.e. recurse down e *)
   | AddrOf(lv) -> begin 
        debug_print 1 ("Hello from AddrOf case in getSizeExpr\n");  flush Pervasives.stderr;
        let ts = containingTypeSigInTrailingFieldOffsetFromNullPtrExpr lv 
        in match ts with
            None -> Undet
          | Some(someTs) ->
                (* If we're using offsetof not sizeof,
                 * it means that we're splicing in some extra stuff,
                 * so we can't be making an array of the whole type. So
                 * the effect is like an incomplete type. *)
                Existing(someTs, false)
      end
   | _ -> Undet
   in
   (debug_print 1 " yielded ";
   (match res with
       Existing(ts, isComplete) -> debug_print 1 (
            (if not isComplete then "incomplete " else "") ^ (typsigToString ts) ^ "\n")
         | Synthetic _ ->  debug_print 1 ("something synthetic\n")
         | Undet -> debug_print 1 "don't know\n"
   );
   flush Pervasives.stderr;
   res
   )

(* FIXME: split this into a "toplevel" that does the HasNoSizeof check,
   and a recursive part which recurses *without* recursively doing the
   HasNoSizeof check. *)
let getSizeExprElseDefault (e: exp) (env : (int * sz) list) (gs : Cil.global list) : sz = 
  (* debug_print 1 ("Hello from getSizeExprElseDefault\n");  flush Pervasives.stderr;  *)
  (* let explicitSizeExpr = getSizeExpr e env in
  match explicitSizeExpr with
    Undet -> Some(typeSig voidType)
  | Existing(t) -> Some(t)
  | Synthetic(ts) -> (* FIXME *) None *)
  getSizeExpr e env gs

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
             debug_print 1 ("call to function " ^ funName ^ " looks like an allocation, but does not match any in LIBALLOCS_{SUB,}ALLOC_FNS\n")
          else if try_match funName "realloc" && (length arglist) > 1
             then (* getSizeExpr (nth arglist 1) *)
             debug_print 1 ("call to function " ^ funName ^ " looks like an allocation, but does not match any in LIBALLOCS_{SUB,}ALLOC_FNS\n")
             else (* getSizeExpr (nth arglist 0) *)
                debug_print 1 ("call to function " ^ funName ^ " looks like an allocation, but does not match any in LIBALLOCS_{SUB,}ALLOC_FNS\n")
      else () 
    end else (* None *)
      (* (debug_print 1 ("call to function " ^ funName ^ " is not an allocation because of empty arglist\n"); (* None *) *) () (* ) *)
| None -> ()

let matchUserAllocArgs i arglist signature env maybeFunNameToPrint (calledFunctionType : Cil.typ) (gs : Cil.global list) : sz =
 let signatureArgSpec = try (
     let nskip = search_forward (regexp "(.*)") signature 0
     in
     let fragment = (* string_after *) (matched_string signature) (* nskip *)
     in 
     (debug_print 1 ("Info: signature " ^ signature ^ " did contain a function arg spec (" ^ fragment ^ " a.k.a. signature + "^ (string_of_int nskip) ^")\n"); flush Pervasives.stderr);
     fragment
 )
 with Not_found -> (
       (debug_print 1 ("Warning: signature " ^ signature ^ " did not contain an arg spec\n"); flush Pervasives.stderr); 
       ""
 )
 in let sizeArgPos = 
       if string_match (regexp "[^A-Z]*[A-Z]") signatureArgSpec 0 
       then Some((String.length (matched_string signatureArgSpec)) - 1 (* for the bracket*) - 1 (* because we want zero-based *))
       else (debug_print 1 ("Warning: signature " ^ signature ^ " did not contain a capitalized arg spec element\n"); flush Pervasives.stderr; None)
 in match sizeArgPos with
  Some(s) -> 
     if (length arglist) > s then 
       let szEx = 
          (debug_print 1 ("Looking at arg expression number " ^ (string_of_int s) ^ "\n"); flush Pervasives.stderr); 
          getSizeExpr (nth arglist s) env gs
       in 
       match szEx with
         Existing(szType, _) -> (debug_print 1 ("Inferred that we are allocating some number of " ^ (Pretty.sprint 80 (Pretty.dprintf  "\t%a\t" d_typsig szType)) ^ "\n"); flush Pervasives.stderr );
               szEx
       | Undet -> debug_print 1 ("Could not infer what we are allocating\n"); flush Pervasives.stderr; szEx
       | Synthetic(_) -> debug_print 1 ("We are allocating a composite: FIXME print this out\n"); flush Pervasives.stderr; szEx
     else (match maybeFunNameToPrint with 
         Some(fnname) -> 
               ((debug_print 1 ("Warning: signature " ^ signature 
               ^ " wrongly predicts allocation function " ^ fnname ^ " will have at least " 
               ^ (string_of_int s) ^ " arguments, where call site it has only " ^ (string_of_int (length arglist)) ^"\n"); 
               flush Pervasives.stderr); Undet)
       | None -> (debug_print 1 ("Warning: spec argument count (" ^ (string_of_int s) ^ ") does not match call-site argument count (" ^ (string_of_int (length arglist)) ^ ")")); Undet)
 | None -> 
      (* If we have no sizearg pos, use the return type of the function: 
         if it is a pointer to non-void, we assume the pointer target type is the allocated type. *)
      match (unrollType calledFunctionType) with
        TFun(returnT, paramTs, isVarArgs, attrs) -> begin
            match typeSig returnT with
            TSBase(TVoid(_)) -> Undet
         |  TSPtr(targetTs, _) -> Existing(targetTs, isCompleteType (
                 match unrollType returnT with
                    TPtr(targetT, _) -> targetT
                  | _ -> failwith "impossible pointer type"
                 )
             )
         |  _ -> Undet (* it returns something else *)
            
        end
      | _ -> raise (Failure "impossible function type")

let explodeString s = 
  let rec expl i l =
    if i < 0 then l else expl (i - 1) (s.[i] :: l) in
  expl (String.length s - 1) []

let parseSignature signature = 
    let matched = string_match (regexp "[^\\(]+") signature 0 
    in 
    let rawName = if matched then matched_string signature else ""
    in
    let friendlyName = if matched then Some(matched_string signature) else None
    in 
    (* skip the bracket if there was one *)
    let argCharsOffset = if matched then 1 + (String.length rawName) else 0
    in
    let argCharsMatched = string_match (regexp "[^\\)]+") signature argCharsOffset
    in
    let rawArgChars = if argCharsMatched then matched_string signature else ""
    in
    let friendlyArgChars = explodeString rawArgChars
    in (friendlyName, friendlyArgChars)
    
let functionNameMatchesSignature fname signature = 
    let (friendlyName, friendlyArgChars) = parseSignature signature
    in
    match friendlyName with 
      Some(s) -> 
        (debug_print 1 ("Info: signature " ^ signature ^ " did contain a function name: " ^ s ^ "\n"); 
        flush Pervasives.stderr; 
        fname = s )
    | None -> (debug_print 1 ("Warning: signature " ^ signature ^ " did not contain a function name\n"); 
        flush Pervasives.stderr; false )

let functionArgCountMatchesSignature arglist signature = 
    let (friendlyName, friendlyArgChars) = parseSignature signature
    in
    debug_print 1 ("Signature " ^ signature ^ " has argcount " ^ (string_of_int (List.length friendlyArgChars)) ^ "\n"); 
    (List.length arglist) = (List.length friendlyArgChars)

let rec extractUserAllocMatchingSignature i maybeFunName arglist signature env (calledFunctionType : Cil.typ) (gs : Cil.global list) : sz option = 
 (* destruct the signature string *)
 debug_print 1 ("Warning: matching against signature " ^ signature ^ " when argcount is " 
    ^ (string_of_int (List.length arglist)) ^ "\n"); 
 flush Pervasives.stderr;
 match maybeFunName with 
   Some(fname) 
    when functionNameMatchesSignature fname signature 
     && functionArgCountMatchesSignature arglist signature
    -> Some(matchUserAllocArgs i arglist signature env (Some(fname)) calledFunctionType gs)
 | Some(_) ->     (* (debug_print 1 ("Warning: extracted function name " ^ signatureFunction ^ " from signature\n"); *) 
                    None 
                  (* ) *)
 | None when functionArgCountMatchesSignature arglist signature -> Some(matchUserAllocArgs i arglist signature env None calledFunctionType gs)
 | None -> None
 (* ) *)

let userAllocFunctions () : string list = 
  let wrappers = try begin 
    (Str.split (regexp "[ \t]+") (Sys.getenv "LIBALLOCS_ALLOC_FNS"))
  end with Not_found -> []
  in
  let suballocs = try begin
    (Str.split (regexp "[ \t]+") (Sys.getenv "LIBALLOCS_SUBALLOC_FNS")) 
  end with Not_found -> []
  in
  let sizeOnlyAllocs = try begin
    (Str.split (regexp "[ \t]+") (Sys.getenv "LIBALLOCS_ALLOCSZ_FNS")) 
  end with Not_found -> []
  in
  wrappers @ suballocs @ sizeOnlyAllocs

(* Return 'None' if none of the candidate alloc fun signatures matches the instr, 
 * or Some(sz) if one did and seemed to be allocating sz (which might still be Undet). *)
let rec getUserAllocExpr (i: instr) (maybeFunName: string option) (arglist: exp list) env candidates (calledFunctionType : Cil.typ) (gs: Cil.global list) : sz option = 
  (* debug_print 1 "Looking for user alloc expr\n"; flush Pervasives.stderr; *)
  try begin
    (* match f.vname with each candidate *) 
    (* debug_print 1 ("Got " ^ (string_of_int (List.length candidates)) ^ "candidate signatures\n"); flush Pervasives.stderr;  *)
    let rec firstMatchingSignature cands = 
      let funNameString = match maybeFunName with Some(s) -> s | None -> "(indirect call)"
      in
      match cands with
        [] -> raise Not_found (* debug_print 1 ("Warning: exhausted candidate signatures in matching function "  ^ funNameString ^ "\n"); None *)
      | s::ss -> begin 
         let extracted = extractUserAllocMatchingSignature i maybeFunName arglist s env calledFunctionType gs
         in match extracted with
             (* None means it didn't match. 
                Some(_) might still be Some(Undet), meaning it matched but we couldn't 
                figure out anything from the size expression. 
                If that happens and it's a direct call, we can return right away.
                If it happens *and* it's an indirect call (i.e. we don't have a function name), 
                we have to try the next candidate, as if it didn't match. *)
         | Some(something) when something != Undet -> Some(something)
         | Some(Undet) when maybeFunName != None -> Some(Undet)
         | _ -> (debug_print 1 ("Warning: signature " ^ s ^ " did not match function " ^ funNameString ^ "; trying other candidates\n"); 
            firstMatchingSignature ss )
        end
    in 
    firstMatchingSignature candidates
  end with Not_found -> (match maybeFunName with 
     Some(funName) -> (warnIfLikelyAllocFn i maybeFunName arglist; None) 
   | None -> None)

let allAllocFunctions () : string list = 
    ["malloc(Z)p"; "calloc(zZ)p"; "realloc(pZ)p"; "posix_memalign(pzZ)p"; 
        "alloca(Z)p"; "__builtin_alloca(Z)p"] 
        @ (userAllocFunctions ())

(* Work out whether this call is an allocation call. If it is,
   return Some(sz)
   where sz is the data type we inferred was being allocated (might be Undet)
   else None. *)
let rec getAllocExpr (i: instr) (maybeFun: varinfo option) (arglist: exp list) env (calledFunctionType : Cil.typ) (gs : Cil.global list) : sz option = 
  let maybeFunName = match maybeFun with 
    Some(f) -> Some(f.vname)
  | None -> None
  in 
  getUserAllocExpr i maybeFunName arglist env (allAllocFunctions ()) calledFunctionType gs

(* I so do not understand Pretty.dprintf *)
let printAllocFn fileAndLine chan maybeFunvar allocType mightBeArrayOfThis = 
   (* debug_print 1 ("printing alloc for " ^ fileAndLine ^ ", funvar " ^ funvar.vname ^ "\n"); *)
   output_string chan fileAndLine;
   let targetFunc = match maybeFunvar with 
     Some(funvar) -> Pretty.sprint 80 
       (Pretty.dprintf  "\t%a\t"
            d_lval (Var(funvar), NoOffset)) 
   | None -> "\t(indirect)\t"
   in
   output_string chan (targetFunc ^ allocType ^ "\t" ^ (if mightBeArrayOfThis then "1" else "0") ^ "\n");
   flush chan

(* What we do is:
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
let sizeofnessToString sz = match sz with
    Existing(ts, isCompl) -> "existing " ^ (Pretty.sprint 80 (d_typsig () ts))
  | Synthetic(tss) -> "synthetic [" ^ (List.fold_left (fun acc -> fun ts -> acc ^ (if acc = "" then "" else "; ") ^ (Pretty.sprint 80 (d_typsig () ts))) "" tss) ^ "]"
  | _ -> "undet"

let rec untilFixedPoint f initialValue = begin
  let printEl (vnum, sz) = "(" ^ string_of_int (vnum) ^ ", " ^ (sizeofnessToString sz) ^ ") "
  in 
  let listAsString = "[" ^ (fold_left (^) "" (map printEl initialValue)) ^ "]"
  in
  debug_print 1 ("hello from untilFixedPoint with initialValue " ^ listAsString ^ "\n"); 
  let newValue = f initialValue in
  if newValue = initialValue then initialValue else untilFixedPoint f newValue
end

let rec accumulateOverStatements acc (stmts: Cil.stmt list) (gs : Cil.global list) =
(* Our input is an environment mapping local variables to sizeofness, 
   and a collection of statements. 
   We propagate sizeofness from predecessor statements to successor statements, 
   but how? 
   We could take a completely flow-insensitive approach 
   and simply ignore the pred/succ structure in stmts, 
   instead just considering each instruction across all stmts. 
   Let's try this. *)
   let rec accumulateOverOneInstr acc i = (* debug_print 1 "hello from accumulateOverOneInstr\n"; flush Pervasives.stderr; *)
       match i with
         Call(_, f, args, l) -> acc
       | Set((host, off), e, l) -> begin 
           match host with
            Var(v) -> if v.vglob then acc else begin
               let szness = getSizeExpr e acc gs in
               match szness with
                   Undet -> acc
                 | _ -> (
                 debug_print 1 ("found some sizeofness in assignment to: " ^ (Pretty.sprint 80 (Pretty.dprintf  "\t%a\t" d_lval (host, off))) ^ " (vid " ^ (string_of_int v.vid) ^ ", sizeofness " ^ (sizeofnessToString szness) ^  ")\n")
                 ; flush Pervasives.stderr; (v.vid, szness) :: (remove_assoc v.vid acc))
              |  _ -> acc
            end
          | Mem(e) -> acc
         end 
       | Asm(_, _, _, _, _, l) -> acc
   in
   let rec accumulateOverInstrs acc instrs = 
     (* debug_print 1 "hello from accumulateOverInstrs\n"; flush Pervasives.stderr; *)
     match instrs with 
            [] -> acc
    |  i :: is -> accumulateOverInstrs (accumulateOverOneInstr acc i) is
   in
   let rec accumulateOneStatement acc s = 
      (* debug_print 1 (Pretty.sprint 80 
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
   |    Block(b) -> (* recurse over the block's stmts *) accumulateOverStatements acc b.bstmts gs
   |    If (e, b1, b2, l) -> accumulateOverStatements (accumulateOverStatements acc b2.bstmts gs) b1.bstmts gs
   |    Switch (e, b, ss, l) -> accumulateOverStatements (accumulateOverStatements acc ss gs) b.bstmts gs
   |    Loop (b, l, continueLabel, breakLabel) -> accumulateOverStatements acc b.bstmts gs
   |    TryFinally (tryBlock, finallyBlock, l) -> accumulateOverStatements (accumulateOverStatements acc tryBlock.bstmts gs) finallyBlock.bstmts gs
   |    TryExcept (tryBlock, _, exceptBlock, l)
         -> accumulateOverStatements (accumulateOverStatements acc tryBlock.bstmts gs) exceptBlock.bstmts gs (* FIXME: instr list doesn't get handled*) 
   | _ -> acc
   in 
   match stmts with 
     [] -> acc
  |  s :: ss -> accumulateOverStatements (accumulateOneStatement acc s) ss gs


let rec propagateSizeEnv stmts (env : (int * sz) list) (gs : Cil.global list) = accumulateOverStatements env stmts gs

class dumpAllocsVisitor = fun (fl: Cil.file) -> object(self)
  inherit nopCilVisitor
  
  (* where we will write our alloc data *)
  val outChannel : out_channel option ref = ref None
  
  (* the mapping of local variables to their sizeofness *)
  val sizeEnv : (int * sz) list ref = ref []
  
  (* at construction time, open the output file *)
  initializer 
    let allocFileName = fl.fileName ^ ".allocs" in
    outChannel := try begin
         let chan = open_out allocFileName in
         (debug_print 1 ("run initializer, opened " ^ allocFileName ^ "\n");
         Some(chan))
      end 
      with _ ->
        raise (Arg.Bad ("Cannot open file " ^ allocFileName))
   

  method vfunc (f: fundec) : fundec visitAction = 
    Cil.prepareCFG(f);
    Cil.computeCFGInfo f false; 
    sizeEnv := untilFixedPoint (fun x -> propagateSizeEnv f.sallstmts x fl.globals) []; 
    (* if this is an allocation function, make it noinline -- this avoids 
     * the (rare) case where an allocation call is inlined. NOTE that -ffunction-sections
     * added by crunchcc is handling a different case, that of *out-of-line* call sites 
     * coming from  the same compilation unit not having a relocation record. *)
    let rec functionNameMatchesAnySignature fname ss =
        match ss with
            [] -> false
          | s :: more -> if functionNameMatchesSignature fname s then true 
                         else functionNameMatchesAnySignature fname more
    in
    (if functionNameMatchesAnySignature f.svar.vname (allAllocFunctions ())
        then (f.svar.vattr <- f.svar.vattr @ [Attr("noinline", [])]; ())
        else ()
    ); 
    (* now we know which locals are sizes, we can visit calls -- in vinstr *)
    DoChildren

  val instrsToLabel = ref []
  method vstmt (outerS: stmt) : stmt visitAction =
      (* We have to be careful. Statements can nest inside other statements,
       * *but* Instr statements cannot nest inside Instr statements.
       * So we use the completion of an Instr statement as a trigger to
       * rewrite the Instr using the labels collected.
       * The vinst needs to pull the current list out of the ref val. *)
      match outerS.skind with
          Instr(outerIs) -> (
              instrsToLabel := []; ChangeDoChildrenPost(outerS, fun s ->
                  match s.skind with Instr(_) ->
                    (* We collected some labels. We need to split the list
                     * into labelled, attribute'd groups. *)
                    instrsToLabel := [];
                    restructureInstrsStatement (fun is ->
                      let rec groupInstrs (revGroupsAcc : (instr list * label option * attribute list) list) 
                                          (curGroup : instr list * label option * attribute list)
                                          (instrs : instr list) =
                          match instrs with
                            (* Okay, no more instrs in this Instr, so return the finished groups *)
                            [] -> List.rev (curGroup :: revGroupsAcc)
                          | x :: more ->
                                (* does "x" need to be made the head of a new group? *)
                                let foundLabel = List.find_opt (fun (i, attrs) -> i == x) !instrsToLabel
                                in match foundLabel with
                                Some(_, attrs) ->
                                    (* okay, flush curGroup to the acc... *)
                                    (* then start a new singleton (bypass the group accumulator *)
                                    let newSingleton = ([x], None, attrs) in
                                    let newRevGroupsAcc = newSingleton :: curGroup :: revGroupsAcc in
                                    groupInstrs newRevGroupsAcc ([], None, []) more
                              | None ->
                                    let (curInstrs, curLabel, curAttrs) = curGroup in
                                    (* no new group needed *)
                                    let newCur = (curInstrs @ [x], curLabel, curAttrs) in
                                    groupInstrs revGroupsAcc newCur more
                      in
                      groupInstrs [] ([], None, []) is
                    ) s;
                    s
                  | _ -> failwith "Instr came back as non-Instr"
              )
         )
      | _ -> DoChildren

  method vinst (i: instr) : instr list visitAction = 
    ( debug_print 1 ("considering instruction " ^ (
       match i with 
          Call(_, _, _, l) -> "(call) at " ^ l.file ^ ", line: " ^ (string_of_int l.line)
        | Set(_, _, l) -> "(assignment) at " ^ l.file ^ ", line: " ^ (string_of_int l.line)
        | Asm(_, _, _, _, _, l) -> "(assembly) at " ^ l.file ^ ", line: " ^ (string_of_int l.line)
      ) ^ "\n"); flush Pervasives.stderr);
      match i with 
      Call(_, funExpr, args, l) -> begin
         let handleCall maybeFunvar (functionT : Cil.typ) = begin
          let functionTs = typeSig functionT in
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
            (* (debug_print 1 ("processing a function " ^ v.vname ^ "\n"); *)
            let chan = match !outChannel with
             | Some(s) -> s
             | None    -> Pervasives.stderr
            in
            let fileAndLine = l.file ^ "\t" ^ (string_of_int l.line) ^ "\t" ^ (string_of_int l.line)
            in
            begin
              (* Here we need to identify the size argument and
                 then do either some hacky pattern matching
                 or a recursive function on the expr structure:
                 Sizeof T lets us terminate
                 Sizeof V also lets us terminate
                 Mul where an arg is a Sizeof lets us terminate *)
              let res = getAllocExpr i maybeFunvar args !sizeEnv functionT fl.globals in
              if res = None then SkipChildren(* this means it's not an allocation function *)
              else let allocString, isComplete = match res with
                 Some(Existing(ts, isComplete)) when isSinglyIndirectGenericPointerTypesig ts -> 
                    ("__uniqtype____EXISTS1___PTR__1", true)
              |  Some(Existing(ts, isComplete)) -> 
                    ((symnameFromSig ts), isComplete)
              |  Some(Synthetic(tss)) ->
                    let idl = dwarfIdlExprFromSynthetic tss (identFromString ("dumpallocs_synthetic_" ^ (trim fileAndLine)))
                    in (idl, false)
              |  Some(Undet) -> (* it is an allocation function, but... *)
                    ("__uniqtype____uninterpreted_byte", true)
              in
              instrsToLabel := (i, [Attr("allocstmt", [AStr(allocString)])]) :: !instrsToLabel;
              printAllocFn fileAndLine chan maybeFunvar allocString isComplete;
              SkipChildren
            end (* ) *)
          end
        | _ -> raise(Failure "impossible function type")
        end
        in
        let getCalledFunctionOrFunctionPointerType fexp : Cil.typ * Cil.varinfo option = 
           match fexp with 
             Lval(Var(v), NoOffset) -> (v.vtype, Some(v))
         |   _ -> (typeOf fexp, None)
        in 
        let (functionT, maybeVarinfo) = getCalledFunctionOrFunctionPointerType funExpr
        in
        match unrollType functionT with
          TFun(returnT, paramTs, isVarArgs, attrs) -> handleCall maybeVarinfo functionT
        | TPtr(ft, ptrAttrs) -> handleCall (None) ft
        | _ -> raise (Failure("impossible called function type" ^ (Pretty.sprint 80 (d_type () functionT))))
        
        (* TSPtr(TSFun(returnTs, paramTss, isVarArgs, funAttrs), ptrAttrs) -> handleCall None returnTs paramTss isVarArgs funAttrs
               | _ (* match v.vtype *) -> (debug_print 1 ("skipping call to non-function var " ^ v.vname ^ "\n"); flush Pervasives.stderr; SkipChildren)
             end
        | _ (* match f *) -> (debug_print 1 ("skipping call to non-lvalue at " ^ l.file ^ ":" ^ (string_of_int l.line) ^ "\n"); flush Pervasives.stderr; SkipChildren)
        *)
      end 
    | Set(lv, e, l) -> (* (debug_print 1 ("skipping assignment at " ^ l.file ^ ":" ^ (string_of_int l.line) ^ "\n" ); flush Pervasives.stderr; *) SkipChildren (* ) *)
    | Asm(_, _, _, _, _, l) -> (* (debug_print 1 ("skipping assignment at " ^ l.file ^ ":" ^ (string_of_int l.line) ^ "\n" ); *) SkipChildren (* ) *)
   (* ) *)
end (* class dumpAllocsVisitor *)

let feature : Feature.t = 
  { fd_name = "dumpallocs";
    fd_enabled = false;
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

let () = Feature.register feature
