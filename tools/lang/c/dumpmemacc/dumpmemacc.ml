open Unix
open List
open Str
open Pretty
open Cil
open Feature
open Cilallocs

class dumpMemAccVisitor = fun (fl: Cil.file) -> object(self)
  inherit nopCilVisitor
  
  (* where we will write our output data *)
  val outChannel : out_channel option ref = ref None
  val currentLoc : location option ref = ref None
  
  method doReport (direction : string) (kind: string) (exprT : Cil.typ) (enclosingT : Cil.typ) : unit =
      let chan = match !outChannel with
          Some(c) -> c
        | None -> Out_channel.stderr
      in
      let loc = match !currentLoc with
          Some(l) -> l
        | None -> locUnknown
      in
      output_string chan (loc.file ^ "\t" ^
        (string_of_int loc.line) ^ "\t" ^
        (string_of_int loc.line) ^ "\t" ^
        direction ^ "\t" ^
        kind ^ "\t" ^
        (symnameFromSig (Cil.typeSig exprT)) ^ "\t" ^
        (symnameFromSig (Cil.typeSig enclosingT)) ^ "\n")
        
  method reportRead (lv : Cil.lval): unit =
      self#doReport
        "read"
        "real"
        (Cil.typeOf (Lval(lv)))
        (Cil.typeOf (let (lhost, loff) = lv in Lval(lhost, NoOffset)))
  
  method reportVirtualRead (e : Cil.exp) : unit =
      self#doReport
        "read"
        "virtual"
        (Cil.typeOf e)
        (Cil.typeOf e)

  method reportWrite (lv : lval) : unit =
      self#doReport
        "write"
        "real"
        (Cil.typeOf (Lval(lv)))
        (Cil.typeOf (let (lhost, loff) = lv in Lval(lhost, NoOffset)))
  
  method reportVirtualWrite (e : Cil.exp) : unit =
      self#doReport
        "write"
        "virtual"
        (Cil.typeOf e)
        (Cil.typeOf e)

  (* at construction time, open the output file *)
  initializer 
    let memAccFileName = fl.fileName ^ ".memacc" in
    outChannel := try begin
         let chan = open_out memAccFileName in
         (* output_string chan ("run initializer, opened " ^ memAccFileName); *)
         Some(chan)
      end 
      with _ ->
        raise (Arg.Bad ("Cannot open file " ^ memAccFileName))

  (* We want to output a file with one entry per read/write subexpression.
   * File should have
   * file name
   * begin line#/col#
   * end line#/col#
   * sense of access (read/write)
   * realness of access (definite load, definite store, "virtual" temporary/stack load or store)
   * type of access
   * biggest enclosing type visible in source (i.e. lvalue type with offset erased)
   * offset within that type (HMM -- actually we don't know this except in textual/symbolic form)
   * dump of expression
   *)

  method vexpr (outerE: exp) : exp visitAction = 
    (* use ChangeDoChildrenPost so that we visit subexpressions first *)
    ChangeDoChildrenPost(outerE, fun e -> 
        let castIsRepChanging t subE = (
            let castTo = t in
            let castFrom = Cil.typeOf subE in
            let castToTs = Cil.typeSig castTo in
            let castFromTs = Cil.typeSig castFrom in
            castToTs <>  castFromTs
               && (* not both pointers *) match (castToTs, castFromTs) with
                   (TSPtr(_, _), TSPtr(_, _)) -> false
                 | _ -> true
        )
        in
        match e with
    |   Const(_) -> self#reportVirtualRead e; (* no write *) e (* i.e., stored constants? computed big constants? *)
    |   Lval(lhost, loff) -> self#reportRead (lhost, loff); (* no write, or caught below *) e (* ... i.e. likely a read, er, unless target of a Set() or Call() which we catch later *)
    |   SizeOf(_) -> e (* no read, no write *)
    |   SizeOfE(_) -> e (* no read, no write *)
    |   SizeOfStr(_) -> e (* no read, no write *)
    |   AlignOf(_) -> e (* no read, no write *)
    |   AlignOfE(_) -> e (* no read, no write *)
    |   UnOp(op, subE, t) -> (* no read *) self#reportVirtualWrite e; e (* result may go in a temporary *)
    |   BinOp(op, subE1, subE2, t) ->  (* no read *) self#reportVirtualWrite e; e (* result may go in a temporary *)
    |   CastE(t, subE) -> 
            (* if a rep-changing cast, result may go in a temporary *)
            (* no read *) (if castIsRepChanging t subE then self#reportVirtualWrite e else ()); e (* result may go in a temporary *)
    |   AddrOf(_) -> e (* no read, no write *)
    |   StartOf(_) -> e (* no read, no write *)
    |   Question(subE1, subE2, subE3, t) -> self#reportVirtualRead e; e
    |   AddrOfLabel (_) -> e
    )

  method vinst (outerI: instr) : instr list visitAction = ChangeDoChildrenPost([outerI], fun is ->
      match is with 
      [Call(maybeOut, funExpr, args, l, _)] -> (
          currentLoc := Some(l);
          (match maybeOut with
              Some(lv) -> self#reportWrite lv
            | None -> ()
          );
          let _ = List.mapi (fun idx -> (fun subE -> (self#reportVirtualWrite subE))) args in ();
          is
      )
    | [Set(lv, e, l, _)] ->
          currentLoc := Some(l);
          self#reportVirtualWrite e;
          self#reportWrite lv;
          is
    | [Asm(_, _, _, _, _, l)] ->
          currentLoc := Some(l);
          (* FIXME: use extended ASM writes/clobber list here *)
          is
    | _ -> failwith "impossible: did not match single instruction" 
    )

end (* class dumpMemAccVisitor *)

let feature : Feature.t = 
  { fd_name = "dumpmemacc";
    fd_enabled = false;
    fd_description = "print information about memory read/write sites";
    fd_extraopt = [];
    fd_doit = 
    (function (f: file) -> 
      let dmVisitor = new dumpMemAccVisitor f in
      (* Cfg.computeFileCFG f;
      computeAEs f; *)
      visitCilFileSameGlobals (dmVisitor :> cilVisitor) f);
    fd_post_check = true;
  } 

let () = Feature.register feature
