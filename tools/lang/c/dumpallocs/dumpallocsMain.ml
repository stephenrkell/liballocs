(* Heavily pilfered from Cil's main.ml *)

open List
open Str
open Pretty
open Cil
open Feature
open Dumpallocs
module E = Errormsg
module H = Hashtbl

(* We can also run as a standalone program *)
(* PROBLEM with this right now is that CIL needs preprocessed source, 
   and real code will have hacks and need particular preprocessor flags,
   which can only be source from a configured source tree
   (OR, erm, possibly debugging info, but we need source anyway....)
   So we don't use this for now. *)
type outfile = 
    { fname: string;
      fchan: out_channel } 
let failed = ref false 
let outChannel : outfile option ref = ref None
let mergedChannel : outfile option ref = ref None
let cleanup () = 
  if !E.verboseFlag || !Cilutil.printStats then
    Stats.print stderr "Timings:\n";
  if !E.logChannel != stderr then 
    close_out (! E.logChannel);  
  (match ! outChannel with Some c -> close_out c.fchan | _ -> ())

let parseOneFile (fname: string) : Cil.file =
  let cil = Frontc.parse fname () in
  cil

let rec processOneFile (cil: Cil.file) =
  begin

    if !Cilutil.doCheck then begin
      ignore (E.log "First CIL check\n");
      if not (Check.checkFile [] cil) && !Cilutil.strictChecking then begin
        E.bug ("CIL's internal data structures are inconsistent "
               ^^"(see the warnings above).  This may be a bug "
               ^^"in CIL.\n")
      end
    end;
    (match !outChannel with
      None -> ()
    | Some c -> Stats.time "printCIL" 
        (Cil.dumpFile (!Cil.printerForMaincil) c.fchan c.fname) cil);

    if !E.hadErrors then
      E.s (E.error "Error while processing file; see above for details.");

  end
let fileNames : string list ref = ref []
let recordFile fname = 
  fileNames := fname :: (!fileNames) 
let options : (string * Arg.spec * string) list =
  let is_default = function
      true -> " (default)"
    | false -> "" in
  [
    (* General Options *)
    "", Arg.Unit (fun () -> ()), " \n\t\tGeneral Options\n";

    "--version",
    Arg.Unit (fun _ ->
                print_endline ("CIL version " ^ Cil.cilVersion ^
                                 "\nMore information at http://cil.sourceforge.net/\n");
                exit 0),
    " Output version information and exit";

    "--verbose",
    Arg.Set E.verboseFlag,
    (" Print lots of random stuff; this is passed on from cilly" ^
       is_default !E.verboseFlag);

    "--noverbose",
    Arg.Clear E.verboseFlag,
    (" Undo effect of verbose flag" ^ is_default (not !E.verboseFlag));
]
  
let theMain () =
  let usageMsg = "Usage: dumpallocs [options] source-file" in
  (* Processign of output file arguments *)
  let openFile (what: string) (takeit: outfile -> unit) (fl: string) = 
    try takeit { fname = fl;
                 fchan = open_out fl }
    with _ ->
      raise (Arg.Bad ("Cannot open " ^ what ^ " file " ^ fl))
  in
  let outName = ref "" in
  (* sm: enabling this by default, since I think usually we
   * want 'cilly' transformations to preserve annotations; I
   * can easily add a command-line flag if someone sometimes
   * wants these suppressed *)
  Cil.print_CIL_Input := true;

  (*********** COMMAND LINE ARGUMENTS *****************)
  (* Construct the arguments for the features configured from the Makefile *)
  let argDescr = options @ 
        [ 
          "--out", Arg.String (openFile "output" 
                                 (fun oc -> outChannel := Some oc)),
              " the name of the output CIL file";
          "--mergedout", Arg.String (openFile "merged output"
                                       (fun oc -> mergedChannel := Some oc)),
              " specify the name of the merged file";
        ]
        @ Frontc.args in
  begin
    (* this point in the code is the program entry point *)

    (* Stats.reset Stats.HardwareIfAvail; *)

    (* parse the command-line arguments *)
    Arg.parse (Arg.align argDescr) recordFile usageMsg;
    Cil.initCIL ();

    fileNames := List.rev !fileNames;

    let files = List.map parseOneFile !fileNames in

    (* if there's more than one source file, merge them together; *)
    (* now we have just one CIL "file" to deal with *)
    let one =
      match files with
        [one] -> one
      | [] -> E.s (E.error "No arguments for CIL")
      | _ ->
          let merged =
            Stats.time "merge" (Mergecil.merge files)
              (if !outName = "" then "stdout" else !outName) in
          if !E.hadErrors then
            E.s (E.error "There were errors during merging");
          (* See if we must save the merged file *)
          (match !mergedChannel with
            None -> ()
          | Some mc -> begin
              let oldpci = !Cil.print_CIL_Input in
              Cil.print_CIL_Input := true;
              Stats.time "printMerged"
                (Cil.dumpFile !Cil.printerForMaincil mc.fchan mc.fname) merged;
              Cil.print_CIL_Input := oldpci
          end);
          merged
    in
    if !E.hadErrors then
      E.s (E.error "Cabs2cil had some errors");
      (* process the CIL file (merged if necessary) *)
      processOneFile one
  end
;;

begin 
  try 
    theMain (); 
  with Frontc.CabsOnly -> (* this is OK *) ()
end;
cleanup ();
exit (if !failed then 1 else 0)

