# Compiler wrapper base class.
# Understands argstrings of cc/gcc/...-like compilers.
# Always compiles via .o, even if the user is asking to link as well.
# Also supports fixing up output .o files e.g. to support symbol interposition.

import os, sys, re, subprocess, tempfile, abc, copy

def generatePhases(**ps):
    return type('Phase', (), ps)

Phase = generatePhases(DRIVER=0, PREPROCESS=1, COMPILE=2, ASSEMBLE=3, LINK=4)

# input files (i.e. filenames) are just strings that we also hang other properties off
class InputFile(str):
    lang = None
    def __new__(cls, fname):
        return super(InputFile, cls).__new__(cls, fname)
    def __init__(self, fname):
        str.__init__(fname)
class SourceFile(InputFile):
    lang = None
    def __new__(cls, fname, lang=None):
        return super(SourceFile, cls).__new__(cls, fname)
    def __init__(self, fname, lang=None):
        InputFile.__init__(self, fname)
        self.lang = lang
    # Here we encode the rules such as how ".c" becomes ".o" for the link phase.
    def langAfterPhase(self, phase):
        if phase == Phase.PREPROCESS:
            if lang in {"c", "c-header"}:
                return "cpp-output"
            if lang in {"c++", "c++-header"}:
                return "c++-cpp-output"
            if lang in {"objective-c", "objective-c-header"}:
                return "objective-c-cpp-output"
            if lang in {"objective-c++", "objective-c++-header"}:
                return "objective-c++-cpp-output"
            if lang in {"assembler-with-cpp"}:
                return "assembler"
        elif phase == Phase.COMPILE:
            return "assembler"
        return None
    def nameAfterPhase(self, phase):
        stem, ext = os.path.splitext(self)
        stemDirname, stemBasename = (os.path.dirname(stem), os.path.basename(stem))
        if phase == Phase.DRIVER:
            return self
        if phase == Phase.COMPILE:
            return stemBasename + ".s"
        if phase == Phase.ASSEMBLE:
            return stemBasename + ".o"
        if phase == Phase.PREPROCESS:
            langToUse = lang if lang != None else guessInputLanguageFromFilename(self)
            if langToUse == "c":
                return stemBasename + ".i"
            elif langToUse == "c++":
                return stemBasename + ".ii"
        # if we got here, then, hmm, we're not sure
        return None
        
def guessInputLanguageFromFilename(inputFilename):
    # Note that gcc's "-x" option recognises the following "languages"
    # where "phase differences" occur along the horizontal direction.
    # 
    # c  c-header  cpp-output
    # c++  c++-header  c++-cpp-output
    # objective-c  objective-c-header  objective-c-cpp-output
    # objective-c++ objective-c++-header objective-c++-cpp-output
    # assembler  assembler-with-cpp
    # ada
    # f77  f77-cpp-input f95  f95-cpp-input
    # go
    # java
    #
    # ... and "none" to mean "use filename suffix".
    filename, fileExtension = os.path.splitext(inputFilename)
    if fileExtension in {".c"}:
        return "c"
    if fileExtension in {".h"}:
        return "c-header"
    if fileExtension in {".i"}:
        return "cpp-output"
    if fileExtension in {".C", ".cc", ".cpp", ".cxx", "CPP", "c++", ".cp"}:
        return "c++"
    if fileExtension in {".H", ".hh", ".hpp", ".hxx", "HPP", "h++", ".hp", ".tc"}:
        return "c++-header"
    if fileExtension in {".ii"}:
        return "c++-cpp-output"
    if fileExtension in {".s"}:
        return "assembler"
    if fileExtension in {".S"}:
        return "assembler-with-cpp"
    if fileExtension in {".o", ".os", ".a", ".so"}:
        return None # no source language -- goes straight to linker
    sys.stderr.write("Could not identify source language for input filename %s\n" % inputFilename)
    return None
    
def phasesForInputLanguage(inputLanguage):
    laterPhases = {Phase.ASSEMBLE, Phase.LINK}
    if inputLanguage == "c" or inputLanguage == "c-header":
        return set.union({Phase.PREPROCESS, Phase.COMPILE}, laterPhases)
    if inputLanguage == "c++" or inputLanguage == "c++-header":
        return set.union({Phase.PREPROCESS, Phase.COMPILE}, laterPhases)
    if inputLanguage == "cpp-output" or inputLanguage == "c++-cpp-output":
        return set.union({Phase.COMPILE}, laterPhases)
    if inputLanguage == "assembler":
        return laterPhases
    if inputLanguage == "assembler-with-cpp":
        return set.union({Phase.PREPROCESS}, laterPhases)
    if inputLanguage == None:
        return set({Phase.LINK})
    sys.stderr.write("Could not enumerate phases for input filename %s\n" % inputFilename)
    return {}

class CompilerWrapper:
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def getCompilerCommand(self, itemsAndOptions, phases):
        """return a list of strings that is the command (including arguments) to invoke
           the underlying compiler"""
        return

    def debugMsg(self, msg):
        if "DEBUG_CC" in os.environ:
            sys.stderr.write(msg)
            sys.stderr.flush()
    
    def makeErrFile(self, name, mode):
        # we get an exception in the case where the dir already exists
        # AND in the case where it can't be created, so...
        try:
            os.makedirs(os.path.dirname(name))
        except os.error:
            pass
        # ... we let it pass, because "can't be created" => the open will fail
        return open(name, mode)
    
    def printErrors(self, errfile):
        # if the errfile is not stderr, cat the errfile to stderr
        if errfile.fileno() != sys.stderr.fileno():
            errfile.seek(0)
            for line in errfile:
                sys.stderr.write(line)
    
    # Our basic model is a bunch of "phases", each of which can have 
    # arguments that are either "items" (ordered) or "options" (unordered).
    # But NOTE that "items" needn't be filenames -- ordered options like "-lxxx" or "-x lang"
    # are included.
    # This naturally splits things into
    #    "preprocessor directives and related position-dependent args (such as -include xxx)",
    #    "input files and related position-dependent args (such as -x <lang>)",
    #    "output file name (optional, and maybe absent e.g. *.c -> *.o)",
    #    "linker directives" (-Wl,<anything>, -shared, -L<anything>, -l<anything>,  ...)
    # There is a "top-level" DRIVER phase for options that don't apply to particular phases.
    # NOTE that this model all comes directly from the gcc manual page: 
    # "Compilation can involve up to four stages...".
    
    # which phases are to happen? by default, we try to do everything
    enabledPhases = set({Phase.PREPROCESS, Phase.COMPILE, Phase.ASSEMBLE, Phase.LINK})
    
    # all args, keyed by index -- but making SourceFiles where necessary
    allArgs = dict({})
    
    # a list of sets of phase numbers, one per argument
    argPhases = [set({}) for n in range(0, len(sys.argv))]
    
    # for each phase, a list of argument indices for the phase's items
    phaseItemIndices = [[] for n in range(Phase.DRIVER, 1+Phase.LINK)]
    
    # also the items themselves -- could be strings or SourceFiles
    phaseItems = [[] for n in range(Phase.DRIVER, 1+Phase.LINK)]
    
    # keep a map of all source files (not items; excluding linker inputs), indexed by position
    allSourceFiles = dict({})

    # keep a map of all items, indexed by position
    allItems = dict({})
    
    # for each phase, a k/v mapping from option signifier (e.g. "-o") to value (e.g. output filename) or None
    # ... actually a pair, whose second element is the arglist indices of the options
    phaseOptionIndices = [dict({}) for n in range(Phase.DRIVER, 1+Phase.LINK)]

    # the phase options themselves
    phaseOptions = [dict({}) for n in range(Phase.DRIVER, 1+Phase.LINK)]

    # Report whether we're doing anything other than preprocessing
    def onlyPreprocessing(self):
        return self.enabledPhases == {Phase.PREPROCESS}
    
    # What do we do with '--' or equivalents?
    # It *is* still necessary, and part of "items", because some "options" are actually "options"
    # in command-line-speak, i.e. their order matters, like -l or -x.
    # It is never included in "options".
    def argItem(self, phases, num, lang=None):
        item = SourceFile(sys.argv[num], lang) if lang != None else sys.argv[num]
        self.debugMsg("Argument at position %d is `%s', classified as an item (language: %s) for phases %s\n" \
             % (num, sys.argv[num], str(lang), str(phases)))
        for phase in phases:
            self.argPhases[num] =  self.argPhases[num].union({phase})
            self.phaseItemIndices[phase] += [num]
            self.phaseItems[phase] += [item]
        if isinstance(item, SourceFile):
            self.allSourceFiles[num] = item
        self.allItems[num] = item
        self.allArgs[num] = item
    
    def argOption(self, phases, num, k, v):
        self.debugMsg("Argument at position %d is `%s', classified as an option (argument: %s) for phases %s\n" \
             % (num, k, str(v), str(phases)))
        self.argPhases[num] = self.argPhases[num].union(phases)
        for phase in phases:
            self.phaseOptionIndices[phase][k] = num
            self.phaseOptions[phase][k] = v
        self.allArgs[num] = k
        if v:
            self.allArgs[num+1] = v
    
    def optionsForPhases(self, phases):
        return dict([(k, v) for phase in phases for (k,v) in self.phaseOptions[phase].items()])
    
    def specialOptionsForPhases(self, phases, deletions, additions=dict({})):
        opts = self.optionsForPhases(phases)
        for d in deletions:
            if d in opts:
                del opts[d]
        for (k, v) in additions:
            opts[k] = v
        return opts
    
    def flatOptions(self, options):
        # get a flat list of options pertaining to the phases given
        return sum([[optPart, argPart] for (optPart, argPart) in options.items() if argPart != None], []) \
           + sum([[optPart] for (optPart, argPart) in options.items() if argPart == None], [])
    
    def itemsForPhases(self, phases):
        # Avoid duplication here by iterating over allArgs.
        # Also, substitute the name appropriate for the *earliest* phase
        # we're doing.
        prevPhase = min(phases) - 1
        return [s if not isinstance(s, SourceFile) else s.nameAfterPhase(prevPhase) \
            for (idx, s) in self.allArgs.items() \
            if idx in self.allItems and self.argPhases[idx].intersection(phases)]
    
    def flatItems(self, items):
        # our main job is to reinstate "-x" where it is necessary,
        # i.e. where a SourceFile has a lang that doesn't match its name.
        # Intermediate files will always have non-confusing names, so
        # we don't have to worry about those -- rather, we assume that
        # a SourceFile has been translated to a string, if necessary,
        # for a phase-appropriate
        return sum([[x] if not isinstance(x, SourceFile) or x.lang == guessInputLanguageFromFilename(x) \
            else ["-x", guessInputLanguageFromFilename(x), x, "-x", "none"] \
            for x in items], [])
    
    # The options that we desperately have to understand are those that consist of two (or more)
    # words. That's so that we can avoid breaking them up. For example, if we didn't know that
    # "-T <script>" was a linker option taking a linker script argument, we would classify "-T"
    # as an option and "<script>" as an input file for an unknown phase.
    def classifyArguments(self, args):
        skipNext = False
        seenNoMoreOptionsMarker = False
        currentLanguage = None
        seenSomeInput = True
        outputFile = None
        outputFileNum = None
        for num in range(0,len(args)):
            if num == 0: # "allocscc" or whatever
                self.argItem({Phase.DRIVER}, num)
            elif skipNext: 
                skipNext = False
                continue
            #if args[num] == "-V":
            #    args[num] = "-0"
            elif not seenNoMoreOptionsMarker and args[num] == '--':
                seenNoMoreOptionsMarker = True
                # add to all phases
                self.argItem(self.phases, num)
            elif seenNoMoreOptionsMarker or args[num] == '-' or not args[num].startswith('-'):
                # it's a filename
                inputLanguage = guessInputLanguageFromFilename(args[num]) if currentLanguage == None else currentLanguage
                self.argItem(phasesForInputLanguage(inputLanguage), num, lang=inputLanguage)
                seenSomeInput = True
            elif args[num] == "-o":
                # "-o" goes on the driver, initially; we add it to the last phase, later
                # don't test and len(args) >= num + 2:  -- just let it fail
                self.argOption({Phase.DRIVER}, num, "-o", args[num + 1])
                outputFile = args[num + 1]
                outputFileNum = num
                skipNext = True
            elif args[num].startswith('-l'):
                self.argItem({Phase.LINK}, num)
            elif args[num] == '-I':
                self.argOption({Phase.PREPROCESS}, num, "-I%s" % args[num+1], None)
                skipNext = True
            elif args[num].startswith('-I'):
                self.argOption({Phase.PREPROCESS}, num, args[num], None)
            elif args[num] == '-L':
                self.argItem({Phase.LINK}, num)
                self.argItem({Phase.LINK}, num+1)
                skipNext = True
            elif args[num].startswith('-L'):
                self.argItem({Phase.LINK}, num)
            elif args[num] in {'-flto', "-fno-lto"}:
                self.argOption({Phase.COMPILE, Phase.LINK}, num, args[num], None)
            elif args[num].startswith('-f'):
                self.argOption({Phase.COMPILE}, num, args[num], None)
            elif args[num].startswith('-O'):
                self.argOption({Phase.COMPILE}, num, args[num], None)
            elif args[num].startswith('-std'):
                self.argOption({Phase.PREPROCESS, Phase.COMPILE}, num, args[num], None)
            elif args[num].startswith('-g'):
                self.argOption({Phase.COMPILE, Phase.ASSEMBLE, Phase.LINK}, num, args[num], None)
            elif args[num] == '-shared' or args[num] == '-G':
                self.argOption({Phase.LINK}, num, "-shared", None)
            elif args[num] == '-c':
                self.argItem({Phase.DRIVER}, num)
                self.enabledPhases = {Phase.PREPROCESS, Phase.COMPILE, Phase.ASSEMBLE}
            elif args[num] == '-h' or args[num].startswith("--help") or args[num].startswith("--target-help"):
                self.argItem({Phase.DRIVER}, num)
            elif args[num] == '-E':
                self.argItem({Phase.DRIVER}, num)
                self.enabledPhases = {Phase.PREPROCESS}
            elif args[num] == '-S':
                self.argItem({Phase.DRIVER}, num)
                self.enabledPhases = {Phase.PREPROCESS, Phase.COMPILE}
            elif args[num] == "-x":
                if args[num + 1] == "none":
                    currentLanguage = None
                else:
                    # record that we're setting the current language here
                    currentLanguage = args[num + 1]
                skipNext = True
            elif (args[num] == "-include" or args[num] == "-isystem" \
                  or args[num] == "-include" or args[num] == "-idirafter" \
                  or args[num] == "-imacros" or args[num] == "-iprefix" \
                  or args[num] == "-iquote" or args[num] == "-iwithprefix" \
                  or args[num] == "-iwithprefixbefore"):
                self.argItem({Phase.PREPROCESS}, num)
                self.argItem({Phase.PREPROCESS}, num+1)
                skipNext = True
            elif args[num] == '-param' or args[num] == '--param':
                self.argItem({Phase.COMPILE}, num)
                self.argItem({Phase.COMPILE}, num+1)
                skipNext = True
            elif args[num] in {'-M', '-MM', '-MG', '-MP', '-MD', '-MMD'}:
                self.argItem({Phase.PREPROCESS}, num)
                skipNext = True
            elif args[num] in {'-MT', '-MQ', '-MF'}:
                self.argOption({Phase.PREPROCESS}, num, args[num], args[num + 1])
                skipNext = True
            elif args[num] == "-T":
                self.argOption({Phase.LINK}, num, args[num], args[num+1])
                skipNext = True
            elif args[num] == "-u":
                self.argItem({Phase.LINK}, num)
                self.argItem({Phase.LINK}, num+1)
                skipNext = True
            elif args[num].startswith("-Wl"):
                self.argOption({Phase.LINK}, num, args[num], None)
            elif args[num].startswith("-Xlinker"):
                self.argOption({Phase.LINK}, num, "-Wl," + args[num+1], None)
                skipNext = True
            elif args[num].startswith("-Wp"):
                self.argOption({Phase.PREPROCESS}, num, args[num], None)
            elif args[num].startswith("-Xpreprocessor"):
                self.argOption({Phase.PREPROCESS}, num, "-Wp," + args[num+1], None)
                skipNext = True
            elif args[num].startswith("-Wa"):
                self.argOption({Phase.ASSEMBLE}, num, args[num], None)
            elif args[num].startswith("-Xassembler"):
                self.argOption({Phase.ASSEMBLE}, num, "-Wa," + args[num+1], None)
                skipNext = True
            elif args[num].startswith("-mllvm"):
                if "=" not in args[num]:  # Val can be separated by either a space or '='.
                    skipNext = True
                self.argOption({Phase.LINK, Phase.PREPROCESS, Phase.COMPILE, Phase.ASSEMBLE}, num, args[num], None if "=" in args[num] else args[num+1])
            elif args[num].startswith('-'):
                # looks like an option; pass it to all phases
                self.debugMsg("Default treatment for options %s\n" % args[num])
                self.argOption(range(Phase.DRIVER, 1+Phase.LINK), num, args[num], None)
            else:
                assert false
        # now we've seen all the options, we can tell which one the "-o" applies to (if we saw it)
        if outputFile:
            self.argOption({max(self.enabledPhases)}, outputFileNum, "-o", outputFile)
        # if we have no input items, not much we can do
        if len(self.itemsForPhases({Phase.PREPROCESS, Phase.COMPILE, Phase.ASSEMBLE, Phase.LINK})) == 0:
            self.enabledPhases = {Phase.DRIVER}
        self.debugMsg("enabledPhases: %s\n" % str(self.enabledPhases))
        self.debugMsg("allArgs: %s\n" % str(self.allArgs))
        self.debugMsg("argPhases: %s\n" % str(self.argPhases))
        self.debugMsg("phaseItemIndices: %s\n" % str(self.phaseItemIndices))
        self.debugMsg("phaseItems: %s\n" % str(self.phaseItems))
        self.debugMsg("allSourceFiles: %s\n" % str(self.allSourceFiles))
        self.debugMsg("phaseOptionIndices: %s\n" % str(self.phaseOptionIndices))
        self.debugMsg("phaseOptions: %s\n" % str(self.phaseOptions))
    
    def filenamesAndLanguagesFromInputItems(self, items):
        indexOfNoMoreOptionsMarker = None
        currentLanguage = "none"
        skipNext = False
        l = []
        for n in range(0, items):
            if skipNext:
                skipNext = False
                continue
            if items[n] == '--' and indexOfNoMoreOptionsMarker == None:
                indexOfNoMoreOptionsMarker = n
                continue
            if items[n] == '-x':
                currentLanguage = items[n+1]
                skipNext = True
                continue
            if (indexOfNoMoreOptionsMarker != None and n > indexOfNoMoreOptionsMarker) \
                or items[n] == '-' \
                or not items[n].startswith("-"):
                l += [(items[n], currentLanguage)]
        return l
    
    # FIXME: ideally get rid of these
    
    def getSourceInputFiles(self):
        return list(self.allSourceFiles.values())

    def getOutputFilename(self, phase=Phase.DRIVER):
        maybeGiven = self.phaseOptions[phase].get("-o")
        if maybeGiven == None:
            if self.doingFinalLink() \
                and not "-shared" in self.phaseOptions[Phase.LINK].keys() \
                and not "-Wl,-r" in self.phaseOptions[Phase.LINK].keys():
                return "a.out"
                # there are no defaults for shared lib outputs (or other linker outputs)
            elif not phase == Phase.LINK:
                # if we have a unique source input (FIXME: should be input to the last phase...)
                if len(self.getSourceInputFiles()) == 1:
                     return next(iter(self.getSourceInputFiles())).nameAfterPhase(phase)
        return maybeGiven
    
    def parseInputAndOutputFiles(self):
        args = sys.argv
        self.classifyArguments(args)
#        allSourceInputArgs = [args[n] for n in range(0,len(args)) if \
#            (Phase.PREPROCESS in argPhases[n] and n in phaseItemIndices[Phase.PREPROCESS]) or \
#            (Phase.COMPILE in argPhases[n] and n in phaseItemIndices[Phase.COMPILE]) or \
#            (Phase.ASSEMBLE in argPhases[n] and n in phaseItemIndices[Phase.ASSEMBLE])]
#        
#        sourceInputFilenamesAndLanguages = filenamesAndLanguagesFromInput)
    
    def __init__(self):
        self.parseInputAndOutputFiles()
    
    # HACK: regrettably, in at least one case we need to probe the compiler
    # for the options it supports. That's for -no-pie, because some GCCs
    # make position-independent executables by default. In allocscompilerwrapper.py
    # we want to make a relocatable version of the output, so we use "-r", but
    # this conflicts with the -pie that is implied on gcc 6+... so we need to add
    # -no-pie, but gcc 4.9 does not understand that.
    #
    # For probing the compiler, the heuristic we use is that if the compiler
    # doesn't support an option, passing just that option will cause it to 
    # echo the option back on stderr with some spacing/quoting stuff around it.
    def recognisesOption(self, opt):
        errOutput = subprocess.Popen(self.getCompilerCommand([], {}) + [opt], \
            stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[1].decode() 
        m = re.match(".*[^-a-z0-9]" + opt + "([^-a-z0-9].*|$)", errOutput) # FIXME: escaping
        if m:
            return False
        else:
            return True

    def doingFinalLink(self):
        return Phase.LINK in self.enabledPhases and \
            not "-r" in self.phaseOptions[Phase.LINK].keys() \
            and not "-Wl,-r" in self.phaseOptions[Phase.LINK].keys() \
            and not "-Wl,--relocatable" in self.phaseOptions[Phase.LINK].keys()

    def doingStaticLink(self):
        return Phase.LINK in self.enabledPhases and \
            ("-static" in self.phaseOptions[Phase.LINK].keys() \
            or "-Bstatic" in self.phaseOptions[Phase.LINK].keys())
    
    def linkingSharedObject(self):
        return Phase.LINK in self.enabledPhases and \
            ("-shared" in self.phaseOptions[Phase.LINK].keys() \
            or "-G" in self.phaseOptions[Phase.LINK].keys())
    
    def linkingExecutable(self):
        return Phase.LINK in self.enabledPhases and self.doingFinalLink() \
            and not self.linkingSharedObject()

    # We interfere with the usual compiler driver in one key way:
    # we permit interference before and after linking.
    # To be specific, we
    # - run any/all "before linking" phases, in one go;
    #   -- allow subclasses to interfere here
    # - run linking to a single relocatable output file (.o)
    #   -- allow subclasses to interfere here
    # - run final linking (if necessary) to intended output file class
    #   -- allow subclasses to interfere here

    # by default, fixup does nothing
    def fixupPostAssemblyDotO(self, filename, errfile):
        return 0
    def fixupPostLinkDotO(self, filename, errfile):
        return 0
    def fixupFinalBinary(self, filename, errfile):
        return 0
    
    # Instead of saying "run underlying compiler (sourceFiles, otherOptions)"
    # we use the power of our input options: source files are instances of
    # SourceFile so are easily distinguished
    def runCompiler(self, itemsAndOptions, phases):
        commandAndArgs = self.getCompilerCommand(itemsAndOptions, phases)
        #self.debugMsg("Environment is %s\n" % str(os.environ))
        self.debugMsg("Running compiler command: " + " ".join(commandAndArgs) + "\n")
        ret1 = subprocess.call(commandAndArgs)
        self.debugMsg("Exit status was %d\n" % ret1)
        return ret1

    def buildOneObjectFile(self, sourceFile, outputFilename, lang="c"):
        phases = {Phase.PREPROCESS, Phase.COMPILE, Phase.ASSEMBLE}
        options = specialOptionsForPhases(phases, ["-o"])
        options.pop("-o", None)
        # This means "preprocess-and-compile options and items [but not filenames]", 
        # IMPORTANT: "-I" is an item! so we're interested in more than just options
        args = self.flatOptions(options) + self.flatItems([x for x in itemsForPhases(phases) if not isinstance(x, SourceFile)])
        return self.runCompiler([sourceFile if isinstance(x, SourceFile) else SourceFile(x, lang)] \
         + args + ["-c", "-o", outputFilename], {Phase.PREPROCESS, Phase.COMPILE, Phase.ASSEMBLE})
    
    def optionToStopAfterPhase(self, phase):
        if phase == Phase.PREPROCESS:
            return "-E"
        if phase == Phase.COMPILE:
            return "-S"
        if phase == Phase.ASSEMBLE:
            return "-c"
        return None

    def runPhasesBeforeLink(self):
        sourceInputFiles = self.getSourceInputFiles()
        if len(self.itemsForPhases(self.enabledPhases)) == 0 and Phase.LINK not in self.enabledPhases:
            # just run the driver
            return self.runCompiler(self.itemsForPhases({Phase.DRIVER}) + \
                self.flatOptions(self.optionsForPhases({Phase.DRIVER})), \
                self.enabledPhases)
        if len(sourceInputFiles) == 0:
            return 0 # nothing to do here
        
        self.debugMsg("Making .o files from " + " ".join(sourceInputFiles) + "\n")
        # What we want to do is a lot like buildOneObjectFile, but we have to
        # - not do any phases that aren't enabled
        phases = self.enabledPhases.difference({Phase.DRIVER, Phase.LINK})
        self.debugMsg("Phases before link are: %s\n" % str(phases))
        # - heed the output filename: if the last enabled phase has a defined 
        #   output file, we pass it
        options = self.specialOptionsForPhases(phases, ["-o"])
        # the -o we want to give is that of the last of our pre-link phases
        if "-o" in self.optionsForPhases({max(phases)}):
            options["-o"] = self.optionsForPhases({max(phases)})["-o"]
        else:
            # this means our last phase doesn't specify an output file;
            # we let the preprocessor, compiler and/or assembler choose it for us
            pass
        # we remove this driver option, but other driver options *can* be present
        ret = self.runCompiler(self.flatOptions(options) + \
            self.flatItems(self.itemsForPhases(phases)) + \
            [self.optionToStopAfterPhase(max(phases))], \
            self.enabledPhases)
        if ret != 0 or not Phase.ASSEMBLE in self.enabledPhases:
            return ret
        # if we just assembled any objects, do the postprocessing
        for sourceFile in sourceInputFiles:
            outputFilename = sourceFile.nameAfterPhase(Phase.ASSEMBLE) \
               if len(sourceInputFiles) > 1 or not "-o" in self.optionsForPhases({Phase.ASSEMBLE}).keys() \
               else self.optionsForPhases({Phase.ASSEMBLE})["-o"]
            ret = self.fixupPostAssemblyDotO(outputFilename, None)
            if ret != 0:
                # we didn't succeed, so quit now
                return ret
        return 0
        #        if Phase.ASSEMBLE in self.enabledPhases:
        #            maybeUniqueOutputFile = phaseOptions[Phase.ASSEMBLE].get("-o")
        #            allObjs = [maybeUniqueOutputFile] if maybeUniqueOutputFile else \
        #                [x.nameAfterPhase(Phase.ASSEMBLE) for x in phaseItems[Phase.ASSEMBLE] \
        #                    if isinstance(x, SourceFile)]
        #            for obj in allObjs:
        #                # we have a single named output file
        #                ret2 = self.fixupPostAssemblyDotO(obj, None)
        #                if (ret2 != 0):
        #                    return ret2
        #            return 0
