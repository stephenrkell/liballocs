# Compiler wrapper base class.
# Understands argstrings of cc/gcc/...-like compilers.
# Always compiles via .o, even if the user is asking to link as well.
# Also supports fixing up output .o files e.g. to support symbol interposition.

import os, sys, re, subprocess, tempfile, abc
import abc
import copy

class SourceFile(str):
    lang = None

class CompilerWrapper:
    __metaclass__ = abc.ABCMeta

    class StrWithLang(str):
        lang = None
    
    @abc.abstractmethod
    def getUnderlyingCompilerCommand(self, sourceFiles):
        """return a list of strings that is the command (including arguments) to invoke
           the underlying compiler"""
        return
    
    @abc.abstractmethod
    def makeObjectFileName(self, sourceFileName):
        """return a sensible name for an object file given an input source file name"""
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
        except os.error, e:
            pass
        # ... we let it pass, because "can't be created" => the open will fail
        return open(name, mode)
    
    def print_errors(self, errfile):
        # if the errfile is not stderr, cat the errfile to stderr
        if errfile.fileno() != sys.stderr.fileno():
            errfile.seek(0)
            for line in errfile:
                sys.stderr.write(line)

    def getCustomCompileArgs(self, sourceInputFiles):
        return []
    
    def commandStopsBeforeObjectOutput(self):
        return "-E" in sys.argv or "-S" in sys.argv
   
    def allWrappedSymNames(self):
        return []
    
    def parseInputAndOutputFiles(self, args):
        skipNext = False
        outputFile = None
        currentLang = None
        sourceInputFiles = []
        objectInputFiles = []
        seenLib = False
        seenNonExecutableOutput = False
        seenSomeInput = False
        seenNoMoreOptionsMarker = False
        isDefinitelyLink = False
        isDefinitelyNotLink = False
        for num in range(0,len(args)):
            if num == 0:
                pass # "allocscc" or whatevre
            elif skipNext: 
                skipNext = False
                continue
            #if args[num] == "-V":
            #    args[num] = "-0"
            elif not seenNoMoreOptionsMarker and args[num] == "-o" and len(args) >= num + 2:
                outputFile = args[num + 1]
                outputFilename = os.path.basename(args[num + 1])
                skipNext = True
                # HACK: is this really necessary?
                if outputFilename.endswith(".o") or outputFilename.endswith(".i"):
                    seenNonExecutableOutput = True
            elif not seenNoMoreOptionsMarker and args[num].startswith('-l'):
                seenLib = True
            elif not seenNoMoreOptionsMarker and (args[num] == '-shared' or args[num] == '-G'):
                isDefinitelyLink = True
            elif not seenNoMoreOptionsMarker and args[num] == '-c':
                isDefinitelyNotLink = True
            elif not seenNoMoreOptionsMarker and (args[num] == '-E' or args[num] == '-S'):
                isDefinitelyNotLink = True
            elif not seenNoMoreOptionsMarker and args[num] == "-x":
                if args[num + 1] == "none":
                    currentLang = None
                else:
                    currentLang = args[num + 1]
                skipNext = True
            elif not seenNoMoreOptionsMarker and \
                  (args[num] == "-include" or args[num] == "-isystem" \
                  or args[num] == "-include" or args[num] == "-idirafter" \
                  or args[num] == "-imacros" or args[num] == "-iprefix" \
                  or args[num] == "-iquote" or args[num] == "-iwithprefix" \
                  or args[num] == "-iwithprefixbefore"):
                skipNext = True # HMM -- want to save this somehow?
            elif not seenNoMoreOptionsMarker and (args[num] == '-param' or args[num] == '--param'):
                skipNext = True
            elif args[num] == '-MT' or args[num] == "-MF":
                skipNext = True
            # -M options: if we use -MF or -MD or -MMD, we might actually be doing the compile. 
            elif not seenNoMoreOptionsMarker and (args[num] == '-M' or args[num] == '-MM') and not ("-MF" in args):
                isDefinitelyNotLink = True
            elif not seenNoMoreOptionsMarker and args[num] != "-" and args[num].startswith('-'):
                pass
            elif not seenNoMoreOptionsMarker and args[num] == '--':
                seenNoMoreOptionsMarker = True
            elif args[num] != '-' and args[num].startswith('-') and not seenNoMoreOptionsMarker:
                # looks like an option
                pass
            # glibc builds some files with ".os" extensions
            elif args[num].endswith('.o') or args[num].endswith('.os') or args[num].endswith('.a'):
                objectInputFiles += [args[num]]
                seenSomeInput = True
            elif args[num].endswith('.so'):
                # HMM: what does this mean exactly? it's like "-lBLAH" but giving an explicit path
                objectInputFiles += [args[num]]
            else:
                self.debugMsg("guessed that source file is " + args[num] + "\n")
                seenSomeInput = True
                sourceFileToAdd = SourceFile(args[num])
                if currentLang != None:
                    sourceFileToAdd.lang = currentLang
                sourceInputFiles += [sourceFileToAdd]
        
        if seenNonExecutableOutput:
            self.debugMsg("Outputting something other than a linked binary (by the looks of it), so not linking\n")
            isLink = False
        elif isDefinitelyLink:
            self.debugMsg("Saw an option to make us think we ought to be linking\n")
            if isDefinitelyNotLink:
                sys.stderr.write("command cannot both link and not link\n")
                exit(1)
            isLink = True
        elif isDefinitelyNotLink:
            self.debugMsg("Saw an option to make us think we ought not to be linking\n")
            isLink = False
        elif seenSomeInput:    # so long as we have some input, we could be linking
            self.debugMsg("Saw some input, so we could be linking\n")
            isLink = True
        else:
            # it's probably an error, but don't do linky stuff
            self.debugMsg("No input of note, so we can't be linking\n")
            isLink = False

        if outputFile == None and isLink and not "-shared" in args:
            outputFile = "a.out"
        return (sourceInputFiles, objectInputFiles, outputFile, isLink)

    # by default, fixup does nothing
    def fixupDotO(self, filename, errfile):
        return 0

    def optionsToBuildOneObjectFile(self, sourceFile, outputFilename, argvWithoutOutputOptions):
        return argvWithoutOutputOptions + ["-c", "-o", outputFilename, sourceFile]

    def buildOneObjectFile(self, sourceFile, outputFilename, argvWithoutOutputOptions):
        return self.runUnderlyingCompiler([sourceFile], 
            self.optionsToBuildOneObjectFile(sourceFile, outputFilename, argvWithoutOutputOptions))
    
    def runUnderlyingCompiler(self, sourceFiles, otherOptions):
        # HACK, FIXME, etc
        #libraryArgs = [arg for arg in otherOptions if arg.startswith("-l") or arg.endswith(".a") \
        #    or arg.endswith(".so")]
        #nonLibraryArgs = [arg for arg in otherOptions if not arg in libraryArgs]
        # NO NO NO -- the above doesn't work, because we will disrupt the use of 
        # things like "-Wl,--some-option", "-lallocs_noop", "-Wl,--some-option"
        # (e.g. push/pop as-needed)
        commandAndArgs = self.getUnderlyingCompilerCommand(sourceFiles) + \
            otherOptions # nonLibraryArgs + libraryArgs
        self.debugMsg("Environment is %s\n" % str(os.environ))
        self.debugMsg("Running underlying compiler: " + " ".join(commandAndArgs) + "\n")
        ret1 = subprocess.call(commandAndArgs)
        self.debugMsg("Exit status was %d\n" % ret1)
        return ret1

    def makeDotOAndPassThrough(self, argv, customArgs, sourceInputFiles):
        argvToPassThrough = [x for x in argv[1:] if not x in sourceInputFiles]
        argvWithoutOutputOptions = [argvToPassThrough[i] for i in range(0, len(argvToPassThrough)) \
           if argvToPassThrough[i] != '-o' and (i != 0 and argvToPassThrough[i-1] != '-o') \
           and argvToPassThrough[i] != '-shared' and argvToPassThrough[i] != '-c' \
           and argvToPassThrough[i] != '-static']

        self.debugMsg("Source input files: " + ', '.join(sourceInputFiles) + "\n")
        self.debugMsg("Custom args: " + ', '.join(customArgs) + "\n")
        self.debugMsg("argv without output options: " + ', '.join(argvWithoutOutputOptions) + "\n")

        for sourceFile in sourceInputFiles:
            # compile to .o with the custom args
            # -- erase -shared etc, and erase "-o blah"
            outputFilename = self.makeObjectFileName(sourceFile)
            ret1 = self.buildOneObjectFile(sourceFile, outputFilename, \
                    argvWithoutOutputOptions + customArgs)

            if ret1 != 0:
                # we didn't succeed, so quit now
                exit(ret1)
            else:
                ret2 = self.fixupDotO(outputFilename, None)
                if ret2 != 0:
                    # we didn't succeed, so quit now
                    exit(ret2)

                # include the .o file in our passed-through args
                argvToPassThrough = [outputFilename] + argvToPassThrough

        self.debugMsg("After making .o files, passing through arguments " + " ".join(argvToPassThrough) + "\n")
        return argvToPassThrough

