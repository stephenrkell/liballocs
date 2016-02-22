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
    
    def isLinkCommand(self):
        seenLib = False
        seenNonExecutableOutput = False
        # By default, the compiler will try to output an executable.
        # But if we see options for other kinds of output, we take note.
        for argnum in range(0,len(sys.argv)):
            arg = sys.argv[argnum]
            if arg.startswith('-l'):
                seenLib = True
            if arg == '-shared' or arg == '-G':
                return True
            if arg == '-c':
                return False
            if arg == '-E' or arg == '-S':
                return False
            # -M options: if we use -MF or -MD or -MMD, we might actually be doing the compile. 
            if (arg == '-M' or arg == '-MM') and not ("-MF" in sys.argv):
                return False
            if arg == "-o" and len(sys.argv) >= argnum + 2:
                outputFilename = os.path.basename(sys.argv[argnum + 1])
                # HACK: is this really necessary?
                if outputFilename.endswith(".o") or outputFilename.endswith(".i"):
                    seenNonExecutableOutput = True
        if seenNonExecutableOutput:
            return False
        return True
        # NOTE: we don't use seenLib currently, since we often link simple progs without any -l
    
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
        for num in range(0,len(args)):
            if skipNext: 
                skipNext = False
                continue
            #if args[num] == "-V":
            #    args[num] = "-0"
            if args[num] == "-o":
                outputFile = args[num + 1]
                skipNext = True
            if args[num] == "-x":
                if args[num + 1] == "none":
                    currentLang = None
                else:
                    currentLang = args[num + 1]
                skipNext = True
            if args[num] == "-include" or args[num] == "-isystem" \
                  or args[num] == "-include" or args[num] == "-idirafter" \
                  or args[num] == "-imacros" or args[num] == "-iprefix" \
                  or args[num] == "-iquote" or args[num] == "-iwithprefix" \
                  or args[num] == "-iwithprefixbefore":
                skipNext = True # HMM -- want to save this somehow?
            if args[num] == '-param' or args[num] == '--param':
                skipNext = True
            if args[num] == '-MT' or args[num] == "-MF":
                skipNext = True
            if args[num] != "-" and args[num].startswith('-'):
                continue
            if num == 0:
                continue # this means we have "allocscc" as the arg
            # glibc builds some files with ".os" extensions
            if args[num].endswith('.o') or args[num].endswith('.os') or args[num].endswith('.a'):
                objectInputFiles += [args[num]]
                continue
            if args[num].endswith('.so'):
                # HMM: what does this mean exactly? it's like "-lBLAH" but giving an explicit path
                objectInputFiles += [args[num]]
                continue
            else:
                self.debugMsg("guessed that source file is " + args[num] + "\n")
                sourceFileToAdd = SourceFile(args[num])
                if currentLang != None:
                    sourceFileToAdd.lang = currentLang
                sourceInputFiles += [sourceFileToAdd]
                    
        if outputFile == None and self.isLinkCommand() and not "-shared" in args:
            outputFile = "a.out"
        return (sourceInputFiles, objectInputFiles, outputFile)

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

