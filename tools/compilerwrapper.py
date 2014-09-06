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
            if args[num].endswith('.o') or args[num].endswith('.a'):
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
    
    def fixupDotO(self, filename, errfile):
        if self.commandStopsBeforeObjectOutput():
            return
        # do we need to unbind? 
        # MONSTER HACK: globalize a symbol if it's a named alloc fn. 
        # This is needed e.g. for SPEC benchmark bzip2
        with (self.makeErrFile(filename + ".fixuplog", "w+") if not errfile else errfile) as errfile:

            wrappedFns = self.allWrappedSymNames()
            self.debugMsg("Looking for wrapped functions that need unbinding\n")
            cmdstring = "objdump -t \"%s\" | grep -v UND | egrep \"[ \\.](%s)$\"; exit $?" \
                % (filename, "|".join(wrappedFns))
            self.debugMsg("cmdstring is " + cmdstring + "\n")
            grep_ret = subprocess.call(["sh", "-c", cmdstring], stdout=errfile, stderr=errfile)
            if grep_ret == 0:
                # we need to unbind. We unbind the allocsite syms
                # *and* --prefer-non-section-relocs. 
                # This will give us a file with __def_ and __ref_ symbols
                # for the allocation function. We then rename these to 
                # __real_ and __wrap_ respectively. 
                backup_filename = os.path.splitext(filename)[0] + ".backup.o"
                self.debugMsg("Found that we need to unbind some or all of symbols [%s]... making backup as %s\n" % \
                    (", ".join(wrappedFns), backup_filename))
                cp_ret = subprocess.call(["cp", filename, backup_filename], stderr=errfile)
                if cp_ret != 0:
                    self.print_errors(errfile)
                    return cp_ret
                unbind_pairs = [["--unbind-sym", sym] for sym in wrappedFns]
                unbind_cmd = ["objcopy", "--prefer-non-section-relocs"] \
                 + [opt for pair in unbind_pairs for opt in pair] \
                 + [filename]
                self.debugMsg("cmdstring is " + " ".join(unbind_cmd) + "\n")
                objcopy_ret = subprocess.call(unbind_cmd, stderr=errfile)
                if objcopy_ret != 0:
                    self.print_errors(errfile)
                    return objcopy_ret
                else:
                    # one more objcopy to rename the __def_ and __ref_ symbols
                    self.debugMsg("Renaming __def_ and __ref_ alloc symbols\n")
                    def_ref_args = [["--redefine-sym", "__def_" + sym + "=" + sym, \
                       "--redefine-sym", "__ref_" + sym + "=__wrap_" + sym] for sym in wrappedFns]
                    objcopy_ret = subprocess.call(["objcopy", "--prefer-non-section-relocs"] \
                     + [opt for seq in def_ref_args for opt in seq] \
                     + [filename], stderr=errfile)
                    if objcopy_ret != 0:
                        self.print_errors(errfile)
                        return objcopy_ret

            self.debugMsg("Looking for wrapped functions that need globalizing\n")
            # grep for local symbols -- a lower-case letter after the symname is the giveaway
            cmdstring = "nm -fposix --defined-only \"%s\" | egrep \"^(%s) [a-z] \"" \
                % (filename, "|".join(wrappedFns))
            self.debugMsg("cmdstring is %s\n" % cmdstring)
            grep_ret = subprocess.call(["sh", "-c", cmdstring], stderr=errfile)
            if grep_ret == 0:
                self.debugMsg("Found that we need to globalize\n")
                globalize_pairs = [["--globalize-symbol", sym] for sym in wrappedFns]
                objcopy_ret = subprocess.call(["objcopy"] \
                 + [opt for pair in globalize_pairs for opt in pair] \
                 + [filename])
                return objcopy_ret
            # no need to objcopy; all good
            self.debugMsg("No need to globalize\n")
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
        # NO NO NO -- this doesn't work, because we will disrupt the use of 
        # things like "-Wl,--some-option", "-lallocs_noop", "-Wl,--some-option"
        # (e.g. push/pop as-needed)
        commandAndArgs = self.getUnderlyingCompilerCommand(sourceFiles) + \
            otherOptions # nonLibraryArgs + libraryArgs
        self.debugMsg("Running " + " ".join(commandAndArgs) + "\n")
        ret1 = subprocess.call(commandAndArgs)
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

