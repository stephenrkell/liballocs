import os, sys, re, subprocess, tempfile
from compilerwrapper import *

class AllocsCompilerWrapper(CompilerWrapper):

    def defaultL1AllocFns(self):
        return []

    def defaultFreeFns(self):
        return []

    def allL1OrWrapperAllocFns(self):
        if "LIBALLOCS_ALLOC_FNS" in os.environ:
            return self.defaultL1AllocFns() + [s for s in os.environ["LIBALLOCS_ALLOC_FNS"].split(' ') if s != '']
        else:
            return self.defaultL1AllocFns()

    def allSubAllocFns(self):
        if "LIBALLOCS_SUBALLOC_FNS" in os.environ:
            return [s for s in os.environ["LIBALLOCS_SUBALLOC_FNS"].split(' ') if s != '']
        else:
            return []

    def allAllocSzFns(self):
        if "LIBALLOCS_ALLOCSZ_FNS" in os.environ:
            return [s for s in os.environ["LIBALLOCS_ALLOCSZ_FNS"].split(' ') if s != '']
        else:
            return []

    def allAllocFns(self):
        return self.allL1OrWrapperAllocFns() + self.allSubAllocFns() + self.allAllocSzFns()

    def allL1FreeFns(self):
        if "LIBALLOCS_FREE_FNS" in os.environ:
            return self.defaultFreeFns() + [s for s in os.environ["LIBALLOCS_FREE_FNS"].split(' ') if s != '']
        else:
            return self.defaultFreeFns()

    def allSubFreeFns(self):
        if "LIBALLOCS_SUBFREE_FNS" in os.environ:
            return [s for s in os.environ["LIBALLOCS_SUBFREE_FNS"].split(' ') if s != '']
        else:
            return []

    def allFreeFns(self):
        return self.allL1FreeFns() + self.allSubFreeFns()

    def allWrappedSymNames(self):
        syms = []
        for allocFn in self.allAllocFns():
            if allocFn != '':
                m = re.match("(.*)\((.*)\)(.?)", allocFn)
                fnName = m.groups()[0]
                syms += [fnName]
        for freeFn in self.allSubFreeFns():
            if freeFn != '':
                m = re.match("(.*)\((.*)\)(->[a-zA-Z0-9_]+)", freeFn)
                fnName = m.groups()[0]
                syms += [fnName]
        for freeFn in self.allL1FreeFns():
            if freeFn != '':
                m = re.match("(.*)\((.*)\)", freeFn)
                fnName = m.groups()[0]
                syms += [fnName]
        return syms

    def findFirstUpperCase(self, s):
        allLower = s.lower()
        for i in range(0, len(s)):
            if s[i] != allLower[i]:
                return i
        return -1
        
    def getLibAllocsBaseDir(self):
        return os.path.dirname(__file__) + "/../"

    def getLibNameStem(self):
        return "allocs"
    
    def getLdLibBase(self):
        return "-l" + self.getLibNameStem()
     
    def getLinkPath(self):
        return self.getLibAllocsBaseDir() + "/lib"
     
    def getRunPath(self):
        return self.getLinkPath()
    
    def getCustomCompileArgs(self, sourceInputFiles):
        return ["-gdwarf-4", "-gstrict-dwarf", "-fvar-tracking-assignments", \
        "-fno-omit-frame-pointer", "-ffunction-sections"]

    def main(self):
        # un-export CC from the env if it's set to allocscc, because 
        # we don't want to recursively crunchcc the -uniqtypes.c files
        # that this make invocation will be compiling for us.
        # NOTE that we really do mean CC and not CXX here, because
        # all the stuff we build ourselves is built from C.
        #if "CC" in os.environ and os.environ["CC"].endswith(os.path.basename(sys.argv[0])):
        if "CC" in os.environ:# and os.environ["CC"].endswith(os.path.basename(sys.argv[0])):
           del os.environ["CC"]
        self.debugMsg(sys.argv[0] + " called with args  " + " ".join(sys.argv) + "\n")

        sourceInputFiles, objectInputFiles, outputFile = self.parseInputAndOutputFiles(sys.argv)

        # If we're a linker command, then we have to handle allocation functions
        # specially.
        # Each allocation function, e.g. xmalloc, is linked with --wrap.
        # If we're outputting a shared library, we leave it like this,
        # with dangling references to __wrap_xmalloc,
        # and an unused implementation of __real_xmalloc.
        # If we're outputting an executable, 
        # then we link a thread-local variable "__liballocs_current_allocsite"
        # into the executable,
        # and for each allocation function, we link a generated stub.

        allocsccCustomArgs = self.getCustomCompileArgs(sourceInputFiles)
        
        # we add -ffunction-sections to ensure that references to malloc functions 
        # generate a relocation record -- since a *static, address-taken* malloc function
        # might otherwise have its address taken without a relocation record. 
        # Moreover, we want the relocation record to refer to the function symbol, not
        # the section symbol. We handle this by using my hacked-in --prefer-non-section-relocs
        # objcopy option *if* we do symbol unbinding.

        mallocWrapArgs = []
        for sym in self.allWrappedSymNames():
            mallocWrapArgs += ["-Wl,--wrap," + sym]

        linkArgs = []
        if self.isLinkCommand():
            # we need to build the .o files first, 
            # then link in the uniqtypes they reference, 
            # then resume linking these .o files
            if len(sourceInputFiles) > 0:
                self.debugMsg("Making .o files first from " + " ".join(sourceInputFiles) + "\n")
                passedThroughArgs = self.makeDotOAndPassThrough(sys.argv, allocsccCustomArgs, sourceInputFiles)
            else:
                passedThroughArgs = sys.argv[1:]

            # we need to wrap each allocation function
            self.debugMsg("allocscc doing linking\n")
            passedThroughArgs += mallocWrapArgs
            # we need to export-dynamic, s.t. __is_a is linked from liballocs
            linkArgs += ["-Wl,--export-dynamic"]
            # if we're building an executable, append the magic objects
            # -- and link with the noop *shared* library, to be interposable
            if not "-shared" in passedThroughArgs \
                and not "-G" in passedThroughArgs:

                # make a temporary file for the stubs
                stubsfile = tempfile.NamedTemporaryFile(delete=False, suffix=".c")
                self.debugMsg("stubsfile is %s\n" % stubsfile.name)
                stubsfile.write("#include \"" + self.getLibAllocsBaseDir() + "/tools/stubgen.h\"\n")

                def writeArgList(fnName, fnSig):
                    stubsfile.write("#define arglist_%s(make_arg) " % fnName)
                    ndx = 0
                    for c in fnSig: 
                        if ndx != 0:
                            stubsfile.write(", ")
                        stubsfile.write("make_arg(%d, %c)" % (ndx, c))
                        ndx += 1
                    stubsfile.write("\n")

                for allocFn in self.allAllocFns():
                    m = re.match("(.*)\((.*)\)(.?)", allocFn)
                    fnName = m.groups()[0]
                    fnSig = m.groups()[1]
                    retSig = m.groups()[2]
                    writeArgList(fnName, fnSig)
                    sizendx = self.findFirstUpperCase(fnSig)
                    if sizendx != -1:
                        # it's a size char, so flag that up
                        stubsfile.write("#define size_arg_%s make_argname(%d, %c)\n" % (fnName, sizendx, fnSig[sizendx]))
                    else:
                        # If there's no size arg, it's a typed allocation primitive, and 
                        # the size is the size of the thing it returns. How can we get
                        # at that? Have we built the typeobj already? No, because we haven't
                        # even built the binary. But we have built the .o, including the
                        # one containing the "real" allocator function. Call a helper
                        # to do this.
                        size_find_command = self.getLibAllocsBaseDir() + \
                            ["/tools/find-allocated-type-size", fnName] + [ \
                            objfile for objfile in passedThroughArgs if objfile.endswith(".o")]
                        self.debugMsg("Calling " + " ".join(size_find_command) + "\n")
                        outp = subprocess.Popen(size_find_command, stdout=subprocess.PIPE).communicate()[0]
                        self.debugMsg("Got output: " + outp + "\n")
                        # we get lines of the form <number> \t <explanation>
                        # so just chomp the first number
                        outp_lines = outp.split("\n")
                        if (len(outp_lines) < 1 or outp_lines[0] == ""):
                            self.debugMsg("No output from %s" % " ".join(size_find_command))
                            return 1  # give up now
                        sz = int(outp_lines[0].split("\t")[0])
                        stubsfile.write("#define size_arg_%s %d\n" % (fnName, sz))
                    if allocFn in self.allL1OrWrapperAllocFns():
                        stubsfile.write("make_wrapper(%s, %s)\n" % (fnName, retSig))
                    elif allocFn in self.allAllocSzFns():
                        stubsfile.write("make_size_wrapper(%s, %s)\n" % (fnName, retSig))
                    else:
                        stubsfile.write("make_suballocator_alloc_wrapper(%s, %s)\n" % (fnName, retSig))
                    stubsfile.flush()
                # also do subfree wrappers
                for freeFn in self.allSubFreeFns():
                    m = re.match("(.*)\((.*)\)(->([a-zA-Z0-9_]+))", freeFn)
                    fnName = m.groups()[0]
                    fnSig = m.groups()[1]
                    allocFnName = m.groups()[3]
                    ptrndx = fnSig.find('P')
                    if ptrndx != -1:
                        # it's a ptr, so flag that up
                        stubsfile.write("#define ptr_arg_%s make_argname(%d, %c)\n" % (fnName, ptrndx, fnSig[ptrndx]))
                    writeArgList(fnName, fnSig)
                    stubsfile.write("make_suballocator_free_wrapper(%s, %s)\n" % (fnName, allocFnName))
                    stubsfile.flush()
                # also do free (non-sub) -wrappers
                for freeFn in self.allL1FreeFns():
                    m = re.match("(.*)\((.*)\)", freeFn)
                    fnName = m.groups()[0]
                    fnSig = m.groups()[1]
                    ptrndx = fnSig.find('P')
                    if ptrndx != -1:
                        # it's a ptr, so flag that up
                        stubsfile.write("#define ptr_arg_%s make_argname(%d, %c)\n" % (fnName, ptrndx, fnSig[ptrndx]))
                    writeArgList(fnName, fnSig)
                    stubsfile.write("make_free_wrapper(%s)\n" % fnName)
                    stubsfile.flush()
                # now we compile the C file ourselves, rather than cilly doing it, 
                # because it's a special magic stub
                stubs_pp = os.path.splitext(stubsfile.name)[0] + ".i"
                stubs_bin = os.path.splitext(stubsfile.name)[0] + ".o"
                # We *should* pass through some options here, like -DNO_TLS. 
                # To do "mostly the right thing", we preprocess with 
                # most of the user's options, 
                # then compile with a more tightly controlled set
                stubs_pp_cmd = ["cc", "-E", "-o", stubs_pp, \
                    "-I" + self.getLibAllocsBaseDir() + "/tools"] \
                    + [arg for arg in passedThroughArgs if arg.startswith("-D")] \
                    + [stubsfile.name]
                self.debugMsg("Preprocessing stubs file %s to %s with command %s\n" \
                    % (stubsfile.name, stubs_pp, " ".join(stubs_pp_cmd)))
                ret_stubs_pp = subprocess.call(stubs_pp_cmd)
                if ret_stubs_pp != 0:
                    self.debugMsg("Could not preproces stubs file %s: compiler returned %d\n" \
                        % (stubsfile.name, ret_stubs_pp))
                    exit(1)
                # now erase the '# ... file ' lines that refer to our stubs file,
                # and add some line breaks
                stubs_sed_cmd = ["sed", "-r", "-i", "s^#.*allocs.*/stubgen\\.h\" *[0-9]* *$^^\n " \
                + "/__real_|__wrap_|__current_/ s^[;\\{\\}]^&\\n^g", stubs_pp]
                ret_stubs_sed = subprocess.call(stubs_sed_cmd)
                if ret_stubs_sed != 0:
                    self.debugMsg("Could not sed stubs file %s: sed returned %d\n" \
                        % (stubs_pp, ret_stubs_sed))
                    exit(1)
                stubs_cc_cmd = ["cc", "-g", "-c", "-o", stubs_bin, \
                    "-I" + self.getLibAllocsBaseDir() + "/tools", \
                    stubs_pp]
                self.debugMsg("Compiling stubs file %s to %s with command %s\n" \
                    % (stubs_pp, stubs_bin, " ".join(stubs_cc_cmd)))
                try:
                    stubs_output = subprocess.check_output(stubs_cc_cmd, stderr=subprocess.STDOUT)
                except subprocess.CalledProcessError, e:
                    self.debugMsg("Could not compile stubs file %s: compiler returned %d and said \"%s\"\n" \
                        % (stubs_pp, e.returncode, stubs_output))
                    exit(1)
                if stubs_output != "":
                    self.debugMsg("Compiling stubs file %s: compiler said \"%s\"\n" \
                        % (stubs_pp, stubs_output))

                linkArgs += [stubs_bin]
                linkArgs += ["-L" + self.getLinkPath()]
                if not "-static" in passedThroughArgs and not "-Bstatic" in passedThroughArgs:
                    # we're building a dynamically linked executable
                    linkArgs += ["-Wl,-R" + self.getRunPath()]
                    if "LIBALLOCS_USE_PRELOAD" in os.environ and os.environ["LIBALLOCS_USE_PRELOAD"] == "no":
                        linkArgs += [self.getLdLibBase()]
                    else: # FIXME: weak linkage one day; FIXME: don't clobber as-neededness
                        linkArgs += ["-Wl,--no-as-needed", self.getLdLibBase() + "_noop"]
                else:
                    # we're building a statically linked executable
                    if "LIBALLOCS_USE_PRELOAD" in os.environ and os.environ["LIBALLOCS_USE_PRELOAD"] == "no":
                        linkArgs += [self.getLdLibBase()]
                    else:
                        # no load-time overriding; do link-time overriding 
                        # by using the full, preloaded library in archive form
                        linkArgs += [self.getLinkPath() + "/lib" + self.getLibNameStem() + "_preload.a"]
                    
            else:
                # We're building a shared library, so simply add liballocs_noop.o; 
                # only link directly if we're disabling the preload approach
                if "LIBALLOCS_USE_PRELOAD" in os.environ and os.environ["LIBALLOCS_USE_PRELOAD"] == "no":
                    linkArgs += ["-L" + self.getLinkPath()]
                    linkArgs += ["-Wl,-R" + self.getRunPath()]
                    if "LIBALLOCS_USE_PRELOAD" in os.environ and os.environ["LIBALLOCS_USE_PRELOAD"] == "no":
                        linkArgs += [getLdLibBase()]
                else: # FIXME: weak linkage one day....
                    linkArgs += [self.getLinkPath() + "/lib" + self.getLibNameStem() + "_noop.o"]
                # note: we leave the shared library with 
                # dangling dependencies on __wrap_
                # and unused __real_

            linkArgs += ["-ldl"]

        else:
            passedThroughArgs = sys.argv[1:]

        if "DEBUG_CC" in os.environ:
            verboseArgs = ["--verbose"]
        else:
            verboseArgs = []

        argsToExec = verboseArgs + allocsccCustomArgs \
        + linkArgs \
        + passedThroughArgs
        self.debugMsg("about to run cilly with args: " + " ".join(argsToExec) + "\n")
        self.debugMsg("passedThroughArgs is: " + " ".join(passedThroughArgs) + "\n")
        self.debugMsg("allocsccCustomArgs is: " + " ".join(allocsccCustomArgs) + "\n")
        self.debugMsg("linkArgs is: " + " ".join(linkArgs) + "\n")

        ret1 = subprocess.call(self.getUnderlyingCompilerCommand() + argsToExec)

        if ret1 != 0:
            # we didn't succeed, so quit now
            return ret1

        # We did succeed, so we need to fix up the output binary's 
        # __uniqtype references to the actual binary-compatible type
        # definitions which the compiler generated.

        if not self.isLinkCommand():
            if outputFile:
                # we have a single named output file
                ret2 = self.fixupDotO(outputFile, None)
                return ret2
            else:
                # no explicit output file; the compiler output >=1 .o files, one for each input
                for outputFilename in [nameStem + ".o" for (nameStem, nameExtension) in map(os.path.splitext, sourceInputFiles)]:
                    self.fixupDotO(outputFilename, None)

        else: # isLinkCommand()
            # We've just output an object, so invoke make to collect the allocsites, 
            # with our target name as the file we've just built, using ALLOCSITES_BASE 
            # to set the appropriate prefix
            if "ALLOCSITES_BASE" in os.environ:
                baseDir = os.environ["ALLOCSITES_BASE"]
            else:
                baseDir = "/usr/lib/allocsites"
            targetNames = [baseDir + os.path.realpath(outputFile) + ext \
            for ext in [".allocs", "-types.c", "-types.o", "-types.so", "-allocsites.c", "-allocsites.so"]]
            errfilename = baseDir + os.path.realpath(outputFile) + ".makelog"

            ret2 = 42
            with self.makeErrFile(errfilename, "w+") as errfile:
                ret2 = subprocess.call(["make", "-C", self.getLibAllocsBaseDir() + "/tools", \
                    "-f", "Makefile.allocsites"] +  targetNames, stderr=errfile, stdout=errfile)
                if (ret2 != 0 or "DEBUG_CC" in os.environ):
                    self.print_errors(errfile)
            return ret2

    # expose base class methods to derived classes
    def isLinkCommand(self):
        return CompilerWrapper.isLinkCommand(self)
    
    def parseInputAndOutputFiles(self, args):
        return CompilerWrapper.parseInputAndOutputFiles(self, args)
    
    def fixupDotO(self, filename, errfile):
        return CompilerWrapper.fixupDotO(self, filename, errfile)

    def makeDotOAndPassThrough(self, argv, customArgs, inputFiles):
        return CompilerWrapper.makeDotOAndPassThrough(self, argv, customArgs, inputFiles)
