import os, sys, re, subprocess, tempfile, copy
import distutils
import distutils.spawn
from compilerwrapper import *

# we have an extra phase
FAKE_RELOC_LINK = Phase.LINK + 1

class AllocsCompilerWrapper(CompilerWrapper):

    def defaultL1AllocFns(self):
        return []

    def defaultFreeFns(self):
        return []
    
    def wordSplitEnv(self, key):
        return [s for s in os.environ.get(key, "").split(' ') if s != '']

    def allWrapperAllocFns(self):
        return self.wordSplitEnv("LIBALLOCS_ALLOC_FNS")

    def allL1OrWrapperAllocFns(self):
        return self.defaultL1AllocFns() + self.allWrapperAllocFns()

    def allSubAllocFns(self):
        return self.wordSplitEnv("LIBALLOCS_SUBALLOC_FNS")

    def allAllocSzFns(self):
        return self.wordSplitEnv("LIBALLOCS_ALLOCSZ_FNS")

    def allAllocFns(self):
        return self.allL1OrWrapperAllocFns() + self.allSubAllocFns() + self.allAllocSzFns()

    def allL1FreeFns(self):
        return self.defaultFreeFns() + self.wordSplitEnv("LIBALLOCS_FREE_FNS")

    def allSubFreeFns(self):
        return self.wordSplitEnv("LIBALLOCS_SUBFREE_FNS")

    def allFreeFns(self):
        return self.allL1FreeFns() + self.allSubFreeFns()

    def symNamesForFns(self, fns):
        syms = []
        for fn in fns:
            if fn != '':
                # allocfns are "(.*)\((.*)\)(.?)
                # subfreefns are "(.*)\((.*)\)(->[a-zA-Z0-9_]+)"
                # l1freefns are "(.*)\((.*)\)"
                m = re.match("(.*)\((.*)\)(->[a-zA-Z0-9_]+|.)?", fn)
                fnName = m.groups()[0]
                syms += [fnName]
        return syms

    # FIXME: we shouldn't caller-wrap allocator entry points (non-wrappers),
    # though we should callee-wrap them (whic we currently do with --wrap,__real_*)
    def allWrappedSymNames(self):
        return self.symNamesForFns(self.allAllocFns() + self.allSubFreeFns() + self.allL1FreeFns())

    def findFirstUpperCase(self, s):
        allLower = s.lower()
        for i in range(0, len(s)):
            if s[i] != allLower[i]:
                return i
        return -1
        
    def getLibAllocsBaseDir(self):
        # FIXME: don't assume we're run in-place
        return os.path.dirname(__file__) + "/../"

    def getLibNameStem(self):
        return "allocs"
    
    def getDummyWeakObjectNameStem(self):
        return "dummyweaks"
    
    def getDummyWeakLinkArgs(self, outputIsDynamic, outputIsExecutable):
        if outputIsDynamic and outputIsExecutable:
            return [ "-Wl,--push-state", "-Wl,--no-as-needed", \
                    self.getLinkPath() + "/lib" + self.getLibNameStem() + "_" + self.getDummyWeakObjectNameStem() + ".so", \
                    "-Wl,--pop-state" ]
        elif outputIsDynamic and not outputIsExecutable:
            return [self.getLinkPath() + "/lib" + self.getLibNameStem() + "_" + self.getDummyWeakObjectNameStem() + ".o"]
        else:
            return []
    
    def getLdLibBase(self):
        return "-l" + self.getLibNameStem()
     
    def getLinkPath(self):
        return self.getLibAllocsBaseDir() + "/lib"
     
    def getRunPath(self):
        return self.getLinkPath()

    # please override me
    def getBasicCompilerCommand(self):
        return ["cc"]
    
    # This is different: we want a C compiler that we can reliably use
    # to compile generate code. To avoid infinite regress or unwanted
    # recursive application of whatever compiler-wrapping cleverness
    # we're doing, we need to get one that *is not us*. 
    def getBasicCCompilerCommand(self):
        ourPath = os.path.realpath(sys.argv[0])
        whichOutput = subprocess.Popen(["which", "-a", "cc"], stdout=subprocess.PIPE, stderr=sys.stderr).communicate()[0]
        for cmd in [l for l in whichOutput.split("\n") if l != '']:
            # HACK: avoid things in the same directory, to avoid crunchbcc using "cc" a.k.a. crunchcc
            if os.path.dirname(os.path.realpath(cmd)) != os.path.dirname(ourPath):
                sys.stderr.write("Using basic C compiler: %s (we are: %s)\n" % (str(cmd), str(ourPath)))
                return [cmd]
        sys.stderr.write("abort: could not find a C compiler which is not us.\n")
        exit(2)
    
    def getCompilerCommand(self, itemsAndOptions, phases):
        # we add -ffunction-sections to ensure that references to malloc functions 
        # generate a relocation record -- since a *static, address-taken* malloc function
        # might otherwise have its address taken without a relocation record. 
        # Moreover, we want the relocation record to refer to the function symbol, not
        # the section symbol. We handle this by using my hacked-in --prefer-non-section-relocs
        # objcopy option *if* we do symbol unbinding.
        mustHaveOpts = ["-gdwarf-4", "-gstrict-dwarf", "-fno-omit-frame-pointer", "-ffunction-sections" ]
        # HACK
        if not "CC_IS_CLANG" in os.environ:
            # assume gcc
            mustHaveOpts += ["-fvar-tracking-assignments"]
        return self.getBasicCompilerCommand() + mustHaveOpts + [x for x in itemsAndOptions if not x in mustHaveOpts]
    
    def listDefinedSymbolsMatching(self, filename, patterns, errfile=None):
        with (self.makeErrFile(os.path.realpath(filename) + ".fixuplog", "w+") if not errfile else errfile) as errfile:
            regex = "|".join(patterns)
            self.debugMsg("Looking for defined functions matching `%s'\n" % regex)
            cmdstring = "nm -fbsd \"%s\" | grep -v '^[0-9a-f ]\+ U ' | egrep \"^[0-9a-f ]+ . (%s)$\" | sed 's/^[0-9a-f ]\+ . //'" \
                % (filename, regex)
            self.debugMsg("cmdstring for objdump is " + cmdstring + "\n")
            grep_output = subprocess.Popen(["sh", "-c", cmdstring], stdout=subprocess.PIPE, stderr=errfile).communicate()[0]
            return [l for l in grep_output.split("\n") if l != '']
    
    def fixupPostAssemblyDotO(self, filename, errfile):
        self.debugMsg("Fixing up .o file: %s\n" % filename)
        if not Phase.ASSEMBLE in self.enabledPhases:
            self.debugMsg("No .o file output.\n")
            return
        
        # do we need to unbind? 
        # MONSTER HACK: globalize a symbol if it's a named alloc fn. 
        # This is needed e.g. for SPEC benchmark bzip2
        with (self.makeErrFile(os.path.realpath(filename) + ".fixuplog", "w+") if not errfile else errfile) as errfile:

            # also link the file with the uniqtypes it references
            linkUsedTypesCmd = [self.getLibAllocsBaseDir() + "/tools/lang/c/bin/link-used-types", filename]
            self.debugMsg("Calling " + " ".join(linkUsedTypesCmd) + "\n")
            ret = subprocess.call(linkUsedTypesCmd, stderr=errfile)
            if ret != 0:
                self.printErrors(errfile)
                return ret  # give up now

            # Now deal with wrapped functions
            wrappedFns = self.allWrappedSymNames()
            self.debugMsg("Looking for wrapped functions that need unbinding\n")
            toUnbind = self.listDefinedSymbolsMatching(filename, wrappedFns)
            self.debugMsg("Got %s\n" % (str(toUnbind)))
            if toUnbind != []:
                # we need to unbind. We unbind the allocsite syms
                # *and* --prefer-non-section-relocs. 
                # This will give us a file with __def_ and __ref_ symbols
                # for the allocation function. We then rename these to 
                # __real_ and __wrap_ respectively. 
                backup_filename = os.path.splitext(filename)[0] + ".backup.o"
                self.debugMsg("Found that we need to unbind symbols [%s]... making backup as %s\n" % \
                    (", ".join(toUnbind), backup_filename))
                cp_ret = subprocess.call(["cp", filename, backup_filename], stderr=errfile)
                if cp_ret != 0:
                    self.printErrors(errfile)
                    return cp_ret
                unbind_pairs = [["--unbind-sym", sym] for sym in toUnbind]
                unbind_cmd = ["objcopy", "--prefer-non-section-relocs"] \
                 + [opt for pair in unbind_pairs for opt in pair] \
                 + [filename]
                self.debugMsg("cmdstring for objcopy (unbind) is " + " ".join(unbind_cmd) + "\n")
                objcopy_ret = subprocess.call(unbind_cmd, stderr=errfile)
                if objcopy_ret != 0:
                    self.debugMsg("problem doing objcopy (unbind) (ret %d)\n" % objcopy_ret)
                    self.printErrors(errfile)
                    return objcopy_ret
                else:
                    # one more objcopy to rename the __def_ and __ref_ symbols
                    self.debugMsg("Renaming __def_ and __ref_ alloc symbols\n")
                    # instead of objcopying to replace __def_<sym> with <sym>,
                    # we use ld -r to define <sym> and __real_<sym> as *extra* symbols
                    ref_args = [["--redefine-sym", "__ref_" + sym + "=__wrap_" + sym] for sym in toUnbind]
                    objcopy_ret = subprocess.call(["objcopy", "--prefer-non-section-relocs"] \
                     + [opt for seq in ref_args for opt in seq] \
                     + [filename], stderr=errfile)
                    if objcopy_ret != 0:
                        self.printErrors(errfile)
                        return objcopy_ret
                    tmp_filename = os.path.splitext(filename)[0] + ".tmp.o"
                    cp_ret = subprocess.call(["cp", filename, tmp_filename], stderr=errfile)
                    if cp_ret != 0:
                        self.printErrors(errfile)
                        return cp_ret
                    def_args = [["--defsym", sym + "=__def_" + sym, \
                        "--defsym", "__real_" + sym + "=__def_" + sym, \
                        ] for sym in toUnbind]
                    ld_ret = subprocess.call(["ld", "-r"] \
                     + [opt for seq in def_args for opt in seq] \
                     + [tmp_filename, "-o", filename], stderr=errfile)
                    if ld_ret != 0:
                        self.debugMsg("problem doing ld -r (__real_ = __def_) (ret %d)\n" % ld_ret)
                        self.printErrors(errfile)
                        return ld_ret

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

    def fixupLinkedObject(self, filename, errfile):
        self.debugMsg("Fixing up linked output object: %s\n" % filename)
        wrappedFns = self.allWrappedSymNames()
        with (self.makeErrFile(os.path.realpath(filename) + ".fixuplog", "w+") if not errfile else errfile) as errfile:
            #  For any defined allocator function `malloc', we append
            #  -Wl,--defsym,malloc=__wrap___real_malloc
            #  -Wl,--wrap,__real_malloc
            #
            #  i.e. to link in the callee-side instrumentation.
            # For standard allocators, these are defined in liballocs_nonshared.a.
            # For user-specific allocators, we have generated the callee wrappers
            # ourselves, earlier, in  *only* do this for non-wrappers,
            # i.e. for actual allocators.
            syms = [x for x in self.allWrappedSymNames() \
                if x not in self.symNamesForFns(self.allWrapperAllocFns() + self.allAllocSzFns() + \
                    self.allL1FreeFns())]
            matches = self.listDefinedSymbolsMatching(filename, syms)
            return (0, sum([["-Wl,--defsym," + m + "=__wrap___real_" + m, "-Wl,--wrap,__real_" + m] \
              for m in matches], []))
            
            # for any allocator symbols that it defines, we must
            # 1. link in the callee-side stubs it needs
            #          (CAN'T do that now of course -- assume it's already been done)
            # 2. rename __wrap___real_<allocator> to <allocator> 
            #       and <allocator> to something arbitrary
            # In this way, local callers must already have had the extra 
            #   --wrap __real_<allocator> 
            # argument in order to get the callee instr. Internal calls are wired up properly.
            # Next, to allow lib-to-exe calls to hit the callee instr,
            # use objcopy to rename them
            # ARGH. This won't work because objcopy can't rename dynsys 
            pass
            # what allocator fns does it define globally?
            # grep for global symbols -- an upper-case letter after the symname is the giveaway
#                cmdstring = "nm -fposix --extern-only --defined-only \"%s\" | sed 's/ [A-Z] [0-9a-f ]\\+$//' | egrep \"^__wrap___real_(%s)$\""\
#                    % (filename, "|".join(wrappedFns))
#                self.debugMsg("cmdstring is %s\n" % cmdstring)
#                wrappedRealNames = subprocess.Popen(["sh", "-c", cmdstring], stderr=errfile, stdout=subprocess.PIPE).communicate()[0].split("\n")
#                self.debugMsg("output was %s\n" % wrappedRealNames)
#                if len(wrappedRealNames) > 0:
#                    # firstly do the bare (non-wrap-real-prefixed) ones
#                    bareNames = [sym[len("__wrap___real_"):] for sym in wrappedRealNames]
#                    self.debugMsg("Renaming __wrap___real_* alloc symbols: %s\n" % bareNames)
#                    redefine_args = [["--redefine-sym", sym + "=" + "__liballocs_bare_" + sym] \
#                        for sym in bareNames if sym != ""]
#                    objcopy_ret = subprocess.call(["objcopy"] \
#                     + [opt for seq in redefine_args for opt in seq] \
#                     + [filename], stderr=errfile)
#                    if objcopy_ret != 0:
#                        self.printErrors(errfile)
#                        return objcopy_ret
#                    redefine_args = [["--redefine-sym", "__wrap___real_" + sym + "=" + sym] \
#                       for sym in bareNames if sym != ""]
#                    objcopy_ret = subprocess.call(["objcopy"] \
#                     + [opt for seq in redefine_args for opt in seq] \
#                     + [filename], stderr=errfile)
        return (0, [])
        
    def doPostLinkMetadataBuild(self, outputFile):
        # We've just output an object, so invoke make to collect the allocsites, 
        # with our target name as the file we've just built, using ALLOCSITES_BASE 
        # to set the appropriate prefix
        if "ALLOCSITES_BASE" in os.environ:
            baseDir = os.environ["ALLOCSITES_BASE"]
        else:
            baseDir = "/usr/lib/allocsites"
        if os.path.exists(os.path.realpath(outputFile)):
            targetNames = [baseDir + os.path.realpath(outputFile) + ext \
                for ext in [".allocs", "-types.c", "-types.so", "-allocsites.c", "-allocsites.so"]]
            errfilename = baseDir + os.path.realpath(outputFile) + ".makelog"

            ret2 = 42
            with self.makeErrFile(errfilename, "w+") as errfile:
                cmd = ["make", "CC=" + " ".join(self.getBasicCCompilerCommand()), \
                    "-C", self.getLibAllocsBaseDir() + "/tools", \
                    "-f", "Makefile.allocsites"] +  targetNames
                errfile.write("Running: " + " ".join(cmd) + "\n")
                ret2 = subprocess.call(cmd, stderr=errfile, stdout=errfile)
                errfile.write("Exit status was %d\n" % ret2)
                if (ret2 != 0 or "DEBUG_CC" in os.environ):
                    self.printErrors(errfile)
            return ret2
        else:
            return 1

    def getStubGenHeaderPath(self):
        return self.getLibAllocsBaseDir() + "/tools/stubgen.h"

    def getStubGenCompileArgs(self):
        return []
            
    def generateAllocStubsObject(self):
        # make a temporary file for the stubs
        # -- we derive the name from the output binary,
        # -- ... and bail if it's taken? NO, because we want repeat builds to succeed
        stubsfile_name = self.getOutputFilename(Phase.LINK) + ".allocstubs.c"
        with open(stubsfile_name, "w") as stubsfile:
            self.debugMsg("stubsfile is %s\n" % stubsfile.name)
            stubsfile.write("#include \"" + self.getStubGenHeaderPath() + "\"\n")

            def writeArgList(fnName, fnSig):
                stubsfile.write("#define arglist_%s(make_arg) " % fnName)
                ndx = 0
                for c in fnSig: 
                    if ndx != 0:
                        stubsfile.write(", ")
                    stubsfile.write("make_arg(%d, %c)" % (ndx, c))
                    ndx += 1
                stubsfile.write("\n")
                stubsfile.write("#define rev_arglist_%s(make_arg) " % fnName)
                ndx = len(fnSig) - 1
                for c in fnSig[::-1]: # reverse
                    if ndx != len(fnSig) - 1:
                        stubsfile.write(", ")
                    stubsfile.write("make_arg(%d, %c)" % (ndx, c))
                    ndx -= 1
                stubsfile.write("\n")
                stubsfile.write("#define arglist_nocomma_%s(make_arg) " % fnName)
                ndx = 0
                for c in fnSig: 
                    stubsfile.write("make_arg(%d, %c)" % (ndx, c))
                    ndx += 1
                stubsfile.write("\n")
                stubsfile.write("#define rev_arglist_nocomma_%s(make_arg) " % fnName)
                ndx = len(fnSig) - 1
                for c in fnSig[::-1]: # reverse
                    stubsfile.write("make_arg(%d, %c)" % (ndx, c))
                    ndx -= 1
                stubsfile.write("\n")

            # generate caller-side alloc stubs
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
                    size_find_command = [self.getLibAllocsBaseDir() \
                        + "/tools/find-allocated-type-size", fnName] + [ \
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
                    stubsfile.write("make_caller_wrapper(%s, %s)\n" % (fnName, retSig))
                elif allocFn in self.allAllocSzFns():
                    stubsfile.write("make_size_caller_wrapper(%s, %s)\n" % (fnName, retSig))
                else:
                    stubsfile.write("make_suballocator_alloc_caller_wrapper(%s, %s)\n" % (fnName, retSig))
                # for genuine allocators (not wrapper fns), also make a callee wrapper
                if allocFn in self.allSubAllocFns(): # FIXME: cover non-sub clases
                    stubsfile.write("make_callee_wrapper(%s, %s)\n" % (fnName, retSig))
                stubsfile.flush()
            # also do caller-side subfree wrappers
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
                stubsfile.write("make_suballocator_free_caller_wrapper(%s, %s)\n" % (fnName, allocFnName))
                stubsfile.flush()
                if allocFn in self.allSubFreeFns(): # FIXME: cover non-sub and non-void clases
                    stubsfile.write("make_void_callee_wrapper(%s)\n" % (fnName))
            # also do caller-side free (non-sub) -wrappers
            for freeFn in self.allL1FreeFns():
                m = re.match("(.*)\((.*)\)", freeFn)
                fnName = m.groups()[0]
                fnSig = m.groups()[1]
                ptrndx = fnSig.find('P')
                if ptrndx != -1:
                    # it's a ptr, so flag that up
                    stubsfile.write("#define ptr_arg_%s make_argname(%d, %c)\n" % (fnName, ptrndx, fnSig[ptrndx]))
                writeArgList(fnName, fnSig)
                stubsfile.write("make_free_caller_wrapper(%s)\n" % fnName)
                stubsfile.flush()
            # now we compile the C file ourselves, rather than cilly doing it, 
            # because it's a special magic stub
            stubs_pp = os.path.splitext(stubsfile.name)[0] + ".i"
            stubs_bin = os.path.splitext(stubsfile.name)[0] + ".o"
            # We *should* pass through some options here, like -DNO_TLS. 
            # To do "mostly the right thing", we preprocess with 
            # most of the user's options, 
            # then compile with a more tightly controlled set
            extraFlags = self.getStubGenCompileArgs()
            extraFlags += ["-fPIC"]
            stubs_pp_cmd = self.getBasicCCompilerCommand() + ["-std=c11", "-E", "-Wp,-P"] + extraFlags + ["-o", stubs_pp, \
                "-I" + self.getLibAllocsBaseDir() + "/tools", \
                "-I" + self.getLibAllocsBaseDir() + "/include", \
                "-DRELF_DEFINE_STRUCTURES"
                ] \
                + [arg for arg in self.phaseItems[Phase.PREPROCESS] if arg.startswith("-D")] \
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
            # -- HMM, why not just erase all #line directives? i.e. preprocess with -P?
            # We already do this.
            # NOTE: the "right" thing to do is keep the line directives
            # and replace the ones pointing to stubgen.h
            # with ones pointing at the .i file itself, at the appropriate line numbers.
            # This is tricky because our insertion of newlines will mess with the
            # line numbers.
            # Though, actually, we should only need a single #line directive.
            # Of course this is only useful if the .i file is kept around.
            stubs_sed_cmd = ["sed", "-r", "-i", "s^#.*allocs.*/stubgen\\.h\" *[0-9]* *$^^\n " \
            + "/__real_|__wrap_|__current_/ s^[;\\{\\}]^&\\n^g", stubs_pp]
            ret_stubs_sed = subprocess.call(stubs_sed_cmd)
            if ret_stubs_sed != 0:
                self.debugMsg("Could not sed stubs file %s: sed returned %d\n" \
                    % (stubs_pp, ret_stubs_sed))
                exit(1)
            stubs_cc_cmd = self.getBasicCCompilerCommand() + ["-std=c11", "-g"] + extraFlags + ["-c", "-o", stubs_bin, \
                "-I" + self.getLibAllocsBaseDir() + "/tools", \
                stubs_pp]
            self.debugMsg("Compiling stubs file %s to %s with command %s\n" \
                % (stubs_pp, stubs_bin, " ".join(stubs_cc_cmd)))
            stubs_output = None
            try:
                stubs_output = subprocess.check_output(stubs_cc_cmd, stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError, e:
                self.debugMsg("Could not compile stubs file %s: compiler returned %d and said %s\n" \
                    % (stubs_pp, e.returncode, str(e.output)))
                exit(1)
            if stubs_output != "":
                self.debugMsg("Compiling stubs file %s: compiler said \"%s\"\n" \
                    % (stubs_pp, stubs_output))
            return stubs_bin
            
    def getLiballocsLinkArgs(self):
        liballocsLinkArgs = ["-L" + self.getLinkPath()]
        if self.doingFinalLink() and not self.doingStaticLink() and not self.linkingSharedObject():
            # we're building a dynamically linked executable
            liballocsLinkArgs += ["-Wl,-rpath," + self.getRunPath()]
            if "LIBALLOCS_USE_PRELOAD" in os.environ and os.environ["LIBALLOCS_USE_PRELOAD"] == "no":
                liballocsLinkArgs += [self.getLdLibBase()]
            else: # FIXME: weak linkage one day; FIXME: don't clobber as-neededness
                # HACK: why do we need --as-needed? try without.
                # NO NO NO! linker chooses the path of weakness, i.e. instead of 
                # using symbols from _noop.so, uses 0 and doesn't depend on noop.
                # AHA: the GNU linker has this handy --push-state thing...
                liballocsLinkArgs += self.getDummyWeakLinkArgs(True, True)
        elif self.linkingSharedObject():
            # We're building a shared library, so simply add liballocs_noop.o; 
            # only link directly if we're disabling the preload approach
            if "LIBALLOCS_USE_PRELOAD" in os.environ and os.environ["LIBALLOCS_USE_PRELOAD"] == "no":
                liballocsLinkArgs += ["-L" + self.getLinkPath()]
                liballocsLinkArgs += ["-Wl,-rpath," + self.getRunPath()]
                liballocsLinkArgs += [getLdLibBase()]
            else: # FIXME: weak linkage one day....
                liballocsLinkArgs += self.getDummyWeakLinkArgs(True, False)
            # note: we leave the shared library with 
            # dangling dependencies on __wrap_
            # and unused __real_
        elif self.doingStaticLink():
            # we're building a statically linked executable
            if "LIBALLOCS_USE_PRELOAD" in os.environ and os.environ["LIBALLOCS_USE_PRELOAD"] == "no":
                liballocsLinkArgs += [self.getLdLibBase()]
            else:
                # no load-time overriding; do link-time overriding 
                # by using the full liballocs library in archive form
                liballocsLinkArgs += [self.getLinkPath() + "/lib" + self.getLibNameStem() + ".a"]
        else:
            assert not self.doingFinalLink()
            # we're building a relocatable object. Don't add anything, because
            # we'll get multiple definition errors. Instead assume that allocscc
            # will be used to link the eventual output, so that is the right time
            # to fill in the extra undefineds that we're inserting.
            pass
        liballocsLinkArgs += ["-ldl"]
        return liballocsLinkArgs
    
    def main(self):
        # un-export CC from the env if it's set to allocscc, because 
        # we don't want to recursively crunchcc the -uniqtypes.c files
        # that this make invocation will be compiling for us.
        # NOTE that we really do mean CC and not CXX or FC here, because
        # all the stuff we build ourselves is built from C.
        #if "CC" in os.environ and os.environ["CC"].endswith(os.path.basename(sys.argv[0])):
        if "CC" in os.environ:# and os.environ["CC"].endswith(os.path.basename(sys.argv[0])):
           del os.environ["CC"]
        self.debugMsg(sys.argv[0] + " called with args  " + " ".join(sys.argv) + "\n")

        if Phase.LINK in self.enabledPhases:
            self.debugMsg("We are a link command\n")
        else:
            self.debugMsg("We are not a link command\n")
        
        ret = self.runPhasesBeforeLink()
        if ret != 0:
            return ret
        if not Phase.LINK in self.enabledPhases:
            return ret

        # HMM. What are the semantics of linking everything reloc?
        # The only way to do it is to pass -Wl,-r, i.e. invisibly to the compiler.
        # I think that it will link in the crt*.o stuff, say, so
        # we really do get one big object.
        # But it follows that we shouldn't use the compiler for the final link;
        # we must use the linker directly. Or, hmm, maybe we can use -nostdlibs etc.
        # Remind me:  why did we want to do this? It's just so that we can do
        # the callee-side allocator stuff that we were doing badly in the
        # liballocs.so linker script. In there, what we wanted was
        # for any defined allocator function `malloc', we append
        # -Wl,--defsym,malloc=__wrap___real_malloc
        # -Wl,--wrap,__real_malloc
        # ... and generate the corresponding __wrap___real_malloc (callee stub, i.e. hook/event stuff).
        # So in here we want three steps:
        # - reloc link
        # - CHECK for defined allocators and generate/link callee stubs (+ allocator obj!)
        # - CHECK for used allocators and generate/link caller stubs (currently we generate them unconditionally)

        finalLinkArgs = []
        stubsLinkArgs = []
        # if we're building an executable, append the magic objects
        # -- and link with the noop *shared* library, to be interposable.
        # Recall that if we're building a shared object, we don't need to
        # link in the alloc stubs, because we will use symbol interposition
        # to get control into our stubs. OH, but wait. We still have custom
        # allocation functions, and we want them to set the alloc site. 
        # So we do want to link in the wrappers. Do we need to rewrite
        # references to __real_X after this?
        for sym in self.allWrappedSymNames():
            stubsLinkArgs += ["-Wl,--wrap," + sym]
        if self.doingFinalLink():
            # Each allocation function, e.g. xmalloc, is linked with --wrap.
            # If we're outputting a shared library, we leave it like this,
            # with dangling references to __wrap_xmalloc,
            # and an unused implementation of __real_xmalloc.
            # If we're outputting an executable, 
            # then we link a thread-local variable "__liballocs_current_allocsite"
            # into the executable,
            # and for each allocation function, we link a generated stub.
            # FIXME: is it really true that the alloc caller stubs goes only in a final link?
            # Or might we also want it to go in a non-final link?
            # In fact it NEEDS to go in the non-final link so that --wrap can have its effect.
            stubsObject = self.generateAllocStubsObject()
            # CARE: we must insert the wrapper object on the cmdline *before* any 
            # archive that is providing the wrapped functions -- e.g. libc. 
            # HACK: the easiest way is to insert it first, it appears.
            stubsLinkArgs = [stubsObject] + stubsLinkArgs
            # we need to export-dynamic, s.t. __is_a is linked from liballocs
            # FIXME: I no longer understand this
            finalLinkArgs += ["-Wl,--export-dynamic"]
            finalLinkArgs += self.getLiballocsLinkArgs()

        # HACK: if we're linking, always link to a .o and then separately to whatever output file
        allLinkOutputOptions = {"-pie", "-shared", "--pic-executable", \
                       "-Wl,-pie", "-Wl,-shared", "-Wl,--pic-executable", "-Wl,-r", "-Wl,--relocatable"}
        thisLinkOutputOptions = set(self.phaseOptions[Phase.LINK].keys()).intersection(allLinkOutputOptions)
        finalLinkOutput = self.getOutputFilename()
        finalItemsAndOpts = []
        if self.doingFinalLink():
            # okay, first do a via-big-.o link
            # NOTE that we can't link in any shared libraries at this stage -- ld
            # will look only for archives once you pass it -Wl,-r.
            # So we ask not to link in any standard libs etc., and we also remove
            # any libraries which might be shared libraries -- anything "-l".
            # If a .so file is specified directly, it'll fail, so we want to filter these out.
            # Archives specified directly are okay -- SEMANTICS though?
            # What we want is "user code that is going into this link".
            opts = self.specialOptionsForPhases(set({Phase.LINK}), deletions=thisLinkOutputOptions.union(set(["-o"])))
            assert ("-o" not in self.flatOptions(opts))
            relocFilename = finalLinkOutput + ".linked.o"
            extraFirstOpts = ["-Wl,-r", "-o", relocFilename, "-nostartfiles", "-nodefaultlibs", "-nostdlib"]
            allLinkItems = self.flatItems(self.itemsForPhases({Phase.LINK}))
            linkItemsIncluded = []
            linkItemsDeferred = []
            for item in allLinkItems:
                if item.startswith("-L") or item.startswith("-l") or item.endswith(".so"):
                    linkItemsDeferred += [item]
                else:
                    linkItemsIncluded += [item]
            allArgs = self.flatOptions(opts) + extraFirstOpts + stubsLinkArgs + linkItemsIncluded
            assert("-o" not in self.flatItems(self.itemsForPhases({Phase.LINK})))
            self.debugMsg("running underlying compiler once to link with reloc output, with args: " + \
                " ".join(allArgs) + "\n")
            ret = self.runCompiler(allArgs, {FAKE_RELOC_LINK})
            if ret != 0:
                return ret
            ret, extraFinalLinkArgs = self.fixupLinkedObject(relocFilename, None)
            if ret != 0:
                return ret
            finalItemsAndOpts = self.flatOptions(opts) + [x for x in thisLinkOutputOptions] \
              + ["-o", finalLinkOutput] \
              + [relocFilename] + linkItemsDeferred \
              + finalLinkArgs + extraFinalLinkArgs
        else:
            finalItemsAndOpts = self.flatOptions(self.phaseOptions[Phase.LINK]) + \
                self.flatItems(self.itemsForPhases({Phase.LINK}))
        
        self.debugMsg(("running underlying compiler for %s link, with args: " + \
            " ".join(finalItemsAndOpts) + "\n") % ("final" if self.doingFinalLink() else "relocatable"))
        ret = self.runCompiler(finalItemsAndOpts, {Phase.LINK})
        if ret != 0 or not self.doingFinalLink():
            return ret
        return self.doPostLinkMetadataBuild(finalLinkOutput)

