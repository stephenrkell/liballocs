import os, sys, re, subprocess, tempfile, copy
from compilerwrapper import *

# we have an extra phase
FAKE_RELOC_LINK = Phase.LINK + 1

class AllocsCompilerWrapper(CompilerWrapper):

    def defaultL1AllocFns(self):
        return []

    def defaultL1FreeFns(self):
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

    def allWrapperFreeFns(self):
        return self.wordSplitEnv("LIBALLOCS_FREE_FNS")

    def allL1OrWrapperFreeFns(self):
        return self.defaultL1FreeFns() + self.allWrapperFreeFns()

    def allSubFreeFns(self):
        return self.wordSplitEnv("LIBALLOCS_SUBFREE_FNS")

    def allFreeFns(self):
        return self.allL1OrWrapperFreeFns() + self.allSubFreeFns()

    def symNamesForFns(self, fns):
        syms = []
        for fn in fns:
            if fn != '':
                # allocfns are "(.*)\((.*)\)(.?)
                # subfreefns are "(.*)\((.*)\)(->[a-zA-Z0-9_]+)"
                # l1freefns are "(.*)\((.*)\)"
                m = re.match("(.*)\\((.*)\\)(->[a-zA-Z0-9_]+|.)?", fn)
                fnName = m.groups()[0]
                syms += [fnName]
        return syms

    # FIXME: we shouldn't caller-wrap allocator entry points (non-wrappers),
    # though we should callee-wrap them (whic we currently do with --wrap,__real_*)
    def allWrappedSymNames(self):
        #return self.symNamesForFns(self.allL1OrWrapperAllocFns() + self.allAllocSzFns() + self.allL1OrWrapperFreeFns())
        return self.symNamesForFns(self.allAllocFns() + self.allFreeFns())

    def findFirstUpperCase(self, s):
        allLower = s.lower()
        for i in range(0, len(s)):
            if s[i] != allLower[i]:
                return i
        return -1
        
    def getLibAllocsBaseDir(self):
        # FIXME: don't assume we're run in-place
        return os.path.dirname(os.path.dirname(__file__))

    def getLibNameStem(self):
        return "allocs"
    
    def getDummyWeakObjectNameStem(self):
        return "dummyweaks"
    
    def getDummyWeakLinkArgs(self, outputIsDynamic, outputIsExecutable):
        if outputIsDynamic:
            return [ "-Wl,--push-state", "-Wl,--no-as-needed", \
                     "-l" + self.getLibNameStem() + "_" + self.getDummyWeakObjectNameStem(), \
                    "-Wl,--pop-state" ]
        else:
            return []
    
    def getLdLibBase(self):
        return "-l" + self.getLibNameStem()
     
    def getLinkPath(self):
        return self.getLibAllocsBaseDir() + "/lib"
     
    def getRunPath(self):
        return self.getLinkPath()

    # please override me... e.g. allocscc overrides this to cilly
    def getBasicCompilerCommand(self):
        return ["cc"]
    
    # This is different: we want a C compiler that we can reliably use
    # to compile generate code. To avoid infinite regress or unwanted
    # recursive application of whatever compiler-wrapping cleverness
    # we're doing, we need to get one that *is not us*. 
    def getPlainCCompilerCommand(self):
        ourPath = os.path.realpath(sys.argv[0])
        whichOutput = subprocess.Popen(["which", "-a", "cc"], stdout=subprocess.PIPE, stderr=sys.stderr).communicate()[0].decode()
        for cmd in [l for l in whichOutput.split("\n") if l != '']:
            # HACK: avoid things in the same directory, to avoid crunchbcc using "cc" a.k.a. crunchcc
            if os.path.dirname(os.path.realpath(cmd)) != os.path.dirname(ourPath):
                #sys.stderr.write("Using basic C compiler: %s (we are: %s)\n" % (str(cmd), str(ourPath)))
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
            grep_output = subprocess.Popen(["sh", "-c", cmdstring], stdout=subprocess.PIPE, stderr=errfile).communicate()[0].decode()
            return [l for l in grep_output.split("\n") if l != '']
    
    def fixupPostAssemblyDotO(self, filename, errfile):
        self.debugMsg("Fixing up .o file: %s\n" % filename)
        if not Phase.ASSEMBLE in self.enabledPhases:
            self.debugMsg("No .o file output.\n")
            return
        
        # do we need to unbind? 
        with (self.makeErrFile(os.path.realpath(filename) + ".fixuplog", "w+") if not errfile else errfile) as errfile:

            # Now deal with globalizing wrapped functions
            self.debugMsg("Looking for wrapped functions that need globalizing\n")
            # grep for local symbols -- a lower-case letter after the symname is the giveaway
            cmdstring = "nm -fposix --defined-only \"%s\" | egrep \"^(%s) [a-z] \"" \
                % (filename, "|".join(self.allWrappedSymNames()))
            self.debugMsg("cmdstring is %s\n" % cmdstring)
            grep_ret = subprocess.call(["sh", "-c", cmdstring], stderr=errfile)
            if grep_ret == 0:
                self.debugMsg("Found that we need to globalize\n")
                globalize_pairs = [["--globalize-symbol", sym] for sym in self.allWrappedSymNames()]
                objcopy_ret = subprocess.call(["objcopy"] \
                 + [opt for pair in globalize_pairs for opt in pair] \
                 + [filename])
                return objcopy_ret
            # no need to objcopy; all good
            self.debugMsg("No need to globalize\n")
            return 0

    def doPostLinkMetadataBuild(self, outputFile, stripRelocs):
        # We've just output an object, so invoke make to collect the allocsites, 
        # with our target name as the file we've just built, using META_BASE 
        # to set the appropriate prefix
        if "META_BASE" in os.environ:
            baseDir = os.environ["META_BASE"]
        else:
            baseDir = "/usr/lib/meta"
        if os.path.exists(os.path.realpath(outputFile)):
            targetNames = [baseDir + os.path.realpath(outputFile) + ext \
                for ext in [".allocs", "-meta.so"]]
            errfilename = baseDir + os.path.realpath(outputFile) + ".makelog"

            ret2 = 42
            with self.makeErrFile(errfilename, "w+") as errfile:
                cmd = ["make", "CC=" + " ".join(self.getPlainCCompilerCommand()), \
                    "-C", self.getLibAllocsBaseDir() + "/tools", \
                    "-f", "Makefile.meta"] +  targetNames
                errfile.write("Running: " + " ".join(cmd) + "\n")
                ret2 = subprocess.call(cmd, stderr=errfile, stdout=errfile)
                errfile.write("Exit status was %d\n" % ret2)
                if ret2 != 0:
                    errfile.write("Metadata build failed, so will not strip relocs from output binary")
                if (ret2 != 0 or "DEBUG_CC" in os.environ):
                    sys.stderr.write("\nstatus %d; printing Makefile.meta errors %sto %s\n" % (ret2, "(if any) " if "DEBUG_CC" in os.environ else "", errfile))
                    self.printErrors(errfile)
                # Now if the metadata build succeeded, and if we're asked to
                # strip relocs
                if stripRelocs and ret2 == 0:
                    cmd = [self.getLibAllocsBaseDir() + "/tools/strip-non-dynamic-relocs.sh", \
                        os.path.realpath(outputFile)]
                    errfile.write("Running: " + " ".join(cmd) + "\n")
                    #subprocess.call(cmd, stderr=errfile, stdout=errfile)
            return ret2
        else:
            return 1

    def getStubGenHeaderPath(self):
        return self.getLibAllocsBaseDir() + "/tools/stubgen.h"

    def getUsedtypesCompileArgs(self):
        if "LIBALLOCSTOOL" in os.environ:
            liballocstool_include_dir = os.environ["LIBALLOCSTOOL"] + "/include"
        else:
            liballocstool_include_dir = self.getLibAllocsBaseDir() + "/contrib/liballocstool/include"
        return ["-I" + liballocstool_include_dir]

    def getStubGenCompileArgs(self):
        if "LIBRUNT" in os.environ:
            runt_include_dir = os.environ["LIBRUNT"] + "/include"
        else:
            runt_include_dir = self.getLibAllocsBaseDir() + "/contrib/libsystrap/contrib/librunt/include"
        if "LIBMALLOCHOOKS" in os.environ:
            mallochooks_include_dir = os.environ["LIBMALLOCHOOKS"] + "/include"
        else:
            mallochooks_include_dir = self.getLibAllocsBaseDir() + "/contrib/libmallochooks/include"
        return ["-I" + runt_include_dir] + self.getUsedtypesCompileArgs() + \
               ["-I" + mallochooks_include_dir] #"-DRELF_DEFINE_STRUCTURES", \

    def generateAllocatorMods(self, linkedRelocFilename, errfile):
        # make a temporary file for the stubs
        # -- we derive the name from the output binary,
        # -- ... and bail if it's taken? NO, because we want repeat builds to succeed
        stubsfile_name = self.getOutputFilename(Phase.LINK) + ".allocstubs.c"
        self.debugMsg("Doing allocator mods given linked output object: %s\n" % \
            linkedRelocFilename)
        elftin = os.environ.get("ELFTIN")
        if elftin == None:
            elftin = os.path.realpath(os.path.dirname(__file__)+ "/../") + "/contrib/elftin"
        stubsLinkArgs = ["-Wl,-plugin=" + elftin + "/xwrap-ldplugin/xwrap-ldplugin.so"]
        for sym in self.allWrappedSymNames():
             stubsLinkArgs += ["-Wl,-plugin-opt=" + sym]
        definedMatches = self.listDefinedSymbolsMatching(linkedRelocFilename, self.allWrappedSymNames())
        with (self.makeErrFile(os.path.realpath(linkedRelocFilename) + ".fixuplog", "w+") if not errfile else errfile) as errfile:
            with open(stubsfile_name, "w") as stubsfile:
                self.debugMsg("stubsfile is %s\n" % stubsfile.name)
                # For any defined allocator function `malloc', we want to interpose on it.
                # We used to do this by appending
                #  -Wl,--defsym,malloc=__wrap___real_malloc
                #  -Wl,--wrap,__real_malloc
                # i.e. to link in the callee-side instrumentation (__wrap___real_malloc)
                # to be called immediately after the call*er*-side instrumentation (__wrap_malloc).
                # For standard allocators, the wrap-reals were defined in liballocs_nonshared.a.
                # -- NOT ANY MORE! What should happen? using libmallochooks.
                # If we do 
                # ALLOC_EVENT_INDEXING_DEFS(__global_malloc, __global_malloc_usable_size)
                # ... what do we get? and what --wrap or --defsyms do we need?
                # The short answer is that we get the indexing event hook defs and a
                # 'struct allocator', but not the malloc hooks.
                # we still need the equivalents of nonshared_hook_wrappers.o and malloc_hook_stubs_wrapdl.o.
                # We need them somehow, perhaps by including the relevant mallochooks .c file.
                if "malloc" in definedMatches:
                    # we are going to xwrap the whole malloc API,
                    # but we still have the two-stage process: our callee-side wrappers
                    # are the __wrap_malloc (user-to-user),
                    # so we need to create a __wrap___real_malloc
                    # that does the indexing.
                    # We create these by doing user2hook and hook2event (always called hook_*).
                    # This generates the __wrap_ user2hook, calling __wrap___real_
                    stubsfile.write('#define _GNU_SOURCE\n') # see generic_malloc_index.h
                    stubsfile.write('#undef MALLOC_PREFIX\n')
                    stubsfile.write('#define MALLOC_PREFIX(s) __wrap___real_##s\n')
                    stubsfile.write('#undef HOOK_PREFIX\n')
                    stubsfile.write('#define HOOK_PREFIX(s) hook_##s\n')
                    stubsfile.write('#include "../src/user2hook.c"\n')
                    stubsfile.write('#undef HOOK_PREFIX\n')
                    stubsfile.write('#undef MALLOCHOOKS_HOOKAPI_\n') # HACK; hookapi.h should not be include-guarded
                    #stubsfile.write('#define HOOK_PREFIX(s) __terminal_hook_##s\n')
                    #stubsfile.write('#include "mallochooks/hookapi.h"\n')
                    stubsfile.write('#define ALLOC_EVENT(s) __global_malloc_##s\n')
                    stubsfile.write('#define HOOK_PREFIX(s) __terminal_hook_##s\n')
                    stubsfile.write('#include "../src/hook2event.c"\n')
                    # set the prefix that will get dlsym'd. But what is it?
                    # It can't be 'no prefix'... it has to be __real_. Remember
                    # we're actually defining the mallocs locally this time, so
                    # '__real_malloc' is a real symbol.
                    stubsfile.write('#undef MALLOC_PREFIX\n')
                    stubsfile.write('#define MALLOC_PREFIX(s) __real_##s\n')
                    stubsfile.write('#define dlsym_nomalloc fake_dlsym\n')
                    stubsfile.write('#undef HOOK_PREFIX\n')
                    stubsfile.write('#define MALLOC_DLSYM_TARGET get_link_map(__terminal_hook_malloc) \n')
                    stubsfile.write('#include "../src/terminal-indirect-dlsym.c"\n')
                    # FIXME: how do we "xwrap some more", i.e. also xwrap the __real_s?
                    # Does this even work?
                    # Our .allocstubs .o file as above will generate a __wrap___real_malloc function
                    # and a __wrap_malloc function.
                    # The __wrap_malloc is the first one, then needs to call __wrap___real_malloc.
                    # In this file, __wrap_malloc will be generated s.t. it calls __real_malloc.
                    # So we should be able to address this change locally.
                    # Maybe just by #define __real_malloc __wrap___real_malloc?
                    # Then our global malloc will be the *caller-side* wrapper.
                    # I think that is NOT correct, because these need to wrap UNDs,
                    # and if (e.g.) we use allocscc to link another DSO that calls out
                    # to this malloc,
                    # we will still insert a caller-side wrapper so get TWO of them.
                    # Can we fix this by linking the caller DSOs --wrap *but* not
                    # including the __wrap_* in them, but rather in the caller object?
                    # I think yes so long as we special-case malloc: __wrap_malloc goes in
                    # liballocs. It could be an alias of 'malloc' because we set
                    # __current_allocsite if we don't currently have it.
                    # Would be nice if we could avoid all this special-casing,
                    # and just figure out at link time what needs to be generated
                    # and where it can live.
                    #
                    # What comes out of this:
                    # __wrap_malloc calls __wrap___real_malloc which calls event hooks and real malloc
                    # output DSO's global 'malloc' becomes __wrap_malloc (thanks to xwrap semantics)
                    # Terminal hooks look for "__real_malloc" in their own DSO.
                    # These are created by the xwrap plugin.
                    # We set these #defines so that stubgen.h, which generates the caller-side
                    # hooks, will actually generate refernces to __wrap___real_*, not __real_,
                    # and thereby call our indexing implementation of malloc etc..
                    stubsfile.write('#define __real_malloc __wrap___real_malloc\n')
                    stubsfile.write('#define __real_free __wrap___real_free\n')
                    stubsfile.write('#define __real_calloc __wrap___real_calloc\n')
                    stubsfile.write('#define __real_realloc __wrap___real_realloc\n')
                    stubsfile.write('#define __real_free __wrap___real_free\n')
                    stubsfile.write('#define __real_memalign __wrap___real_memalign\n')
                    # PROBLEM: 'malloc_usable_size' is neither an allocation function
                    # nor a free function. So we don't xwrap it. So no __real_malloc_usable_size
                    # is created. So __terminal_hook_malloc_usable_size cannot look it up.
                    # Our variously prefixed wrappers are created (hook_malloc_usable_size,
                    # __terminal_hook_malloc_usable_size) but the global 'malloc_usable_size'
                    # remains the original one, i.e. no __real_ alias and no __wrap_ top-level
                    # alias (cf. malloc which has a caller wrapper, __wrap_malloc).
                    # The __wrap___real_malloc_usable_size wrapper only gets called as sizefn!
                    # It never gets called by common-or-garden callers, owing to lack of --wrap.
                    stubsfile.write('#define __real_malloc_usable_size __wrap___real_malloc_usable_size\n')
                    stubsLinkArgs += ["-Wl,--defsym,__real_malloc_usable_size=malloc_usable_size"]
                else:
                    stubsfile.write('#define RELF_DEFINE_STRUCTURES\n')
                stubsfile.write("#include \"" + self.getStubGenHeaderPath() + "\"\n")
                # For the case of generic-small ('suballocator', LIBALLOCS_SUB_ALLOC_FNS),
                # the caller and callee stuff gets generated at the same time
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
                    m = re.match("(.*)\\((.*)\\)(.?)", allocFn)
                    fnName = m.groups()[0]
                    fnSig = m.groups()[1]
                    def tupify(s):
                        return '(' + ','.join([c for c in s]) + ')'
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
                        outp = subprocess.Popen(size_find_command, stdout=subprocess.PIPE).communicate()[0].decode()
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
                        stubsfile.write("make_caller_wrapper(%s, %s, %s, %s, %s, 0)\n" % \
                        ("__wrap_" + fnName, "__real_" + fnName, fnName, tupify(fnSig), retSig))
                    elif allocFn in self.allAllocSzFns():
                        stubsfile.write("make_size_caller_wrapper(%s, %s, %s, %s, %s, 1)\n" % \
                        ("__wrap_" + fnName, "__real_" + fnName, fnName, tupify(fnSig), retSig))
                    else:
                        stubsfile.write("make_suballoc_wrapper(%s, %s, %s)\n" % \
                        (fnName, tupify(fnSig), retSig))
                    # for genuine allocators (not wrapper fns), also make a callee wrapper
                    if allocFn in self.allSubAllocFns(): # FIXME: cover non-sub clases
                        pass
                        #stubsfile.write("make_callee_wrapper(%s, %s)\n" % (fnName, retSig))
                    stubsfile.flush()
                # also do caller-side subfree wrappers
                for freeFn in self.allSubFreeFns():
                    m = re.match("(.*)\\((.*)\\)(->([a-zA-Z0-9_]+))", freeFn)
                    fnName = m.groups()[0]
                    fnSig = m.groups()[1]
                    allocFnName = m.groups()[3]
                    ptrndx = fnSig.find('P')
                    if ptrndx != -1:
                        # it's a ptr, so flag that up
                        stubsfile.write("#define ptr_arg_%s make_argname(%d, %c)\n" % (fnName, ptrndx, fnSig[ptrndx]))
                    writeArgList(fnName, fnSig)
                    stubsfile.write("make_subfree_wrapper(%s, %s, %s)\n" % (fnName, tupify(fnSig), allocFnName))
                    stubsfile.flush()
                    if allocFn in self.allSubFreeFns(): # FIXME: cover non-sub and non-void clases
                        pass
                        #stubsfile.write("make_void_callee_wrapper(%s)\n" % (fnName))
                # also do caller-side free (non-sub) -wrappers
                for freeFn in self.allL1OrWrapperFreeFns():
                    m = re.match("(.*)\\((.*)\\)", freeFn)
                    fnName = m.groups()[0]
                    fnSig = m.groups()[1]
                    ptrndx = fnSig.find('P')
                    if ptrndx != -1:
                        # it's a ptr, so flag that up
                        stubsfile.write("#define ptr_arg_%s make_argname(%d, %c)\n" % (fnName, ptrndx, tupify(fnSig)[ptrndx]))
                    writeArgList(fnName, fnSig)
                    stubsfile.write("make_free_wrapper(%s, %s, %s, %s)\n" % \
                        ("__wrap_" + fnName, "__real_" + fnName, fnName, tupify(fnSig)))
                    stubsfile.flush()
                if "malloc" in definedMatches:
                    stubsfile.write('#include "generic_malloc_index.h"\n')
                    # See above: our hook path for malloc_usable_size never becomes the
                    # global definition of 'malloc_usable_size', unlike the other malloc/free
                    # functions. But we call through our own hook path, to be good citizens
                    # e.g. if there are other hooks linked in after ours (hmm).
                    stubsfile.write('\nALLOC_EVENT_INDEXING_DEFS(__global_malloc, hook_malloc_usable_size)\n')
                    stubsfile.flush()
                    (dynamicListFd, dynamicListFilename) = tempfile.mkstemp()
                    os.unlink(dynamicListFilename)
                    os.write(dynamicListFd, b"{\n")
                    for sym in definedMatches:
                        # FIXME: only do this if the original sym was export-dynamic'd,
                        # and only for malloc-family syms
                        # HMM. Older linkers don't support --export-dynamic-symbol,
                        # so we may have to fall back on --dynamic-list.
                        # stubsLinkArgs += [ "-Wl,--export-dynamic-symbol," + "__real_" + sym]
                        os.write(dynamicListFd, bytes(sym, 'utf-8') + b";\n")
                    # GAH. If we use NamedTemporaryFile it gets collected too soon.
                    # HACK: use /proc/self/fd/NN
                    stubsLinkArgs += ["-Wl,--dynamic-list," + ("/proc/%d/fd/%d" % (os.getpid(), dynamicListFd))]
                    os.write(dynamicListFd, b"};\n")
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
                # WHERE do we get relf.h, in the librunt era?
                # Bit of a hack: in the contrib. FIXME FIXME.
                stubs_pp_cmd = self.getPlainCCompilerCommand() + ["-gdwarf-4", "-std=c11", "-E", "-Wp,-dD", "-Wp,-P"] \
                    + extraFlags + ["-o", stubs_pp, \
                    "-I" + self.getLibAllocsBaseDir() + "/tools", \
                    "-I" + self.getLibAllocsBaseDir() + "/include", \
                    ] \
                    + [arg for arg in self.phaseItems[Phase.PREPROCESS] if arg.startswith("-D")] \
                    + [stubsfile.name] #, "-Wp,-P"]
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
                #stubs_sed_cmd = ["sed", "-r", "-i", "s^#.*allocs.*/stubgen\\.h\" *[0-9]* *$^^\n " \
                #+ "/__real_|__wrap_|__current_/ s^[;\\{\\}]^&\\n^g", stubs_pp]
                #ret_stubs_sed = subprocess.call(stubs_sed_cmd)
                #if ret_stubs_sed != 0:
                #    self.debugMsg("Could not sed stubs file %s: sed returned %d\n" \
                #        % (stubs_pp, ret_stubs_sed))
                #    exit(1)
                stubs_cc_cmd = self.getPlainCCompilerCommand() + ["-gdwarf-4", "-std=c11", "-g"] + extraFlags + ["-c", "-o", stubs_bin, \
                    "-I" + self.getLibAllocsBaseDir() + "/tools", \
                    stubs_pp]
                self.debugMsg("Compiling stubs file %s to %s with command %s\n" \
                    % (stubs_pp, stubs_bin, " ".join(stubs_cc_cmd)))
                stubs_output = None
                try:
                    stubs_output = subprocess.check_output(stubs_cc_cmd, stderr=subprocess.STDOUT)
                except subprocess.CalledProcessError as e:
                    self.debugMsg("Could not compile stubs file %s: compiler returned %d and said %s\n" \
                        % (stubs_pp, e.returncode, str(e.output)))
                    exit(1) # exit the whole process?!
                if stubs_output != b'':
                    self.debugMsg("Compiling stubs file %s: compiler said \"%s\"\n" \
                        % (stubs_pp, stubs_output))
                return (stubs_bin, stubsLinkArgs)
            
    def getLiballocsLinkArgs(self):
        # some link args need to go late-ish on the command line, others early-ish
        liballocsLeftishLinkArgs = ["-L" + self.getLinkPath()]
        liballocsRightishLinkArgs = []
        if self.doingFinalLink() and not self.doingStaticLink() and not self.linkingSharedObject():
            # we're building a dynamically linked executable
            # We extract the dynamic linker path name exactly from the interp-pad.o,
            # because it MUST match. Otherwise we will not merge the strings correctly
            # and we will get a *third* NUL-terminated string in the output .interp section,
            # instead of just /path/to/allocsld.so\0/lib64/ld-linux-x86-64-so.2
            interpPadO = self.getLibAllocsBaseDir() + "/lib/interp-pad.o"
            dynamicLinkerArg = subprocess.Popen(["objcopy", "-Obinary", "-j.interp", interpPadO, "/dev/stdout"], \
                stdout=subprocess.PIPE, stderr=sys.stderr).communicate()[0].decode().split('\0')[0]
            liballocsLeftishLinkArgs += ["-Wl,--dynamic-linker," + dynamicLinkerArg]
            liballocsLeftishLinkArgs += [interpPadO]
            liballocsLeftishLinkArgs += ["-Wl,-rpath," + self.getRunPath()]
            if "LIBALLOCS_USE_PRELOAD" in os.environ and os.environ["LIBALLOCS_USE_PRELOAD"] == "no":
                liballocsRightishLinkArgs += [self.getLdLibBase()]
            else: # FIXME: weak linkage one day; FIXME: don't clobber as-neededness
                # HACK: why do we need --as-needed? try without.
                # NO NO NO! linker chooses the path of weakness, i.e. instead of 
                # using symbols from _noop.so, uses 0 and doesn't depend on noop.
                # AHA: the GNU linker has this handy --push-state thing...
                liballocsRightishLinkArgs += self.getDummyWeakLinkArgs(True, True)
        elif self.linkingSharedObject():
            # We're building a shared library, so simply add liballocs_noop.o; 
            # only link directly if we're disabling the preload approach
            if "LIBALLOCS_USE_PRELOAD" in os.environ and os.environ["LIBALLOCS_USE_PRELOAD"] == "no":
                liballocsLeftishLinkArgs += ["-L" + self.getLinkPath()]
                liballocsLeftishLinkArgs += ["-Wl,-rpath," + self.getRunPath()]
                liballocsLeftishLinkArgs += [getLdLibBase()]
            else: # FIXME: weak linkage one day....
                liballocsRightishLinkArgs += self.getDummyWeakLinkArgs(True, False)
            # note: we leave the shared library with 
            # dangling dependencies on __wrap_
            # and unused __real_
        elif self.doingStaticLink():
            # we're building a statically linked executable
            if "LIBALLOCS_USE_PRELOAD" in os.environ and os.environ["LIBALLOCS_USE_PRELOAD"] == "no":
                liballocsRightishLinkArgs += [self.getLdLibBase()]
            else:
                # no load-time overriding; do link-time overriding 
                # by using the full liballocs library in archive form
                liballocsRightishLinkArgs += [self.getLinkPath() + "/lib" + self.getLibNameStem() + ".a"]
        else:
            assert not self.doingFinalLink()
            # we're building a relocatable object. Don't add anything, because
            # we'll get multiple definition errors. Instead assume that allocscc
            # will be used to link the eventual output, so that is the right time
            # to fill in the extra undefineds that we're inserting.
            pass
        liballocsRightishLinkArgs += ["-ldl"]
        return liballocsLeftishLinkArgs, liballocsRightishLinkArgs
    
    def main(self):
        with self.tempFileManager:
            # un-export CC from the env if it's set to allocscc, because
            # we don't want to recursively crunchcc the -uniqtypes.c files
            # that this make invocation will be compiling for us.
            # NOTE that we really do mean CC and not CXX or FC here, because
            # all the stuff we build ourselves is built from C.
            #if "CC" in os.environ and os.environ["CC"].endswith(os.path.basename(sys.argv[0])):
            if "CC" in os.environ:# and os.environ["CC"].endswith(os.path.basename(sys.argv[0])):
                del os.environ["CC"]
            self.debugMsg(sys.argv[0] + " called with args  " + " ".join(sys.argv) + "\n")

            if self.onlyPreprocessing():
                self.debugMsg("We are only preprocessing, so we won't do anything liballocs-related.")

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
            finalLinkArgsSavedForEnd = []
            # if we're building an executable, append the magic objects
            # -- and link with the noop *shared* library, to be interposable.
            # Recall that if we're building a shared object, we don't need to
            # link in the alloc stubs, because we will use symbol interposition
            # to get control into our stubs. OH, but wait. We still have custom
            # allocation functions, and we want them to set the alloc site.
            # So we do want to link in the wrappers. Do we need to rewrite
            # references to __real_X after this?
            if self.doingFinalLink():
                # we need to export-dynamic, s.t. __is_a is linked from liballocs
                # FIXME: I no longer understand this. Try deleting it / see what happens
                finalLinkArgs += ["-Wl,--export-dynamic"]
                # ANSWER: it breaks uniqtype uniquing, because in-exe uniqtypes
                # (put into .o files by usedtypes) really need to be export-dynamic'd.
                # We should really do all this at link time,
                # allowing us to be selective about what gets export-dynamic'd.
                leftishLinkArgs, rightishLinkArgs = self.getLiballocsLinkArgs()
                finalLinkArgs += leftishLinkArgs
                finalLinkArgsSavedForEnd += rightishLinkArgs

            # HACK: if we're linking, always link to a .o and then separately to whatever output file
            allLinkOutputOptions = {"-pie", "-shared", "--pic-executable", \
                        "-Wl,-pie", "-Wl,-shared", "-Wl,--pic-executable", \
                        "-Wl,-r", "-Wl,--relocatable"}
            # we will delete any options in the above set when we do the link to ".linked.o"
            thisLinkOutputOptions = set(self.phaseOptions[Phase.LINK].keys()).intersection(allLinkOutputOptions)
            finalLinkOutput = self.getOutputFilename(Phase.LINK)
            finalItemsAndOpts = []
            stripRelocsAfterMetadataBuild = False
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
                if self.recognisesOption("-no-pie"):
                    extraFirstOpts += ["-no-pie"]
                allLinkItems = self.flatItems(self.itemsForPhases({Phase.LINK}))
                linkItemsIncluded = []
                linkItemsDeferred = []
                for item in allLinkItems:
                    if item.startswith("-L") or item.startswith("-l") or re.match(".*\\.so(\\.[0-9]+)*$", item):
                        linkItemsDeferred += [item]
                    else:
                        linkItemsIncluded += [item]
                if "-Wl,-q" not in self.flatOptions(opts) and \
                "-Wl,--emit-relocs" not in self.flatOptions(opts):
                    # we want the relocs, so we will add this
                    extraFirstOpts += ["-Wl,-q"]
                    finalLinkArgs += ["-Wl,-q"]
                    stripRelocsAfterMetadataBuild = True
                else:
                    stripRelocsAfterMetadataBuild = False
                allArgs = self.flatOptions(opts) + extraFirstOpts + linkItemsIncluded
                assert("-o" not in self.flatItems(self.itemsForPhases({Phase.LINK})))
                self.debugMsg("running underlying compiler once to link with reloc output, with args: " + \
                    " ".join(allArgs) + "\n")
                ret = self.runCompiler(allArgs, {FAKE_RELOC_LINK})
                if ret != 0:
                    return ret
                # also link the file with the uniqtypes it references
                usedTypesFileName = self.getOutputFilename(Phase.LINK) + ".usedtypes.c"
                usedTypesFile = open(usedTypesFileName, "w")
                usedTypesCmd = [self.getLibAllocsBaseDir() + "/tools/usedtypes", relocFilename]
                self.debugMsg("Calling " + " ".join(usedTypesCmd) + "\n")
                try:
                    outp = subprocess.call(usedTypesCmd, stdout=usedTypesFile)
                except subprocess.CalledProcessError as e:
                    self.debugMsg("Could not generate usedtypes file %s: usedtypes returned %d and said %s\n" \
                        % (usedTypesFileName, e.returncode, str(e.output)))
                usedTypesObjFileName = self.getOutputFilename(Phase.LINK) + ".usedtypes.o"
                usedTypesCcCmd = self.getPlainCCompilerCommand() + self.getUsedtypesCompileArgs() + \
                    ["-gdwarf-4", "-std=c11"] + [usedTypesFileName] + ["-c", "-o", usedTypesObjFileName]
                self.debugMsg("Calling " + " ".join(usedTypesCcCmd) + "\n")
                try:
                    outp = subprocess.check_output(usedTypesCcCmd)
                except subprocess.CalledProcessError as e:
                    self.debugMsg("Could not generate usedtypes object file %s: compiler returned %d and said %s\n" \
                        % (usedTypesObjFileName, e.returncode, str(e.output)))
                libroottypesAFileName = self.getLibAllocsBaseDir() + "/tools/libroottypes.a"
                finalLinkArgsSavedForEnd += [usedTypesObjFileName, libroottypesAFileName]

                # Q. what did this fixup step do? A. For any defined allocator function `malloc', append
                #  -Wl,--defsym,malloc=__wrap___real_malloc
                #  -Wl,--wrap,__real_malloc
                extraFile, extraFinalLinkArgs = self.generateAllocatorMods(relocFilename, None)
                self.debugMsg("generated allocator mods; got %s, %s\n" % (extraFile, str(extraFinalLinkArgs)))
                if ret != 0:
                    return ret
                finalItemsAndOpts = self.flatOptions(opts) + [x for x in thisLinkOutputOptions] \
                + [extraFile] + [relocFilename] + finalLinkArgs + extraFinalLinkArgs \
                + ["-o", finalLinkOutput] \
                + linkItemsDeferred + finalLinkArgsSavedForEnd
            else: # not doing final link, i.e. our invoker was doing link-to-reloc
                finalItemsAndOpts = self.flatOptions(self.phaseOptions[Phase.LINK]) + \
                    self.flatItems(self.itemsForPhases({Phase.LINK}))

            self.debugMsg(("running underlying compiler for %s link, with args: " + \
                " ".join(finalItemsAndOpts) + "\n") % ("final" if self.doingFinalLink() else "relocatable"))
            ret = self.runCompiler(finalItemsAndOpts, {Phase.LINK})
            if ret != 0 or not self.doingFinalLink():
                return ret
            return self.doPostLinkMetadataBuild(finalLinkOutput, stripRelocsAfterMetadataBuild)

