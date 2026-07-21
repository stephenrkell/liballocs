#!/usr/bin/env python3

# C++ compiler wrapper for liballocs.

import os, sys
# HACK
liballocs_base = os.path.realpath(os.path.dirname(__file__) + "/../../../..")
sys.path.append(liballocs_base + "/tools")
sys.path.append(liballocs_base + "tools/lang/c++/lib")
from allocscompilerwrapper import *

if os.environ.get('ALLOCS_DEBUGPY'):
    import debugpy
    debugpy.listen(int(os.environ['ALLOCS_DEBUGPY']))
    debugpy.wait_for_client()

class AllocsCxx(AllocsCompilerWrapper):

    def defaultL1AllocFns(self):
        return ["malloc(Z)p", "calloc(zZ)p", "realloc(pZ)p", "memalign(zZ)p",
                "_Znwm(Z)p", # new(size_t)
                "_Znam(Z)p", # new[](size_t)
                ]
    def defaultFreeFns(self):
        return ["free(P)",
                "_ZdlPv(P)", # delete(void*)
                "_ZdaPv(P)"  # delete[](void*)
                ]

    def makeObjectFileName(self, sourceFile):
            nameStem, nameExtension = os.path.splitext(sourceFile)
            if (nameExtension == ".cpp" or nameExtension == ".cc" or nameExtension == ".C"):
                outputFilename = nameStem + ".o"
                self.debugMsg("Making a secret output file (from C++ source) " + outputFilename + "\n")
            else:
                outputFilename = sourceFile + ".o"
                self.debugMsg("Making a secret output file (from unknown source) " + outputFilename + "\n")
            return outputFilename

    def getCompilationFlags(self):
        """Return flags needed for clang-ast-parser to parse the source with the same
        include paths, defines, and language standard as the real compiler invocation."""
        opts = self.optionsForPhases({Phase.PREPROCESS, Phase.COMPILE})
        return self.flatOptions(opts)

    def getSystemCxxIncludes(self):
        """Query the real C++ compiler for its system include search paths and return
        them as a list of -isystem flags for clang-ast-parser."""
        cxx = os.environ.get("ALLOCSCXX_CXX", "c++")
        try:
            result = subprocess.run(
                [cxx, "-v", "-x", "c++", "/dev/null", "-fsyntax-only"],
                stderr=subprocess.PIPE, stdout=subprocess.DEVNULL, text=True
            )
            lines = result.stderr.split("\n")
            paths = []
            in_list = False
            for line in lines:
                if "#include <" in line and "search starts here" in line:
                    in_list = True
                    continue
                if "End of search list" in line:
                    break
                if in_list and line.startswith(" "):
                    paths.append(line.strip())
            return [item for p in paths for item in ("-isystem", p)]
        except Exception:
            return []

    def runAllocsParser(self, sourceFile):
        parser = os.path.join(
            self.getLibAllocsBaseDir(),
            "tools/lang/c++/bin/clang-ast-parser"
        )
        if not os.path.exists(parser):
            self.debugMsg("clang-ast-parser not found, skipping C++ allocs dump\n")
            return
        compile_flags = self.getCompilationFlags() + self.getSystemCxxIncludes()
        cmd = [parser, str(sourceFile), "--"] + compile_flags
        self.debugMsg("Running clang-ast-parser: " + " ".join(cmd) + "\n")
        subprocess.call(cmd)

    def runPhasesBeforeLink(self):
        ret = super().runPhasesBeforeLink()
        if ret == 0 and not self.onlyPreprocessing() and Phase.ASSEMBLE in self.enabledPhases:
            for src in self.getSourceInputFiles():
                self.runAllocsParser(src)
        return ret

    def getBasicCompilerCommand(self):
        return [os.environ.get("ALLOCSCXX_CXX", "c++")]

if __name__ == '__main__':
    wrapper = AllocsCxx()
    ret = wrapper.main()
    exit(ret)
