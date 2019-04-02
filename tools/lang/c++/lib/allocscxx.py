#!/usr/bin/env python3

# C++ compiler wrapper for liballocs.

import os, sys
# HACK
liballocs_base = os.path.realpath(os.path.dirname(__file__) + "/../../../..")
sys.path.append(liballocs_base + "/tools")
sys.path.append(liballocs_base + "tools/lang/c++/lib")
from allocscompilerwrapper import *

class AllocsCxx(AllocsCompilerWrapper):

    # FIXME: also new, delete et al
    def defaultL1AllocFns(self):
        return ["malloc(Z)p", "calloc(zZ)p", "realloc(pZ)p", "memalign(zZ)p"]
    def defaultFreeFns(self):
        return ["free(P)"]
    
    def makeObjectFileName(self, sourceFile):
            nameStem, nameExtension = os.path.splitext(sourceFile)
            if (nameExtension == ".cpp" or nameExtension == ".cc" or nameExtension == ".C"):
                outputFilename = nameStem + ".o"
                self.debugMsg("Making a secret output file (from C++ source) " + outputFilename + "\n")
            else:
                outputFilename = sourceFile + ".o"
                self.debugMsg("Making a secret output file (from unknown source) " + outputFilename + "\n")
            return outputFilename
    
    def getUnderlyingCompilerCommand(self, sourceFiles):
        return ["c++"]

if __name__ == '__main__':
    wrapper = AllocsCxx()
    ret = wrapper.main()
    exit(ret)

