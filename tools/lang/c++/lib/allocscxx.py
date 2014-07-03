#!/usr/bin/env python

# C++ compiler wrapper for liballocs.

import os, sys, re, subprocess, tempfile
# HACK
sys.path.append(os.path.realpath(os.path.dirname(__file__) + "/../../.."))
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
                sys.stderr.write("Making a secret output file (from C++ source) " + outputFilename + "\n")
            else:
                outputFilename = sourceFile + ".o"
                sys.stderr.write("Making a secret output file (from unknown source) " + outputFilename + "\n")
            return outputFilename
    
    def getUnderlyingCompilerCommand(self):
        return ["c++"]

if __name__ == '__main__':
    wrapper = AllocsCxx()
    ret = wrapper.main()
    exit(ret)

