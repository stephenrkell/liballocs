#!/usr/bin/env python3

# Fortran 90 compiler wrapper for liballocs.

import os, sys
# HACK
sys.path.append(os.path.realpath(os.path.dirname(__file__) + "/../../.."))
from allocscompilerwrapper import *

class AllocsFC(AllocsCompilerWrapper):

    # FIXME: also new, delete et al
    def defaultL1AllocFns(self):
        return ["malloc(Z)p", "calloc(zZ)p", "realloc(pZ)p", "memalign(zZ)p"]
    def defaultFreeFns(self):
        return ["free(P)"]
    
    def makeObjectFileName(self, sourceFile):
            nameStem, nameExtension = os.path.splitext(sourceFile)
            if (nameExtension == ".f90" or nameExtension == ".f" or nameExtension == ".f77"):
                outputFilename = nameStem + ".o"
                self.debugMsg("Making a secret output file (from Fortran source) " + outputFilename + "\n")
            else:
                outputFilename = sourceFile + ".o"
                self.debugMsg("Making a secret output file (from unknown source) " + outputFilename + "\n")
            return outputFilename
    
    def getUnderlyingCompilerCommand(self, fnames):
        return ["gfortran"]

if __name__ == '__main__':
    wrapper = AllocsFC()
    ret = wrapper.main()
    exit(ret)

