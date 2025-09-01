# We need to clobber the by-path meta-DSO, so that
# we force execution to use the by-build-ID meta-DSO path. Or do we?
# The by-build-ID meta-DSO should get priority. So it suffices that
# in this test's .c file, we look for the by-build-ID meta-DSO.

