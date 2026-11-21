# Phoenix Patch Pattern Analyzer

Read-only lexical inventory for C patcher source files from the iOS 16.1 reference project. It extracts common masked ARM64 signature arrays, nearby comments, references, function declarations, mutation helper call sites, and source SHA-256 hashes.

Python 3.10+; standard library only.

## Usage

Obtain upstream source files separately and preserve their provenance:

    python tools/phoenix-patch-patterns/phoenix_patch_patterns.py \
      --source pmu=upstream/patchsrc/pmuhax.c \
      --source kextport=upstream/patchsrc/kextport.c \
      --source multitouch=upstream/patchsrc/mthax.c \
      --source wifi=upstream/patchsrc/wlanhax.c \
      --source backboard=upstream/patchsrc/backboardhax.c \
      --source baseband=upstream/patchsrc/bbupdaterpatch.c \
      --source dyld-cache=upstream/patchsrc/dscpatch.c \
      --out-json reports/patch-patterns.json \
      --out-md reports/patch-patterns.md

The tool never downloads, compiles, or executes upstream code. It does not modify source files, firmware, or device data.

## Limitations

This is a lexical inventory, not an ARM64 disassembler or semantic patch verifier. It does not calculate whether signatures are unique in a binary, decode control-flow targets, infer hardware meaning, or establish runtime correctness. Macros, complex expressions, unusual initializer syntax, and helper functions outside recognized names may not be fully represented. Review the original C source at the recorded hash and line number before drawing conclusions.

No patcher is compiled or run. No IPSW is generated or restored. No hardware test is performed.
