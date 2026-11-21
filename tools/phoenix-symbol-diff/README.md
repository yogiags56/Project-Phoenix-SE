# Phoenix Symbol Diff

Read-only comparison of conventional Mach-O `LC_SYMTAB` symbol records in JSON reports produced by Phoenix Mach-O Analyzer. Requires Python 3.10+ and only the standard library.

## Usage

Analyze the target and donor Mach-O binaries first:

    python3 tools/phoenix-macho/phoenix_macho.py target-kernel --out reports/target-macho.json
    python3 tools/phoenix-macho/phoenix_macho.py donor-kernel --out reports/donor-macho.json

Compare their symbol tables:

    python3 tools/phoenix-symbol-diff/phoenix_symbol_diff.py \
      --target reports/target-macho.json \
      --donor reports/donor-macho.json \
      --out reports/kernel-symbol-diff.json

Run tests:

    python -m unittest discover -s tools/phoenix-symbol-diff/tests -v

## Comparison

- Matches slices by exact CPU type and CPU subtype.
- Compares symbol names and reports shared, target-only and donor-only names.
- Separates defined and undefined symbol-name sets.
- Reports external symbol counts and debug-symbol records.
- Retains input report and source binary SHA-256 values.
- Caps each emitted name list at 100,000 entries and marks truncation.

## Interpretation and limitations

A matching symbol name does not prove identical function signatures, calling conventions, structure layouts, ABI, implementation or runtime availability. Undefined names are references, not proof that a provider is loadable.

Only conventional `LC_SYMTAB` data emitted by Phoenix Mach-O Analyzer is considered. Stripped symbols, exports trie, chained fixups, dyld shared cache exports, external kernel symbol files and symbol recovery are not currently implemented. A report with no symbol table is valid but provides no symbol comparison evidence.

This is a metadata comparison tool, not a kernel compatibility verdict. It does not inspect raw kernel internals, resolve relocations, validate signatures or entitlements, load drivers, patch firmware or restore a device.
