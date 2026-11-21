# Phoenix Mach-O Analyzer

Read-only parser for 64-bit Mach-O and universal/fat binaries. Requires Python 3.10+ and uses only the standard library.

## Usage

    python3 tools/phoenix-macho/phoenix_macho.py path/to/kernel-or-executable
    python3 tools/phoenix-macho/phoenix_macho.py path/to/binary --out reports/macho.json

Run tests:

    python -m unittest discover -s tools/phoenix-macho/tests -v

## Current capabilities

- Parses thin 64-bit Mach-O binaries and universal/fat containers.
- Validates header, architecture table, load-command boundaries and slice ranges.
- Inventories LC_SEGMENT_64 segments and sections.
- Reads LC_UUID and LC_BUILD_VERSION metadata.
- Reads conventional LC_SYMTAB entries when present.
- Produces JSON reports and SHA-256 hashes.

## Limitations

- No extraction of IMG4 payloads or decompression of kernelcache/kernel collections.
- Does not decode chained fixups, export trie, code signatures, encrypted payloads or Apple-specific kernel collection metadata.
- Symbol inventory is limited to conventional LC_SYMTAB; stripped binaries may expose no names.
- Parsing is not a compatibility verdict and does not patch, sign, execute or restore firmware.

Keep proprietary firmware local. Do not commit extracted kernel binaries, keys, or copyrighted firmware components.
