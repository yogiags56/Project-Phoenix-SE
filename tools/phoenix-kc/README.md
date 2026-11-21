# Phoenix Kernel Collection Inspector

Read-only inventory tool for 64-bit Mach-O MH_FILESET containers and LC_FILESET_ENTRY records. Requires Python 3.10+ and the standard library.

## Usage

    python3 tools/phoenix-kc/phoenix_kc.py path/to/kernel-collection
    python3 tools/phoenix-kc/phoenix_kc.py path/to/kernel-collection --out reports/kernel-collection.json

Run tests:

    python -m unittest discover -s tools/phoenix-kc/tests -v

## Capabilities

- Validates the outer 64-bit Mach-O header and requires MH_FILESET.
- Walks bounded load commands and records LC_FILESET_ENTRY identifiers, VM addresses and file offsets.
- Uses entry offsets to bound embedded images and checks embedded Mach-O header/load-command boundaries.
- Produces JSON inventory and SHA-256.

## Limitations

- This is not a complete Apple Kernel Collection decoder.
- Does not decompress, decrypt, recursively parse all embedded images, decode code signatures, chained fixups, symbols or kext dependency metadata.
- Does not extract IMG4 payloads or handle every Apple-specific kernelcache wrapper.
- Successful structural inspection is not evidence of device compatibility.
- The input is never modified; no firmware is patched, signed, executed or restored.

Use firmware files obtained lawfully and keep proprietary binaries local. Do not commit extracted kernel collections or device-specific secrets.
