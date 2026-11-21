# Phoenix FDT Analyzer

Read-only parser for raw standard Flattened Device Tree (FDT/DTB) blobs. Requires Python 3.10+ and the standard library.

## Usage

    python3 tools/phoenix-fdt/phoenix_fdt.py extracted-device-tree.dtb
    python3 tools/phoenix-fdt/phoenix_fdt.py extracted-device-tree.dtb --out reports/n69-fdt.json

Run tests:

    python -m unittest discover -s tools/phoenix-fdt/tests -v

## Capabilities

- Validates the standard FDT header and block boundaries.
- Parses reserve map, structure tokens, node hierarchy and properties.
- Resolves property-name offsets through the strings block.
- Produces node-path index and summary counts.
- Preserves raw property bytes as hex and heuristically labels strings and big-endian 32-bit cells.
- Writes JSON reports without modifying the input.

## Limitations

- Only raw standard FDT blobs are supported. No IMG4/IM4P extraction, decompression, LZFSE handling or Apple-specific wrapper decoding.
- Property decoding is heuristic. Register, interrupt, phandle, GPIO, clock and cell semantics are not resolved.
- A standard FDT parser accepting a file does not prove it is an iOS DeviceTree or establish driver compatibility.
- No firmware patching, signing, decryption, restore or device communication is performed.

Keep proprietary firmware and extracted device trees local. Publish only independently authored code, metadata, hashes and permitted analysis.
