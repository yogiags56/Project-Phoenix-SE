# Phoenix Kext Dependency Analyzer

Read-only inventory of extracted Apple-style `.kext` bundles. Requires Python 3.10+ and uses only the standard library.

## Usage

    python3 tools/phoenix-kext/phoenix_kext.py path/to/extracted-kext-directory
    python3 tools/phoenix-kext/phoenix_kext.py path/to/extracted-kext-directory --out reports/kexts.json

Run tests:

    python -m unittest discover -s tools/phoenix-kext/tests -v

## Capabilities

- Recursively discovers `.kext` directories without following directory symlinks.
- Reads XML or binary `Info.plist` using Python's plist parser.
- Inventories bundle identifier, executable, version, platform and required metadata.
- Extracts `OSBundleLibraries` dependency declarations.
- Resolves dependency identifiers against the scanned bundle set.
- Reports unresolved dependencies and duplicate bundle identifiers.
- Emits a JSON report with SHA-256 for each Info.plist.

## Important interpretation

A dependency marked resolved means only that a bundle with the requested identifier exists in the scanned directory. It does **not** prove ABI compatibility, version satisfaction, successful loading, or support for A9/iOS. The declared version constraint is recorded, not evaluated.

## Limitations

- Does not parse Mach-O executable contents, kernel symbols, code signatures or entitlements.
- Does not inspect DriverKit `.dext` bundles.
- Does not determine whether a kernel extension is loadable on a particular OS build or device.
- Does not modify files, patch firmware, sign binaries or restore a device.

Keep extracted firmware and proprietary binaries local. Commit only synthetic test fixtures and source code.
