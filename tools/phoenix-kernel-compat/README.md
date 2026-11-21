# Phoenix Kernel Compatibility Analyzer

Correlates JSON reports produced by Phoenix Mach-O Analyzer, Phoenix Kernel Collection Inspector and Phoenix Kext Dependency Analyzer. Requires Python 3.10+ and only the standard library.

## Inputs

Provide six reports: target and donor versions of:
- Mach-O inventory (kernel or relevant executable image)
- Kernel Collection inventory
- Kext dependency inventory

Example:

    python3 tools/phoenix-kernel-compat/phoenix_kernel_compat.py \
      --target-macho reports/n69/kernel-macho.json \
      --target-kc reports/n69/kernel-collection.json \
      --target-kext reports/n69/kexts.json \
      --donor-macho reports/donor/kernel-macho.json \
      --donor-kc reports/donor/kernel-collection.json \
      --donor-kext reports/donor/kexts.json \
      --out reports/kernel-compatibility.json

Run tests:

    python -m unittest discover -s tools/phoenix-kernel-compat/tests -v

## Output

The JSON report records input paths and SHA-256 hashes, Mach-O and Kernel Collection CPU type/subtype tuples, shared and differing architecture evidence, and shared/unique kext bundle identifiers and dependency edges.

## Interpretation

- `Potential`: at least one architecture tuple or bundle identifier overlaps. This is only a lead for further analysis.
- `Incompatible`: at least one binary layer has declared architecture tuples on both sides with no overlap.
- `Unknown`: supplied reports do not provide comparable positive evidence.

An architecture match is not proof of kernel ABI, kernel API, CPU feature, board, device-tree, driver, SEP, baseband, Cryptex, restore or userspace compatibility. Bundle ID equality does not establish executable equivalence or loadability.

## Limitations

The tool correlates Phoenix JSON metadata. It does not parse raw kernelcache files, decrypt or decompress firmware, resolve kernel symbols, validate kext ABI or signatures, interpret entitlements, or test on hardware. No firmware is modified, patched, signed, executed or restored.

Use reports from exact, independently verified target and donor builds. Do not treat an arbitrary same-architecture donor as interchangeable with the iPhone SE platform.
