# PMU Reference Audit — iOS 16.1 SE1 proof of concept

**Status:** static source audit only  
**Reference repository:** https://github.com/pwnerblu/iphonese-ios16  
**Reference file:** `patchsrc/pmuhax.c`  
**Audited source blob:** `1117445bcb8665d7a812e1bb2b22c4c213329376`  
**Reference branch:** `main` (record the blob SHA above; do not rely on a moving branch name)

## Executive finding

The reference PMU patcher is an experimental adaptation from an iPad 5 donor PMU implementation identified as `D2365` to the iPhone SE 1 target personality `D2255`. Its own header says its instruction signatures were derived from the supplied iOS 16.1 iPad 5 kernel and that other builds must satisfy every signature; it does not claim universal iOS 16.x support.

The code is substantially more than a handful of constant substitutions. It locates an embedded PMU kext inside a prelinked ARM64 Mach-O kernel, verifies signature windows, updates PMU/GPIO-related code and metadata, replaces an LDO descriptor table, adjusts an interrupt mask, and installs a sample-array guard stub in executable kernel padding. The source explicitly says hardware validation is pending.

This audit does **not** establish that the patch is safe, that it works on all SE1 devices, or that its approach can be reused for a later iOS release.

## Source-derived inventory

The `rules[]` table contains 70 rule entries:

| Rule indices | Count | Source labels / stated purpose |
|---|---:|---|
| 0–27 | 28 | GPIO geometry / transfer |
| 28–48 | 21 | PMU event / mask geometry |
| 49 | 1 | Shutdown interrupt mask size |
| 50–53 | 4 | 25-byte external interrupt mask copy |
| 54–65 | 12 | LDO index, rail masks, alternate-enable and gate paths |
| 66–69 | 4 | LDO control-flow/table-reference anchors; discovery-only |

Rules 0–65 are marked for instruction replacement. Rules 66–69 are anchors and are marked `change=0`. The source also defines four explicit branch redirects between LDO-related rule locations.

All rules are discovered by scanning the PMU executable region at 4-byte alignment and applying each signature's value/mask pairs. The program requires exactly one match for every rule; zero or multiple matches terminate before output is written. This strict uniqueness gate is a valuable safety property, but a unique match is not proof that the matched code has the intended semantics.

## Major adaptation groups

### 1. GPIO geometry and transfer constants

The source comments describe changes including:

- `cmp w0, #0x60` → `cmp w0, #0x54`
- `mov w1, #0x967` → `mov w1, #0x964`
- repeated `0x18` geometry/length comparisons or immediate values → `0x15`
- `0x24` values → `0x22`
- `0x12` values → `0x11`
- one arithmetic immediate `0x8bd` → `0x8c0`

These are source-comment descriptions of patch intent. They are not yet independently confirmed against disassembled function boundaries, call sites, or hardware register documentation. In particular, do not infer GPIO pin numbering or transfer-buffer sizes from the constants alone.

### 2. PMU event and mask geometry

The comments describe adjustments such as:

- `0x1e` → `0x19` in immediate loads and comparisons
- `0x1601` → `0x1301`
- `0x2c01` → `0x2601`
- `0x2c00` → `0x2600`
- `0xb0` → `0x98`

The source labels these as PMU event/mask geometry. Their precise meaning must be established by decoding the surrounding instructions and correlating them with PMU data structures or documented hardware interfaces. Treat them as unexplained constants until then.

### 3. LDO handling

The patcher modifies LDO-related bounds, fixed and programmable rail masks, and alternate-enable control flow. It also embeds `ldo_before` and `ldo_after` descriptor-table byte arrays.

The table replacement is guarded by a code-reference check: the patcher finds the LDO table anchor, decodes an ADRP+ADD reference, maps the resulting virtual address into the outer kernel, and requires it to point to the exact matched table location. This is stronger than blindly replacing a byte sequence, but the table's field schema and electrical meaning still require independent documentation.

Four branch redirects connect LDO code paths to matched anchors. The code checks branch alignment and immediate range before writing those redirects.

### 4. Shutdown and external interrupt masks

The source requires a unique 30-byte shutdown mask and changes byte offset 9 to `255`. It also includes four rules labelled as 25-byte external interrupt mask copies.

The exact interrupt lines and polarity semantics are not identified by the labels alone. Do not translate these edits into claims about specific peripherals without matching the data to the relevant PMU implementation and device tree.

### 5. PMU personality and sample guard

The patcher locates an embedded kext whose class string is `AppleD2365PMU`, then finds its `IONameMatch` personality entry and changes `pmu,d2365` to `pmu,d2255`.

It additionally searches for an `AppleARMPMU` image and matches a sample/retain context plus a native failure-cleanup sequence. It finds executable trailing padding using section boundaries, verifies the candidate padding is zero-filled, writes an eight-instruction guard stub, and redirects execution to it.

The source comments describe the guard's intended NULL-sample path: release the temporary sample array and branch to native cleanup. The source itself states hardware validation is pending. This hook deserves a separate control-flow and ABI audit before it is considered understood.

## Input and output assumptions

The source header specifies a raw little-endian ARM64 prelinked Mach-O kernel input. The code expects:

- a 64-bit ARM Mach-O image;
- `__PRELINK_TEXT` and `__PRELINK_INFO` in the outer kernel;
- one embedded `AppleD2365PMU` kext with `__TEXT` and `__TEXT_EXEC`;
- one matching PMU metadata personality;
- unique instruction signatures and descriptor/reference anchors;
- sufficient verified executable padding for the guard stub.

It does not use fixed kernel file offsets or a UUID allowlist. This improves relocation tolerance, but does not remove dependence on the exact instruction patterns, binary layout, donor implementation, or firmware build.

## Phoenix conclusions

1. **Confirmed:** the reference patcher is specifically a D2365-to-D2255 PMU adaptation for the SE1 port, with signatures derived from the supplied iOS 16.1 iPad 5 kernel.
2. **Confirmed:** its adaptation covers GPIO transfer geometry, PMU event/mask values, interrupt masks, LDO tables/control flow, PMU personality matching, and a sample guard.
3. **Confirmed:** it validates unique matches and several address/branch constraints before emitting a patched output.
4. **Not confirmed:** the electrical meaning of every changed constant, whether all changes are necessary, or whether the patch works on a broad range of SE1 hardware.
5. **Not transferable by assumption:** a later iOS PMU kext may have different classes, functions, data layouts, signatures, and calling conventions. Reusing these constants or signatures without fresh analysis is unjustified.
6. **Not tested by Phoenix:** no donor IPSW, target kernel, PMU binary, device, or physical hardware was tested as part of this source-only audit.

## Next evidence required

- Obtain legally sourced, exact-build donor and target kernel collections / prelinked kernel images.
- Record firmware build identifiers, image hashes, Mach-O UUIDs, architecture, and extraction procedure.
- Extract the embedded PMU kext and generate symbol-aware disassembly for each matched signature window.
- Decode every changed instruction and classify the data constants separately from instruction immediates.
- Reconstruct each LDO branch path and the sample guard's register/liveness/stack assumptions.
- Correlate PMU personality strings and GPIO/LDO properties with the corresponding device-tree nodes and driver metadata.
- Build a cross-version comparison matrix before considering any patch port.

## References

- Reference source: https://github.com/pwnerblu/iphonese-ios16/blob/main/patchsrc/pmuhax.c
- Rule table and jump map: https://github.com/pwnerblu/iphonese-ios16/blob/main/patchsrc/pmuhax.c#L940-L1020
- Rule discovery and address validation: https://github.com/pwnerblu/iphonese-ios16/blob/main/patchsrc/pmuhax.c#L1089-L1185
- Guard hook preparation and application: https://github.com/pwnerblu/iphonese-ios16/blob/main/patchsrc/pmuhax.c#L1187-L1255
- PMU kext/personality discovery and patch orchestration: https://github.com/pwnerblu/iphonese-ios16/blob/main/patchsrc/pmuhax.c#L1280-L1344

