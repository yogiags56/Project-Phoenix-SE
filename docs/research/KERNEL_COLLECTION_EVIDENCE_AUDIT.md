# Kernel Collection Evidence Audit

**Project:** Project Phoenix SE  
**Audit date:** 2026-11-28  
**Branch:** `main`  
**Audit type:** Static source and documentation review  
**Target direction:** iPhone SE (2016), A9 / iPhone8,4 / n69  
**Prospective donor:** iPhone SE (2020), A13 Bionic  
**OS target policy:** iOS 27.3 or later

## 1. Executive summary

Phoenix already contains a useful read-only analysis chain for Mach-O, MH_FILESET Kernel Collections, kext metadata, dependency graphs, cross-report architecture correlation, and evidence-backed A9 subsystem profiles.

The tools are deliberately conservative and clearly document that metadata overlap is not proof of compatibility. The principal gap is not another generic parser: it is **exact-build evidence binding**. The current kernel compatibility analyzer accepts six reports by role, but does not itself establish that the three target reports belong to one exact target firmware build or that the three donor reports belong to one exact donor firmware build. A researcher can accidentally compare reports from different builds and still receive a syntactically valid result.

No iOS 27.3+ donor IPSW or matching target/donor report set was supplied or verified during this audit. Therefore this document records tool capabilities and evidence gaps; it does not report a kernel compatibility result.

## 2. Audited implementation and source identities

The following files were read from the repository's `main` branch:

| Component | File | Blob SHA-1 |
|---|---|---|
| Kernel Collection Inspector | `tools/phoenix-kc/phoenix_kc.py` | `afeedec4e5a33873b48d775064a01e5e97323b2a` |
| Kernel Compatibility Analyzer | `tools/phoenix-kernel-compat/phoenix_kernel_compat.py` | `706afec754b288e4a227c4e1fe39c87d79e61ab5` |
| Kernel Dependency Graph | `tools/phoenix-kernel-graph/phoenix_kernel_graph.py` | `5f0b242902a5e85df435635764c4fbb83b12deef` |
| A9 Platform Profiler | `tools/phoenix-a9-profile/phoenix_a9_profile.py` | `e32b6678067f49f8305af3c990f8d188e4b1013c` |
| Mach-O Analyzer README | `tools/phoenix-macho/README.md` | `1f66c7508afbc977b0d452ab123990f7d128ccff` |
| Firmware Inspector README | `tools/phoenix-inspector/README.md` | `3d60273e1a717f441e897403118aacbda9f5fc83` |
| Kext Analyzer README | `tools/phoenix-kext/README.md` | `972f8c8fadf4e4fe7be8d54fcf6d0c86b67a7e4e` |
| FDT Analyzer README | `tools/phoenix-fdt/README.md` | `a6985906e0e78468ab6396b5c4fd4c5d1e8e984f` |

These hashes identify the reviewed file contents, not the provenance of any firmware binary.

## 3. Findings by tool

### 3.1 Kernel Collection Inspector

Observed capabilities:
- Validates a 64-bit Mach-O header and requires `MH_FILESET`.
- Bounds the outer load-command table and records `LC_FILESET_ENTRY` identifiers, VM addresses, and file offsets.
- Uses sorted entry offsets to estimate each embedded image's available span.
- Checks embedded Mach-O magic, header, and load-command table bounds.
- Emits source file size and SHA-256.

Important limitations:
- It does not recursively decode embedded load commands or fully parse each fileset image.
- It does not decode code signatures, chained fixups, symbols, kext metadata, or dependency semantics.
- It does not decode IMG4, decrypt, or decompress kernelcache payloads.
- A structurally valid entry is not proof that it is a loadable kernel extension or is compatible with the target.

### 3.2 Kernel Compatibility Analyzer

Observed capabilities:
- Requires target and donor Mach-O, Kernel Collection, and kext JSON reports.
- Records the path and SHA-256 of each input report.
- Compares reported CPU type/subtype tuples.
- Compares kext bundle identifiers and records declared dependency edges.
- Uses conservative labels: `Potential`, `Incompatible`, and `Unknown`.

Critical limitation:
- The analyzer does not validate firmware identity across its six input reports. It does not require the three target reports to share one ProductType/ProductVersion/BuildVersion/manifest identity, nor the three donor reports to share one such identity.
- A shared architecture tuple or bundle ID is only a research lead.
- A reported architecture conflict is limited to the supplied metadata layer; it is not a complete device compatibility verdict.
- It does not evaluate kext version constraints, kernel symbols, ABI, CPU feature requirements, signatures, entitlements, DeviceTree bindings, SEP, baseband, Cryptex, restore, or runtime behavior.

**Audit conclusion:** use this analyzer only after a human has independently established exact report provenance. The next engineering improvement should be an evidence-set manifest and validator, not a more optimistic compatibility score.

### 3.3 Kernel Dependency Graph

Observed capabilities:
- Builds nodes from kext bundle metadata.
- Represents `OSBundleLibraries` dependencies as metadata edges.
- Retains duplicate bundle identifiers as separate candidate nodes.
- Can correlate Kernel Collection entry identifiers with bundle identifiers.
- Accepts explicit, researcher-reviewed symbol-provider mappings.
- Labels selected `OSBundleRequired` values as boot-critical candidates.

Limitations:
- Provider presence is not version satisfaction or successful symbol resolution.
- Exact identifier correlation is not proof of loadability.
- Boot-critical labels are review hints, not verified boot dependencies.
- Symbol relationships are included only when explicitly supplied; the tool does not derive actual symbol binding from the binaries.

### 3.4 A9 Platform Profiler

Observed capabilities:
- Tracks boot/restore, kernel/DeviceTree, CPU, GPU, display, touch, audio, camera, wireless, cellular, SEP/Touch ID, power, storage, memory, services, and SpringBoard.
- Separates status from evidence level.
- Refuses to mark a subsystem `working` without a dated device-test record containing device, build, method, and result.

Limitations:
- A populated identity is not independently verified identity.
- The tool validates researcher-supplied JSON; it does not query a device or infer compatibility.
- The profile must remain `not_assessed` or `researching` where there is no Phoenix evidence.

## 4. Cross-tool assessment

| Area | Current evidence | Remaining gap |
|---|---|---|
| Raw IPSW identity | Firmware Inspector can record ProductVersion, build, supported product types, manifest hash, and optional component hashes | Bind each downstream report to one exact IPSW identity |
| Mach-O | Header, architecture, segments, UUID, build-version metadata, conventional symbol table | Deeper kernel-specific metadata, fixups, exports, and signatures |
| Kernel Collection | Outer MH_FILESET and fileset-entry inventory | Recursive embedded-image parsing and stronger fileset semantics |
| Kext metadata | Bundle IDs, versions, dependencies, required metadata | ABI, executable, symbol, entitlement, and version-constraint validation |
| Dependency graph | Explicit metadata edges and optional reviewed symbol map | Actual binary symbol binding and kernel loadability |
| DeviceTree | FDT structure and property inventory/comparison | Apple wrapper decoding and semantic resolution of interrupts, clocks, GPIO, phandles, and driver bindings |
| A9 platform evidence | Structured subsystem profile and strict device-test gate | Independently verified target identity and actual device test records |
| Target/donor comparison | Architecture and bundle-identifier correlation | Exact-build evidence-set integrity and cross-report provenance |

## 5. Required next improvement: exact-build evidence-set validator

Before producing a target/donor kernel comparison, create a manifest for each evidence set.

Each evidence set should identify:
- role: `target` or `donor`;
- device marketing name and ProductType;
- ProductVersion, BuildVersion, build train, and board identity when known;
- BuildManifest SHA-256 and IPSW SHA-256 when available;
- analyzer report paths and SHA-256 hashes;
- source firmware identity recorded by each report;
- extraction tool and version;
- unresolved identity fields, explicitly represented as unknown rather than guessed.

The validator should:
1. Reject a report whose tool identity does not match its declared report type.
2. Reject a report whose content hash differs from the manifest.
3. Reject mixed ProductVersion/BuildVersion/manifest identities within one evidence set when those fields are present.
4. Distinguish missing identity from a proven mismatch.
5. Never infer that target and donor builds should be identical; they are different devices and may have different build trains.
6. Emit a machine-readable report with `valid`, `incomplete`, or `invalid` evidence-set status and precise reasons.
7. Feed only validated evidence sets into the existing compatibility analyzer.
8. Preserve all current limitations: validation of provenance is not proof of ABI or hardware compatibility.

Suggested files:
- `tools/phoenix-evidence-set/`
- `research/kernel/evidence-set.schema.json`
- `docs/testing/KERNEL_EVIDENCE_SET_WORKFLOW.md`

## 6. iOS 27.3+ project-specific implications

The reference PMU and patcher audits are based on an iOS 16.1 proof-of-concept lineage. Their signatures, offsets, PMU assumptions, kext identities, and patch semantics must not be transferred to iOS 27.3+ without exact-build binary evidence.

The A13 donor is a prospective source of iOS userspace and comparison data. It is not a substitute for A9-native boot chain, kernel, DeviceTree, drivers, PMU, GPU, SEP, baseband, or other platform-specific components.

Until an eligible iPhone SE (2020) donor IPSW at iOS 27.3 or later is identified and inventoried, firmware-dependent comparisons remain pending. Donor-independent tool hardening and A9 evidence collection can continue.

## 7. Status and next action

- Static source/documentation review: **Inspected**.
- Exact-build target evidence set: **Not supplied**.
- Exact-build iOS 27.3+ donor evidence set: **Not supplied**.
- Kernel compatibility verdict: **Unknown / not assessed**.
- Physical device validation: **Not performed**.

**Next milestone:** implement and test the exact-build evidence-set manifest validator, then connect its validated outputs to the existing kernel compatibility analyzer. Do not change any subsystem status to `working` without dated target-device test evidence.
