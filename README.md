# Project Phoenix SE

**Reviving the first-generation iPhone SE through low-level iOS compatibility research.**

> Project Phoenix SE is an experimental research project. Its long-term ambition is to investigate whether newer iOS software can be brought to the original iPhone SE (2016), beyond the device's official software support. No newer iOS release is currently claimed to be working on this device.

## Vision

The original iPhone SE remains a compact and capable piece of Apple hardware. Project Phoenix SE explores the technical boundaries of extending its software life through platform research, compatibility analysis, reverse engineering, and carefully controlled experiments.

The name **Phoenix** represents a second life: bringing an older device back into the conversation through engineering rather than treating an ambitious port as a guaranteed outcome.

## Target device

| Item | Target |
|---|---|
| Device | iPhone SE (1st generation, 2016) |
| Board / platform identifier | iPhone8,4 / n69 |
| SoC | Apple A9 |
| CPU architecture | ARM64 |
| Display | 4-inch, 1136 × 640 |
| Memory | 2 GB RAM |
| Project type | Experimental compatibility and porting research |

Hardware details and identifiers must be verified against trusted device documentation and firmware before implementation decisions are made.

## Research reference

A key starting point is [pwnerblu/iphonese-ios16](https://github.com/pwnerblu/iphonese-ios16), an experimental project that builds a custom iOS 16.1 restore image for the first-generation iPhone SE using components from compatible donor firmware.

That work is a reference for understanding firmware composition and compatibility patching. It is **not** a drop-in foundation for a newer iOS release: each target version must be independently investigated.

## Latest research notes

- [PMU reference audit](research/PMU-REFERENCE-AUDIT.md) — static audit of the iOS 16.1 D2365-to-D2255 PMU patcher. Documents 70 rule entries, LDO control-flow redirects, personality changes, the sample guard, assumptions, and evidence still required. This is not hardware validation.

## Latest PMU artifacts

- [PMU signature catalog](research/PMU-SIGNATURE-CATALOG.json) — exact source-derived signature words/masks, 70 rule records, four branch redirect relationships, and byte-level LDO table differences. It is an inventory, not a hardware compatibility result.
- [PMU catalog extractor](tools/phoenix-pmu-catalog/) — reproducible Python extractor and unit tests.

## Latest PMU analysis artifacts

- [Phoenix PMU LDO Control-Flow Delta Auditor](tools/phoenix-pmu-cf-delta/) — compares original branch/register effects with the four dynamically generated LDO redirects and the static rule-57 NOP, without requiring donor firmware.

- [Phoenix PMU LDO Symbolic Path Model](tools/phoenix-pmu-paths/) — models the four source-declared dynamic redirects and the documented TBZ fall-through without claiming a complete CFG.

- [Phoenix PMU LDO Register Data-Flow Analyzer](tools/phoenix-pmu-dataflow/) — performs conservative, donorless register def-use and instruction-semantic analysis across LDO signature windows 54–69.

- [Phoenix PMU LDO Overlap Reconstruction](tools/phoenix-pmu-ldo/) — reconstructs exact suffix/prefix overlaps among LDO signature windows (rules 54–69) without a donor binary.

- [Phoenix PMU Patch Delta Auditor](tools/phoenix-pmu-delta/) — compares source-derived original instruction templates with declared replacements and dynamic branch redirects; does not require a donor binary.

- [Phoenix PMU Virtual Address Mapper](tools/phoenix-pmu-vmmap/) — maps signature file offsets through embedded Mach-O segment file ranges, reporting VM addresses only for unique executable-segment mappings.

- [Phoenix PMU Signature Discovery](tools/phoenix-pmu-discovery/) — read-only masked signature search across Kernel Collection fileset entries, preserving file offsets and reporting heuristic identity hints separately.

- [Phoenix Payload Inspector](tools/phoenix-payload/) — signature-based format triage, byte-exact IM4P payload extraction, and structural Mach-O/MH_FILESET inspection through the existing analyzers; explicitly does not decrypt, decompress, or establish compatibility.

- [Phoenix IPSW Evidence Inspector](tools/phoenix-evidence/) — local, read-only BuildManifest identity and kernelcache ZIP-member hashing/extraction. It does not decrypt or decompress kernelcache payloads.

- [PMU donor extraction checklist](research/PMU-DONOR-EXTRACTION-CHECKLIST.md) — exact iPad 5 iOS 16.1 donor artifact chain, local-only evidence handling, kernelcache identification, and acceptance criteria for a real PMU disassembly.

- [PMU LDO register trace](research/PMU-LDO-REGISTER-TRACE.md) — source-derived analysis of the index boundary, X8 mask construction, LSRV/TBZ path, W21/W26 relationship, and evidence gaps before claiming a full runtime def-use graph.

- [Phoenix ARM64 register def-use analyzer](tools/phoenix-register-flow/) — conservative sequential read/write tracking, Wn/Xn alias normalization, NZCV access markers, memory base-register reads, and unknown-instruction barriers. It is not yet CFG-aware and must be fed actual disassembly text.

- **Decoder correctness update:** fixed AArch64 unsigned-immediate load/store width decoding (LDRB/LDRH/LDR W/LDR X and STRB/STRH/STR W/STR X). Added width and scaled-offset regression tests. This corrects earlier semantic report entries that labelled some 64-bit LDR encodings as LDRB; regenerate the checked-in JSON report with the updated decoder before relying on its aggregate counts.

- [PMU signature catalog](research/PMU-SIGNATURE-CATALOG.json) — source-derived signature and mutation metadata.
- [PMU ARM64 semantic decode report](research/PMU-ARM64-SEMANTIC-DECODE.json) — decoded instruction subset, replacement words, and explicit unknown/masked-template markers.
- [PMU patch instruction delta](research/PMU-PATCH-INSTRUCTION-DELTA.md) — original/replacement instruction-class comparison for all 66 mutating rules and limits of the current decoder.
- [PMU LDO control-flow reconstruction](research/PMU-LDO-CONTROL-FLOW.md) — runtime branch redirects, target anchors, rule 60 LSRV, and remaining CFG limitations.
- [PMU semantic decoder](tools/phoenix-pmu-semantic/) — reproducible decoder and unit tests.

## Research objectives

1. Understand the original iPhone SE boot chain, firmware layout, kernel, device tree, and restore process.
2. Audit the existing iOS 16.1 proof of concept and document its patches, donor components, and known limitations.
3. Map hardware dependencies: display and touch, GPU, audio, camera, Wi-Fi, Bluetooth, cellular/baseband, Touch ID, and power management.
4. Study kernel and userspace compatibility barriers between the A9 platform and the intended newer iOS target.
5. Build a reproducible compatibility matrix and test plan before attempting any custom firmware.
6. Keep all experiments reversible where possible and separate research devices from primary-use devices.

## Roadmap

### Phase 0 — Project foundation
- [x] Create the Project Phoenix SE repository.
- [x] Establish the project scope and research-first approach.
- [ ] Record exact device model, board identifier, firmware versions, and boot state.
- [x] Add an evidence-validated A9 platform profile template and report generator.
- [ ] Add a research log and source register.

### Phase 1 — Reference implementation audit
- [x] Review the iOS 16.1 build scripts and patching tools (static source audit).
- [x] Identify donor IPSW components and their observed roles in the build script.
- [x] Document kernel, SEP, Cryptex, dyld shared cache, restore ramdisk, iBoot, and firmware changes.
- [x] Separate author-reported working, non-working, and untested features from Phoenix test results.

### Phase 2 — Hardware and software compatibility study
- [x] Add read-only firmware metadata analyzers (IMG4, FDT, Mach-O, MH_FILESET, and kext dependency inventory).
- [x] Add conservative JSON evidence comparison for target and donor reports.
- [x] Create a component-by-component hardware compatibility matrix.
- [x] Add a structured A9 subsystem evidence profile and readiness report tool.
- [x] Add a read-only Device Tree report comparator for node, property, compatible-string and phandle differences.
- [x] Add a kernel evidence correlator for Mach-O architecture, Kernel Collection architecture and kext inventory reports.
- [x] Add a read-only symbol-table comparison tool for matching Mach-O architectures.
- [x] Add an evidence-labelled kernel dependency graph with optional Kernel Collection correlation and explicit symbol-provider mappings.
- [x] Add a read-only HTML/JSON evidence dashboard for aggregating analyzer reports.
- [x] Add a lexical patch-pattern inventory for C patcher sources, with source hashes and mutation-site references.
- [x] Add a textual ARM64 disassembly analyzer with branch/ADRP heuristics and address-aligned before/after diff.
- [x] Audit the reference iOS 16.1 PMU patcher and document source-derived rule groups, assumptions, and validation gaps.
- [x] Extract all 70 PMU signatures, masks, mutation metadata, branch redirect relationships, and LDO descriptor byte differences into a provenance-pinned catalog.
- [x] Add a conservative ARM64 semantic decoder for selected instruction classes; preserve unknown instructions and flag masked signature templates.
- [ ] Investigate A9 kernel support and required low-level interfaces.
- [ ] Validate ARM64 patch semantics against original binaries, relocations, and hardware-specific context.
- [x] Add a static inventory tool for patcher signature arrays and mutation call sites.
- [ ] Investigate graphics, display, touch, audio, camera, and wireless drivers.
- [ ] Investigate SEP, baseband, boot chain, and restore compatibility.
- [ ] Assess userspace requirements, including frameworks, launch services, and system services.

### Phase 3 — Feasibility assessment
- [ ] Select and document the exact target iOS build.
- [ ] Compare target firmware components with the iPhone SE platform.
- [ ] Identify hard blockers, possible workarounds, and unknowns.
- [ ] Publish a go / no-go assessment before attempting a port.

### Phase 4 — Controlled bring-up experiments
- [ ] Define a safe test environment and recovery procedure.
- [ ] Prototype one subsystem at a time.
- [ ] Record logs, failures, patches, and reproducible test results.
- [ ] Do not describe a feature as working until it has been tested on the target device.

## Compatibility status

No Project Phoenix SE port is currently declared functional. The table below is a tracking template, not a claim of support.

| Subsystem | Status | Evidence / notes |
|---|---|---|
| Boot chain and restore | Not assessed | |
| Kernel | Not assessed | |
| Display and touchscreen | Not assessed | |
| GPU / Metal | Not assessed | |
| Audio | Not assessed | |
| Camera / ISP | Not assessed | |
| Wi-Fi | Not assessed | |
| Bluetooth | Not assessed | |
| Cellular / baseband | Not assessed | |
| SEP / Touch ID | Not assessed | |
| Power management | Not assessed | |
| Core iOS services | Not assessed | |
| SpringBoard | Not assessed | |

Status labels: **Not assessed**, **Researching**, **Experimental**, **Partially working**, **Working**, and **Blocked**. Every status update should include a device, build, test method, and evidence.

## Safety and limitations

- This project is research, not a consumer installation guide.
- Custom firmware and restore experiments can erase data, disable functionality, or render a device unusable.
- Never experiment on a primary-use device or without a tested recovery path.
- Preserve original firmware, device-specific data, and logs where legally and technically appropriate.
- Respect Apple's software terms and applicable laws. Do not publish private keys, personal identifiers, or device-specific secrets.
- Do not assume that a donor IPSW, kernel, SEP, or driver from another device is interchangeable.

## Repository structure

The repository will grow as the research becomes reproducible:

    Project-Phoenix-SE/
    ├── README.md
    ├── docs/
    │   ├── architecture/
    │   ├── compatibility/
    │   ├── research/
    │   │   └── REFERENCE_IMPLEMENTATION_MAP.md
    │   └── testing/
    ├── research/
    │   ├── firmware/
    │   ├── kernel/
    │   └── userspace/
    ├── profiles/
    │   └── iphone-se-1st-gen.template.json
    ├── tools/
    │   ├── phoenix-inspector/
    │   ├── phoenix-img4/
    │   ├── phoenix-fdt/
    │   ├── phoenix-macho/
    │   ├── phoenix-kc/
    │   ├── phoenix-kext/
    │   ├── phoenix-compat/
    │   ├── phoenix-a9-profile/
    │   ├── phoenix-dt-diff/
    │   ├── phoenix-kernel-compat/
    │   ├── phoenix-symbol-diff/
    │   ├── phoenix-kernel-graph/
    │   └── phoenix-dashboard/
    └── logs/

Only add scripts and binaries when their purpose, provenance, and usage can be documented.

## Guiding principle

**Research first. Verify every assumption. Change one subsystem at a time.**

A second life for the iPhone SE begins with understanding the device—not with flashing an unverified IPSW.