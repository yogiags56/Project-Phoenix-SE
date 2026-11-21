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
- [ ] Investigate A9 kernel support and required low-level interfaces.
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