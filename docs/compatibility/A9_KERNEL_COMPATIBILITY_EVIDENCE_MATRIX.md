# A9 Kernel Compatibility Evidence Matrix

**Project:** Project Phoenix SE  
**Target:** iPhone SE (2016), A9 / iPhone8,4 / n69  
**Prospective donor:** iPhone SE (2020), A13 Bionic  
**Target OS policy:** iOS 27.3 or later  
**Status:** Research matrix; no firmware-derived or device-measured result is asserted here.

## 1. Purpose and interpretation

This matrix defines the evidence needed to assess whether a newer kernel or kernel-adjacent component can execute on the A9 target. It is deliberately not a list of assumed A9 capabilities.

A shared `arm64` label is insufficient. Compatibility depends on the exact kernel build, CPU instruction requirements, exception-level and boot environment, memory-management configuration, platform interfaces, DeviceTree, interrupt/timer topology, and the drivers needed to bring up the board.

Use only these states:
- **Unknown:** no adequate evidence.
- **Source-observed:** explicit fact in identified source code or metadata.
- **Static-analysis:** confirmed from exact-build binary analysis.
- **Device-tested:** reproduced on the named physical iPhone SE 2016.
- **Blocked:** the required exact-build or device evidence is unavailable.

Do not use a positive state to imply successful boot or runtime stability.

## 2. CPU and execution environment

| Evidence item | Required observation | Current state | Required source |
|---|---|---|---|
| CPU implementer / part / revision | Raw MIDR_EL1 values for each core type, where accessible | Unknown | Target device diagnostic or trusted low-level dump |
| CPU architecture profile | Exact architectural feature profile, not merely ARM64 | Unknown | Target CPU register evidence and exact kernel requirements |
| Instruction extensions | Required versus implemented instructions (for example crypto, atomics, SIMD) | Unknown | Kernel disassembly / feature checks and target CPU feature registers |
| Heterogeneous CPU topology | Core types, affinity, scheduler assumptions | Unknown | Device evidence and target kernel configuration |
| Exception levels | Required EL transitions and execution state | Unknown | Boot-chain and kernel entry analysis |
| Cache topology | Cache levels, line sizes, coherency assumptions | Unknown | Target device evidence and kernel platform code |
| Memory ordering | Required barrier and atomic semantics | Unknown | Exact kernel disassembly and architectural feature evidence |
| Page granule | Kernel page-size assumptions and supported translation granules | Unknown | Kernel build configuration and MMU setup |
| VA/PA layout | Address size, virtual layout, physical memory map | Unknown | Exact target kernel and DeviceTree / boot arguments |
| PMU counters | Required events, counter count, access policy | Unknown | Target PMU registers and exact kernel PMU driver |
| Generic timer | Counter frequency, interrupt routing and access | Unknown | Target timer registers, interrupt map and kernel driver |

A missing CPU feature is a hard blocker only when the exact candidate kernel or required code path demonstrably depends on it and no supported alternative exists. Do not infer requirements from the donor's marketing generation.

## 3. Kernel build and ABI boundary

| Evidence item | Required observation | Current state | Acceptance condition |
|---|---|---|---|
| Kernel image identity | Product/build, UUID, architecture, file hash | Unknown | Exact source IPSW and payload provenance |
| Kernel configuration | Required options, page size, debug/release assumptions | Unknown | Extracted config or defensible binary evidence |
| Kernel ABI | Structures, calling conventions, syscall / trap expectations | Unknown | Exact-build static analysis and interface mapping |
| Kext ABI | Kernel extension API, symbols, dependencies, version constraints | Unknown | Exact kernel and kext metadata plus symbol/relocation analysis |
| Kernel symbols | Required exports and actual providers | Unknown | Symbol table and relocation / binding evidence |
| Linker and fixups | Chained fixups, relocations, pointer authentication assumptions | Unknown | Exact binary parser output and disassembly |
| Code-signing policy | Kernel collection signatures, trust and entitlement requirements | Unknown | Exact-build signature and boot-policy evidence |
| Memory footprint | Kernel, KC, wired memory, driver and boot peak | Unknown | Measured target RAM budget and exact image sizes |

Architecture tuple overlap in the current compatibility analyzer is only a coarse filter. It does not establish any row above.

## 4. Platform interface boundary

| Interface | Required target evidence | Current state |
|---|---|---|
| DeviceTree | Board identity, nodes, compatible strings, clocks, GPIO, interrupts, phandles | Unknown |
| Interrupt controller | Controller type, topology, routing, affinity and priorities | Unknown |
| PMU / power rails | Register map, rail descriptors, sequencing, regulator constraints | Unknown |
| Thermal | Sensors, trip points, throttling and shutdown policy | Unknown |
| Storage / APFS | Controller, DMA, IOMMU and filesystem feature requirements | Unknown |
| Display / touch | Panel, timing, controller, touch transport and firmware | Unknown |
| GPU / Metal | GPU family, firmware, driver ABI, userspace framework dependencies | Unknown |
| Audio | Codec, DSP, routing, clocks and firmware | Unknown |
| Camera / ISP | Sensor, ISP, calibration and firmware chain | Unknown |
| Wi-Fi / Bluetooth | Chipset, transport, firmware, regulatory and driver dependencies | Unknown |
| Cellular / baseband | Modem, baseband firmware, transport and restore dependencies | Unknown |
| SEP / Touch ID | SEP generation, protocol, secure boot and pairing constraints | Unknown |

A donor driver is not a candidate for direct use merely because a similarly named bundle identifier exists. Its hardware bindings, firmware, symbols, ABI and power sequencing must match the target platform.

## 5. Evidence collection order

1. Record the target device identity from trusted diagnostics. Keep serial numbers, ECIDs and other private identifiers out of public commits.
2. Acquire and identify an exact target IPSW; record ProductType, ProductVersion, BuildVersion, manifest hash and IPSW hash.
3. Extract only payloads the existing Phoenix tools can process without pretending encrypted or compressed data has been decoded.
4. Run the Mach-O, Kernel Collection, kext, DeviceTree and symbol analyzers against the same exact target build.
5. Record target CPU and platform evidence separately from firmware-derived evidence.
6. Identify an eligible iPhone SE 2020 iOS 27.3+ donor IPSW before creating a donor comparison set.
7. Validate both report sets with Phoenix Evidence Set Validator.
8. Run Kernel Compatibility Analyzer with `--evidence-set-validation`; review the six matched input hashes.
9. Resolve every potential interface or ABI dependency with exact binary evidence.
10. Only then design a controlled, recoverable device experiment.

## 6. Gate criteria

### Gate A — Evidence integrity
- Exact target and donor firmware identities are recorded independently.
- All six kernel reports have hashes and explicit tool provenance.
- Evidence Set Validator reports both sets as `valid`.
- Kernel Compatibility Analyzer is run with the evidence-set gate.

### Gate B — Static compatibility
- No demonstrated unsupported CPU instruction or execution-state requirement.
- Kernel configuration and memory-management assumptions are understood.
- Required symbols, kext dependencies and ABI interfaces have been mapped.
- DeviceTree and platform-driver requirements have target-side providers.
- Boot, PMU, interrupt, storage and thermal dependencies have a documented plan.

### Gate C — Device validation
- Recovery path and test device are confirmed.
- Tests are isolated and reversible where possible.
- Logs, exact build, test method and result are preserved.
- A subsystem is marked `working` only after repeatable target-device evidence.

Passing Gate A does not imply Gate B. Passing Gate B does not imply Gate C.

## 7. Current assessment

| Area | Assessment |
|---|---|
| Target A9 identity | Project target is defined; exact device-level identity fields remain to be recorded |
| Target kernel build | Not supplied in this research step |
| A9 CPU feature evidence | Not supplied |
| iOS 27.3+ donor firmware | Not verified / not extracted |
| Cross-device kernel compatibility | Unknown; not assessed |
| Hardware bring-up | Not performed |

**Conclusion:** no kernel compatibility verdict can responsibly be made yet. The next useful inputs are exact target firmware metadata and device-derived A9 CPU/platform evidence. Donor-dependent work remains pending until an eligible donor IPSW is verified.

## 8. Safety

This document defines a research gate only. It does not authorize kernel patching, custom restore, boot-chain replacement, SEP changes, baseband changes, or PMU register writes. Do not experiment on a primary-use device or without a tested recovery procedure.
