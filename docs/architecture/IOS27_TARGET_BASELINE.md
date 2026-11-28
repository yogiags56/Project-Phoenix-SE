# iOS 27.3+ Target and Donor Baseline

**Project:** Project Phoenix SE  
**Target device:** iPhone SE (1st generation, 2016) — A9 / iPhone8,4 / n69  
**Donor device:** iPhone SE (2nd generation, 2020) — A13 Bionic  
**Target OS policy:** iOS 27.3 or later  
**Document status:** Planning baseline; no iOS 27.3 donor firmware has been verified or extracted by this document.

## 1. Purpose

This document records the current project direction so that future firmware research, compatibility reports, and experiments use one consistent target definition. It does not claim that iOS 27.3 or a later release is available for the donor, nor that a port to the A9 device is technically feasible.

## 2. Device roles

| Role | Device | Platform | Responsibility |
|---|---|---|---|
| Target | iPhone SE (2016) | A9, iPhone8,4 / n69 | Physical hardware, boot environment, device-specific drivers and peripherals |
| Donor | iPhone SE (2020) | A13 Bionic | Prospective source of target-version iOS userspace and firmware evidence |

The donor is a source of research material, not a drop-in replacement platform. A13 kernel, device tree, boot chain, SEP, baseband, GPU firmware, and hardware-specific drivers must not be assumed to operate on A9.

## 3. OS version policy

1. The minimum intended OS target is iOS 27.3.
2. A later iOS 27.x release may supersede 27.3 when its exact donor firmware is available and its component set is better suited to the research.
3. The selected target must be pinned to an exact ProductVersion, BuildVersion, build train, ProductType, and manifest before binary analysis begins.
4. Do not mix components from different builds without recording and justifying each cross-build dependency.
5. If no eligible donor IPSW is available, continue donor-independent analysis and mark firmware-dependent work as blocked or pending.

## 4. Component provenance policy

Every candidate component must record:
- source device and ProductType;
- source IPSW ProductVersion and BuildVersion;
- manifest identity and component path;
- extraction tool and version;
- SHA-256 of the original and extracted payloads;
- architecture, Mach-O UUID, and relevant platform metadata when applicable;
- compatibility classification and evidence references.

Recommended classifications:
- target-native: retained from the iPhone SE (2016) platform;
- donor-candidate: extracted from the iPhone SE (2020), not yet assessed;
- adaptation-required: requires ABI, interface, metadata, or implementation work;
- incompatible: demonstrated mismatch with a documented reason;
- unknown: insufficient evidence.

## 5. A9/A13 compatibility boundary

The following are platform-sensitive and must be independently investigated rather than copied from the donor by default:
- BootROM-dependent boot flow, LLB, iBoot, and restore chain;
- kernel and kernel configuration;
- DeviceTree and platform properties;
- PMU, power management, interrupt routing, and thermal control;
- GPU/Metal stack and firmware;
- display, touch, audio, camera/ISP, Wi-Fi, Bluetooth, and cellular;
- SEP, Touch ID, and baseband firmware;
- memory limits, page-size assumptions, and userspace ABI dependencies.

A shared ARM64 label does not establish binary, kernel, driver, or firmware compatibility. All conclusions must be tied to exact builds and evidence.

## 6. Research sequence

### Baseline and donor identification
- [ ] Confirm the exact target device model and board identity from device evidence.
- [ ] Identify an eligible iPhone SE (2020) IPSW at iOS 27.3 or later.
- [ ] Record ProductType, ProductVersion, BuildVersion, build train, and manifest hash.
- [ ] Preserve the original IPSW and record its SHA-256.

### Read-only inventory
- [ ] Parse BuildManifest and inventory component identities.
- [ ] Extract only components supported by the available tooling.
- [ ] Record hashes and provenance for every extracted payload.
- [ ] Separate encrypted, compressed, and opaque payloads; do not label them decoded unless decoding has been performed.

### Compatibility analysis
- [ ] Compare target-native A9 evidence with donor component metadata.
- [ ] Audit kernel, DeviceTree, Kernel Collection, kexts, and userspace dependencies.
- [ ] Assess SEP, baseband, Cryptex, APFS, dyld shared cache, and restore requirements.
- [ ] Publish blockers and a go/no-go assessment before any custom restore experiment.

## 7. Evidence and status rules

Use these status labels consistently:
- Planned: defined work not yet started;
- In progress: work actively being performed;
- Inspected: static analysis completed for identified inputs;
- Tested: reproducible test executed with recorded method and output;
- Device-validated: tested on the stated physical target device;
- Blocked: cannot proceed because a named prerequisite is missing.

A successful parser run, CI job, or static report is not evidence of a bootable IPSW or functioning hardware. No subsystem may be marked Working without device/build/test evidence.

## 8. Current status

- Project direction: recorded in this document.
- iOS 27.3+ donor IPSW: not verified in this document.
- Donor extraction: not performed in this document.
- A9 kernel compatibility: unresolved research question.
- Custom IPSW, restore, boot, and hardware validation: not claimed.

## 9. Guiding principle

**Keep the A9 device identity and hardware requirements authoritative. Treat A13 firmware as evidence and candidate source material—not as a compatible platform until proven component by component.**
