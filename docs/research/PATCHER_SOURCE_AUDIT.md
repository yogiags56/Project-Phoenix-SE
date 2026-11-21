# Patch Source Code Audit — iOS 16.1 Reference

**Project:** Project Phoenix SE  
**Reference:** `pwnerblu/iphonese-ios16`, branch `main`  
**Scope:** Static reading of active C patchers under `patchsrc/`.  
**Not performed:** Compilation, patch execution, IPSW build, restore, boot, or hardware validation.

## 1. Executive overview

The active patch source is a collection of purpose-built ARM64/Mach-O and dyld-cache patchers. The tools generally discover target code using instruction signatures, Mach-O metadata, symbol/prelink metadata, Objective-C metadata, or dyld mappings rather than relying solely on fixed file offsets. Many require exactly one match and stop on ambiguous or unsupported input.

This is a strong defensive design pattern, but signature uniqueness does not prove semantic correctness. A matching pattern can still represent a different behavior in another build, and a binary that passes static validation can still fail at runtime. The source comments repeatedly mark hardware validation as pending or identify external firmware dependencies.

## 2. Patcher map

| Patcher | Primary target | Main compatibility operation |
|---|---|---|
| `pmuhax.c` | Embedded `AppleD2365PMU` and `AppleARMPMU` code in prelinked kernel | Adapts PMU assumptions from D2365 toward D2255/SE1, updates IONameMatch and descriptor data, adds sample guard |
| `kextport.c` | Prelinked kernelcache | Grafts three SE1 display/charger kexts into iPad 5 kernelcache and relocates metadata/references |
| `mthax.c` | Prelinked kernel `__PRELINK_INFO` plist | Replaces selected J72 multitouch SPI personality with an SE N69 profile |
| `wlanhax.c` | AppleBCMWLAN DriverKit executable | Applies a narrowly matched Wi-Fi driver compatibility patch; exact behavior requires a separate line-by-line review |
| `backboardhax.c` | `backboardd` | Redirects a UI sensor wrapper from `bs_map:` to `bs_compactMap:` for nil-result handling |
| `bbupdaterpatch.c` | `libTelephonyUtilDynamic.dylib` in restore ramdisk | Maps N69 model identifiers onto an existing J72s product/radio/vendor profile for restore/baseband handling |
| `dscpatch.c` | ARM64 dyld shared-cache/subcache images | Patches NanoRegistry, AVFCapture, Sleep, TelephonyUtil, and BasebandCapabilities code paths |

`obsoletepatch/sepfix.c` is not part of the active compilation loop described in the build script and should not be treated as an active patcher.

## 3. `pmuhax.c` — PMU adaptation

### Observed design

- Accepts a raw ARM64 Mach-O kernel, not a compressed IM4P/kernelcache container.
- Parses the outer kernel's Mach-O segments and resolves embedded kext virtual addresses through the outer file-backed segments.
- Locates exactly one embedded `AppleD2365PMU` image in `__PRELINK_TEXT` and its matching `__PRELINK_INFO` metadata.
- Locates PMU code sites through a large set of masked ARM64 instruction windows. Each rule must match exactly once.
- Resolves an LDO descriptor table through an ADRP/ADD instruction pair and verifies that the code reference points to the table it found.
- Changes the PMU personality's `IONameMatch` from `pmu,d2365` to `pmu,d2255`, and updates descriptor/IRQ-related data.
- Contains an additional `AppleARMPMU` guard path. The source says it handles an empty sample by releasing a temporary array and returning NULL through the native cleanup path.
- Performs discovery and validation before applying the queued modifications, then publishes output through a temporary file and a no-overwrite link operation.

### Compatibility meaning

This is a hardware-generation adaptation, not a generic PMU patch. The source explicitly describes D2365-to-D2255 assumptions and says signatures were derived from the supplied iOS 16.1 iPad 5 kernel. It explicitly does not claim universal iOS 16.x support.

### Risks and open questions

- The precise PMU register, GPIO, event-mask, LDO, and IRQ semantics need independent hardware documentation or controlled tests.
- Instruction signatures are tied to the exact binary generation and may not match another build.
- The added guard has source comments stating hardware testing is pending.
- A successful output file does not prove stable sleep, wake, charging, thermal, or power behavior.

### Phoenix action

Do not port the constants directly to another iOS release. First document every changed instruction/table field, the hardware register it represents, the source/destination PMU identity, and a test that can validate the behavior.

## 4. `kextport.c` — kernel extension grafting and relocation

### Observed design

The file header identifies three source kexts copied from the iPhone SE 1 kernelcache into an iPad 5 destination kernelcache:

- `AppleChestnutDisplayPMU`
- `ApplePinotLCD`
- `AppleSN2400Charger`

The implementation parses Mach-O segments and sections, prelink metadata, kext bundle identifiers, dependencies, KASLR tracking data, and sequential prelink headers. It searches for available zero-filled space in the destination rather than assuming one fixed placement.

It then relocates code and data references, including ADRP/ADD-style PC-relative sequences and other PC-relative instructions. It updates kmod information, KASLR offset tables, and the destination `__PRELINK_INFO` entries. It checks the sequential header chain after insertion and keeps the receiver kernel file length unchanged.

The source includes cross-build private-import resolution using unique masked instruction windows, cross-references, metaclass records, and base-vtable checks. Unsupported or ambiguous inputs are intended to fail rather than produce a kernel.

### Compatibility meaning

This is more than copying driver binaries. A kext is integrated into the receiver's kernel address space and metadata ecosystem. The tool must make its code, data, vtables, kmod descriptors, dependencies, KASLR records, and prelink header representation coherent with the destination.

### Risks and open questions

- Relocation logic is highly sensitive to instruction encodings and kernel layout.
- Private C++/IOKit imports and vtable relationships can differ across builds even when bundle IDs remain the same.
- Free space in one kernelcache does not imply equivalent safe space in another.
- Static structural validation cannot prove that the grafted driver initializes against the destination kernel and hardware.

### Phoenix action

Build a relocation inventory for each grafted kext: source/destination segment map, section sizes, imports, vtables, dependencies, KASLR entries, and every rewritten reference. Treat the tool as specific to the reference donor/receiver pair until independently validated.

## 5. `mthax.c` — multitouch SPI personality adaptation

### Observed design

- Parses a thin ARM64 Mach-O kernel and locates the `__PRELINK_INFO` segment.
- Parses the prelink XML/plist structure, including IDs and references, and validates the XML tree before editing.
- Finds the prelinked multitouch driver entry identified by `com.apple.driver.AppleMultitouchSPIC1F15` or `com.apple.driver.AppleMultitouchSPIN69`.
- Requires a single supported personality with the expected `AppleMultitouchN1SPI` class and `AppleARMSPIDevice` provider.
- Replaces the selected personality data with an embedded SE N69 SPI profile while preserving the existing prelink XML capacity and overall kernel file size.
- Refuses unexpected additional personalities, shared personality containers, duplicate IDs, malformed XML, or insufficient prelink padding.

The source reports the profile fields as `C1F57,5`, size-id `2`, FLL `0x17d3`, analog delay `500us`, and reference divisor `2`.

### Compatibility meaning

This patch changes device configuration metadata for the SPI multitouch path. It is not, by itself, proof that touch input works: the appropriate controller driver, firmware/properties, GPIO/interrupt configuration, and physical device behavior must all line up.

The source explicitly states that external `mtprops`/firmware are still required.

### Phoenix action

Record the complete before/after personality dictionary, identify the external multitouch property and firmware inputs, and test touch initialization, coordinate mapping, multitouch, sleep/wake, and repeated input under load.

## 6. `dscpatch.c` — dyld shared-cache compatibility patches

### Target images detected

The patcher scans ARM64 dyld shared-cache mappings and looks for these image paths:

- `/System/Library/PrivateFrameworks/NanoRegistry.framework/NanoRegistry`
- `/System/Library/PrivateFrameworks/AVFCapture.framework/AVFCapture`
- `/System/Library/PrivateFrameworks/Sleep.framework/Sleep`
- `/usr/lib/libTelephonyUtilDynamic.dylib`
- `/usr/lib/libBasebandCapabilities.dylib`

### Observed operations

- NanoRegistry: changes a matched watch-companion capability check to false.
- AVFCapture: adds an N69/N69u camera capability profile and redirects a capability/release path through a generated helper. The embedded profile labels the camera family as `N69-N69u` and contains a release string `iOS 9.3`.
- Sleep: redirects a matched TH1 entry point to a fallback path.
- TelephonyUtil: adapts N69AP/N69uAP model handling to an existing J72s profile with product value 57 and radio/vendor values 1.
- BasebandCapabilities: adapts the N69/N69u USB location result to `0x03100000`, while preserving the other-model path at `0x04100000`. The hardware-model getter is resolved from sibling subcache `.05` while patching `.13`.

The patcher queues edits, checks that code edits fall within the supported signed-code range, rejects overlapping edits, and validates the input's ad-hoc SHA-256 CodeDirectory page hashes. It refreshes those page hashes after editing.

### Important signing limitation

The source explicitly says this updates code-page hashes, not an Apple CMS signature or a trust cache. It refuses unsupported CMS-signed cache layouts rather than forging an Apple signature. Therefore, refreshing the CodeDirectory hashes is not equivalent to making modified system code trusted by iOS.

### Compatibility meaning

This patcher adapts selected userspace assumptions about product identity, camera capabilities, watch-companion support, sleep behavior, and telephony/RFS location. It does not provide a complete camera, cellular, or sleep driver stack.

### Risks and open questions

- The camera profile and AVFCapture control flow require actual sensor/ISP/firmware validation; changing capability metadata alone cannot make incompatible camera hardware work.
- A patch to a framework's capability path is not proof that all camera capture modes or image pipelines work.
- Telephony model mapping does not prove carrier registration, calls, data, SMS, emergency calling, or baseband stability.
- Ad-hoc hash refresh does not solve Apple code-signing/trust requirements.
- RFS location constants are hardware/restore-specific and must not be reused without evidence.

### Phoenix action

Separate each target image into its own subsystem investigation. For each edit, record original instruction bytes, decoded instruction, control-flow target, replacement behavior, signature uniqueness, code-signing impact, and device test evidence.

## 7. `backboardhax.c` — UI sensor wrapper

The patcher parses a thin ARM64 Mach-O `backboardd`, including Objective-C class/method metadata and chained pointer fixups. It locates class `BKHIDUISensorServiceMatchingWrapper`, method `matcher:servicesDidMatch:`, and selector stubs for `bs_map:` and `bs_compactMap:`. It then redirects one uniquely identified direct call from `bs_map:` to `bs_compactMap:`.

The intended effect is to compact nil UI-sensor wrapper results before dispatch. The source changes one BL instruction, preserves image size, and requires the output to be signed through the existing device signing flow.

This is a narrow userspace compatibility workaround. It does not establish general touchscreen support or prove all BackBoard input services function.

## 8. `bbupdaterpatch.c` — restore/baseband model mapping

The patcher requires the exact thin plain ARM64 dylib identity `/usr/lib/libTelephonyUtilDynamic.dylib` (not `libBBUpdaterDynamic.dylib`) and rejects arm64e/encrypted or unsupported Mach-O layouts.

It identifies the N69AP/N69uAP unknown-model fallback and an existing J72s profile, validates relevant branch topology and shared global references, finds executable header padding, and installs a small branch stub. The stub maps the N69 model keys to the J72s product/radio/vendor profile while leaving the original fallback path for other cases.

The source warns that the code signature becomes stale and that signing/trust is a separate deployment step. This patch changes model/profile selection; it does not itself implement baseband firmware compatibility or prove cellular service.

## 9. `wlanhax.c` — Wi-Fi DriverKit patch

The build script applies this patch to the AppleBCMWLAN DriverKit executable, extracts/reapplies entitlements, and replaces the executable in the filesystem. The source file is an active component, but this audit has not yet completed a line-by-line semantic annotation of its target function and instruction changes.

**Status:** target and integration point confirmed; semantic review remains open. Do not infer the exact Wi-Fi workaround from the filename alone.

## 10. Cross-cutting engineering patterns

Patterns worth adopting in Phoenix:

1. Parse binary formats structurally before editing them.
2. Resolve virtual addresses through segment mappings instead of assuming file offsets.
3. Use masked instruction signatures only when their semantic context is understood.
4. Require unique matches and fail closed on ambiguity.
5. Validate branch reach, alignment, segment bounds, and destination space before writing.
6. Queue edits and complete validation before mutation.
7. Preserve file size/layout when the surrounding format depends on it.
8. Refuse to overwrite existing output paths and use temporary-file publication where implemented.
9. Distinguish binary patch success from code-signing trust, successful restore, successful boot, and hardware function.
10. Record exact firmware build IDs and tool revisions; signatures are not universal across OS releases.

## 11. Gaps and follow-up work

- [ ] Complete line-by-line semantic review of `wlanhax.c`.
- [ ] Produce a patch-site table for all `pmuhax.c` rules: signature, original instruction, replacement, intended hardware semantic, and confidence.
- [ ] Produce the source/destination segment and relocation map for `kextport.c`.
- [ ] Diff the complete N69 SPI personality embedded in `mthax.c` against the donor J72 personality.
- [ ] Decode every `dscpatch.c` target signature and replacement control-flow path.
- [ ] Record all signing, entitlement, and trust-cache assumptions in the build pipeline.
- [ ] Compare every patch target against the exact proposed newer iOS build before considering adaptation.
- [ ] Add isolated synthetic test fixtures for Mach-O parsing, signature matching, bounds checks, branch encoders, and no-overwrite output behavior.

## 12. Audit conclusion

The reference's most valuable contribution is not a ready-made set of bytes to reuse. It is a collection of narrowly scoped compatibility experiments, each built around one hardware or userspace mismatch. Several tools are deliberately defensive, but the source itself repeatedly leaves hardware validation pending and documents dependencies outside the patcher.

**Phoenix status:** source-level patcher map and architectural review completed for six patchers; Wi-Fi patcher semantic review still open. No source has been compiled or executed by Phoenix, and no device-level behavior has been verified.

## Source files

- `pmuhax.c`: https://github.com/pwnerblu/iphonese-ios16/blob/main/patchsrc/pmuhax.c
- `kextport.c`: https://github.com/pwnerblu/iphonese-ios16/blob/main/patchsrc/kextport.c
- `mthax.c`: https://github.com/pwnerblu/iphonese-ios16/blob/main/patchsrc/mthax.c
- `dscpatch.c`: https://github.com/pwnerblu/iphonese-ios16/blob/main/patchsrc/dscpatch.c
- `wlanhax.c`: https://github.com/pwnerblu/iphonese-ios16/blob/main/patchsrc/wlanhax.c
- `backboardhax.c`: https://github.com/pwnerblu/iphonese-ios16/blob/main/patchsrc/backboardhax.c
- `bbupdaterpatch.c`: https://github.com/pwnerblu/iphonese-ios16/blob/main/patchsrc/bbupdaterpatch.c
- Reference build script: https://github.com/pwnerblu/iphonese-ios16/blob/main/build-ipsw.sh

---

*Static source review only. Re-check upstream source and build identifiers before using this analysis in implementation work.*