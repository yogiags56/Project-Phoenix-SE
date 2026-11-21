# Device Tree & Kernel Dependency Audit — N69 / J72 A9 Platforms

**Project:** Project Phoenix SE  
**Target family:** iPhone SE (1st generation), `iPhone8,4`  
**Reference donor family:** iPad 5, `iPad6,11` / `iPad6,12`  
**Scope:** Publicly documented A9 platform identifiers, reference-builder evidence, and a safe methodology for auditing proprietary iOS DeviceTree and kernel dependencies.  
**Status:** Static research only. No device tree, kernelcache, firmware, or hardware has been modified or tested by Phoenix.

## 1. Executive summary

The most important finding is that the A9 family contains two SoC variants that must not be collapsed into one generic 'A9' target:

| Platform family | SoC | DeviceTree-compatible name | Example platform IDs |
|---|---|---|---|
| Samsung A9 | `s8000` | `apple,n69u` for iPhone SE; `apple,j71s` / `apple,j72s` for iPad 5 | `N69uAP`, `J71sAP`, `J72sAP` |
| TSMC A9 | `s8003` | `apple,n69` for iPhone SE; `apple,j71t` / `apple,j72t` for iPad 5 | `N69AP`, `J71tAP`, `J72tAP` |

The public Linux Apple DeviceTree binding explicitly separates the Samsung and TSMC A9 platforms. The Linux device-tree series also identifies the TSMC iPhone SE N69 as `iPhone8,4` and lists retail models A1662/A1723/A1724 for that specific N69 platform. This is useful corroboration, but Linux DeviceTree source is not Apple's proprietary iOS DeviceTree and does not fully describe every iOS driver property.

**Critical rule:** Phoenix must identify the exact target SoC/board variant from trustworthy device and firmware evidence before selecting an IPSW, kernel, SEP, or donor component. Product identifier `iPhone8,4` alone does not distinguish `N69AP` from `N69uAP`.

## 2. Identifier map

| Device | Product identifier | Platform / board family | SoC | Notes |
|---|---|---|---|---|
| iPhone SE 1st gen, TSMC | `iPhone8,4` | `N69AP` / `apple,n69` | `s8003` | TSMC A9 variant |
| iPhone SE 1st gen, Samsung | `iPhone8,4` | `N69uAP` / `apple,n69u` | `s8000` | Samsung A9 variant |
| iPad 5 Wi-Fi, TSMC | `iPad6,11` | `J71tAP` / `apple,j71t` | `s8003` | Wi-Fi model |
| iPad 5 Cellular, TSMC | `iPad6,12` | `J72tAP` / `apple,j72t` | `s8003` | Cellular model |
| iPad 5 Wi-Fi, Samsung | Platform family `J71s` | `J71sAP` / `apple,j71s` | `s8000` | Samsung A9 variant |
| iPad 5 Cellular, Samsung | Platform family `J72s` | `J72sAP` / `apple,j72s` | `s8000` | Samsung A9 variant |

**Caution:** These names are platform/board identifiers, not interchangeable filenames. Confirm the exact spelling and case in the actual IPSW BuildManifest, device tree, kernelcache, and restore bundle. Do not infer an exact retail-model-to-chip pairing from a filename copied from another device.

## 3. Why matching SoC family is not enough

Even when two products use the same A9 generation, they may differ in:

- CPU silicon variant and SoC stepping (`s8000` versus `s8003`).
- Board-level power rails, PMU configuration, GPIO assignments, interrupt routing, and clocks.
- Display controller connections, LCD panel timing, backlight, and touch controller wiring.
- Camera sensors, ISP connections, microphone routes, audio codec and amplifier.
- Wi-Fi/Bluetooth module revisions, RF front-end, antenna configuration, and regulatory data.
- Cellular modem integration, SIM path, RF calibration, and regional band configuration.
- Battery gauge, charger, thermal sensors, storage and peripheral buses.

A shared CPU family may permit reuse of selected low-level code, but it does not establish that a complete kernel, DeviceTree, firmware set, or SEP image is compatible.

## 4. Public DeviceTree evidence versus Apple's iOS DeviceTree

The public Linux Apple DeviceTree bindings are useful for identifying platform families and shared hardware blocks. They are not a complete substitute for Apple's device tree:

- Linux DTS/DTSI files are reverse-engineered descriptions for the Linux kernel's driver model.
- Apple's iOS DeviceTree is a separate firmware artifact with Apple-specific nodes, properties, phandles, service matching, and driver expectations.
- A Linux node or compatible string does not prove that an iOS kext consumes the same property or that the underlying hardware is initialized identically.
- Absence of a peripheral from a public Linux DTS does not prove the peripheral is absent from the device.

Phoenix should use public DTS as a cross-check and vocabulary aid, while treating the exact iOS DeviceTree extracted from the matching IPSW as the authoritative artifact for iOS-side analysis.

## 5. Reference donor audit: an important variant question

The reference builder uses an iPad 5 iOS 16.1 IPSW and extracts the iPad kernel, Cryptex, SEP firmware and restore ramdisk. Its script names the SEP donor files with both `j72t` and `j72s` variants and maps the SE restore bundle to `n69` and `n69u` filenames.

This demonstrates that the builder is aware of both board families at the restore-bundle level. It does **not** by itself prove which donor SEP image is selected for a particular physical SE, nor that renaming a donor image makes it compatible.

The reference `bbupdaterpatch` model mapping and the two SEP donor variants must be analyzed as separate questions:

1. Which physical SE SoC/board variant is the target?
2. Which iPad 5 SEP variant is selected by the actual restore identity?
3. What SEP firmware compatibility and pairing requirements apply?
4. Does the restore process select the intended variant for the exact device?

Phoenix must not resolve these questions from output filenames alone. Inspect BuildManifest identities, restore rules, board configuration, SEP payload metadata and actual restore logs.

## 6. Kernel dependency audit model

Build a dependency graph rather than a flat list of kext filenames. For every kernel component, record:

| Field | Required information |
|---|---|
| Component identity | Bundle identifier, executable name, class/provider identity |
| Source provenance | IPSW, build, kernelcache, extracted path, SHA-256 |
| Platform matching | `IONameMatch`, `IOPropertyMatch`, personality dictionaries, board filters |
| Hardware resources | MMIO regions, IRQs, GPIOs, clocks, power domains, DMA, buses |
| Kernel ABI | Kernel symbols, private imports, C++ classes, vtables, structure assumptions |
| Dependencies | Parent provider, dependent kexts, firmware, userspace service |
| Relocation | Segment/section mapping, PC-relative references, KASLR/prelink metadata |
| Security | Entitlements, code-signing state, trust-cache/AMFI implications |
| Evidence | Exact source location, binary offset/VA, decoded instruction or property, confidence |
| Validation | Static-only, synthetic test, build, restore, boot, subsystem, stability |

Suggested dependency relationships:

- DeviceTree node → matching driver personality → provider/service → dependent driver.
- Kernel extension → imported kernel symbols / C++ classes → provider extension.
- Driver → firmware file(s) → hardware revision / chip identifier.
- Driver → userspace service or DriverKit extension → entitlement and IPC requirements.
- Restore component → board identity / BuildManifest identity → boot or restore stage.

Do not graft a kext solely because its bundle identifier contains `N69` or because the file exists in an older IPSW. Confirm all providers, imports, hardware resources, firmware and ABI assumptions.

## 7. Reference patcher implications

The existing reference audits identify these particularly relevant components:

| Reference component | What source shows | What remains unproven |
|---|---|---|
| `AppleChestnutDisplayPMU` | SE display/PMU kext is grafted into iPad kernel | Complete panel and power sequencing compatibility |
| `ApplePinotLCD` | SE LCD driver is grafted | Correct panel timing, brightness, sleep/wake and stable framebuffer |
| `AppleSN2400Charger` | SE charger driver is grafted | Battery/charger hardware match and safe charging behavior |
| `AppleD2365PMU` / `AppleARMPMU` paths | PMU patch adapts selected PMU assumptions and adds a guard path | Correct register/IRQ/rail behavior on every SE variant |
| Multitouch SPI personality | `mthax` replaces selected personality metadata with N69 values | Correct controller firmware, GPIO, interrupts, coordinates and touch stability |
| Wi-Fi DriverKit | SE firmware is copied and selected iOS 16 driver paths are patched | Exact chip revision, regulatory behavior and stable radio operation |

These are targeted compatibility experiments, not a complete N69 DeviceTree or driver port.

## 8. Required evidence collection

Before implementation, create a reproducible inventory for each candidate firmware:

1. Record IPSW filename, product version, build number, source URL and SHA-256.
2. Parse `BuildManifest.plist` and enumerate all board identities and restore behaviors.
3. Extract device-tree images for every relevant board identity without modifying them.
4. Record device-tree image type, compression/container, hash, root compatible strings, node paths and property types.
5. Extract kernelcache metadata and map prelinked kext bundle identifiers to their personalities and dependencies.
6. Record firmware manifests and exact chip/model associations for Wi-Fi, Bluetooth, baseband, camera, audio, SEP and other peripherals.
7. Compare N69 and N69u first; then compare the corresponding J71/J72 donor variants.
8. Keep all proprietary extracted binaries local; publish only metadata, hashes, original-source references, and independently authored analysis.

### Suggested inventory outputs

- `inventory/ipsw/<build>/build-manifest-summary.json`
- `inventory/devicetree/<build>/<board>/metadata.json`
- `inventory/devicetree/<build>/<board>/node-index.csv`
- `inventory/kernel/<build>/<board>/kext-index.csv`
- `inventory/kernel/<build>/<board>/dependency-graph.json`
- `inventory/firmware/<build>/<board>/firmware-map.csv`
- `reports/diffs/n69-vs-n69u.md`
- `reports/diffs/n69-vs-j72t.md`
- `reports/diffs/n69u-vs-j72s.md`

These are proposed outputs; none have been generated yet.

## 9. Device Tree comparison priorities

Prioritize these node families when comparing the SE and iPad 5:

1. CPU/SoC and interrupt controller nodes.
2. PMU, power domains, regulators, clocks and thermal sensors.
3. Display controller, panel, backlight and framebuffer.
4. SPI/I2C controllers and touch controller nodes.
5. Camera sensor, ISP, flash and imaging pipeline.
6. Audio codec, amplifier, microphones and audio routing.
7. Wi-Fi/Bluetooth controller, transport and firmware references.
8. Baseband, SIM, modem and RF-related nodes.
9. NAND/storage, APFS/flash controller and DMA.
10. NFC, sensors, buttons, proximity and ambient-light components.

For each node, compare compatible strings, `reg` ranges, interrupts, GPIOs, clocks, regulators, power domains, phandles, status, and vendor-specific properties. Record missing properties as unknown until their meaning is understood; do not invent replacement values.

## 10. Stop/go gates for kernel work

| Gate | Pass condition | If not passed |
|---|---|---|
| G0 — Hardware identity | Exact SE board/SoC variant identified | Stop donor selection |
| G1 — Firmware provenance | IPSW build and hashes verified | Stop binary comparison |
| G2 — DeviceTree understanding | Relevant N69 nodes and dependencies mapped | Do not patch board properties |
| G3 — Kernel ABI | Required imports/classes/structures resolved | Do not graft kexts |
| G4 — Firmware pairing | Firmware matches hardware revision and driver interface | Do not load driver |
| G5 — Boot-chain/restore | Restore and recovery path understood | Do not flash target device |
| G6 — Controlled validation | Repeatable boot and subsystem tests with logs | No compatibility claim |

## 11. Immediate next actions

- [ ] Record the actual experimental iPhone SE's model number and board/SoC variant from reliable device diagnostics.
- [ ] Obtain exact SE 15.8.8, iPhone 8 16.1 and iPad 5 16.1 IPSWs used by the reference builder; record hashes.
- [ ] Extract and inventory both `N69AP` and `N69uAP` device-tree artifacts from the correct SE firmware where available.
- [ ] Extract and inventory the relevant `J71/J72` iPad 5 device-tree artifacts for both S8000 and S8003 variants where available.
- [ ] Generate a property-level N69/N69u comparison.
- [ ] Generate a board-level N69/J72 comparison, keeping SoC variants matched.
- [ ] Map the three grafted SE kexts and their complete provider/import/firmware dependencies.
- [ ] Reconcile the `j72t`/`j72s` SEP donor selection with the target restore identity.
- [ ] Document the exact kernel build and every patcher's input/output lineage.

## 12. Audit conclusion

The A9 generation is not one uniform platform. iPhone SE and iPad 5 exist across Samsung S8000 and TSMC S8003 variants, and public DeviceTree bindings explicitly distinguish N69/N69u and J71/J72 board identities. This makes exact board identification a prerequisite for every donor and kernel decision.

The reference iOS 16.1 builder is a useful case study, but its patched kernel, kext grafts, firmware copies, and SEP renaming must not be generalized to an unverified board variant or a newer iOS build.

**Phoenix status:** platform-identifier research and dependency-audit methodology documented. No proprietary iOS DeviceTree has been extracted or compared by Phoenix; no kext dependency graph has been generated; no build, restore, boot, or hardware test has been performed.

## Sources

- Linux Apple DeviceTree binding (S8000/S8003, N69/N69u, J71/J72): https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/devicetree/bindings/arm/apple.yaml
- Linux A7–A11 Apple DeviceTree series, including TSMC iPhone SE N69 and iPad 5 J72t: https://lore.kernel.org/lkml/20240919161443.10340-6-towinchenmi@gmail.com/
- `iometa` device/version overview: https://github.com/Siguza/iometa/blob/master/sym/README.md
- `ipsw` device list: https://blacktop.github.io/ipsw/docs/guides/device_list/
- Reference iOS 16.1 builder: https://github.com/pwnerblu/iphonese-ios16/blob/main/build-ipsw.sh
- Reference patch source: https://github.com/pwnerblu/iphonese-ios16/tree/main/patchsrc

---

*Static research only. Public Linux DeviceTree descriptions are not Apple's iOS DeviceTree. Reconfirm all board identities and binary metadata against the exact firmware and physical device before implementation.*