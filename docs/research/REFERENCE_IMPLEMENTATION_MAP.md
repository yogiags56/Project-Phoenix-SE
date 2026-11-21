# Phoenix Reference Implementation Map

**Reference:** https://github.com/pwnerblu/iphonese-ios16  
**Branch inspected:** main  
**Upstream tree commit observed:** e99a6c920ae1e9ea6fde501614f66c4cb49c7b35  
**Build script blob:** 1ce3c07c24d8bd2bfd05e00084fd3e0ecf460706  
**Audit type:** Static source reconstruction only. Phoenix has not built the IPSW, restored a device, or reproduced the reported results.

## 1. Executive map

The reference is a hybrid firmware builder with three input IPSWs and several independent compatibility layers:

- **iPhone SE 15.8.8 (19H422):** preserves the N69 device identity, selected N69 files, Wi-Fi firmware, original SE kernel as a patching reference, and original SE iBoot images.
- **iPhone 8 16.1 (20B82):** supplies the principal iOS 16.1 filesystem used as the starting userspace.
- **iPad 5 16.1 (20B82):** supplies the kernelcache that is transformed by the kernel patch pipeline, Cryptex OS/App, selected graphics/ISP components, SEP firmware, and restore ramdisk.

The output is not a simple iPhone 8 IPSW with a different model string. It is a custom bundle assembled from selected files and transformed components from all three inputs.

## 2. Donor-to-output map

| Output area | Source IPSW | Source component/path observed in script | Transformation / destination | Evidence class |
|---|---|---|---|---|
| Main system filesystem | iPhone 8 16.1 | 078-65562-105.dmg | Copied into template filesystem mounted as rootfs16 | Direct script observation |
| Filesystem container / restore slot | iPhone SE 15.8.8 | 098-68807-067.dmg | Replaced with converted custom filesystem image | Direct script observation |
| N69-specific files | iPhone SE 15.8.8 | Files whose paths match n69 under mounted root filesystem | Copied with cp -an into new system filesystem | Direct script observation; heuristic may omit files |
| Wi-Fi firmware | iPhone SE 15.8.8 | usr/share/firmware/wifi/* | Copied into AppleBCMWLAN DriverKit extension firmware directory | Direct script observation |
| Wi-Fi DriverKit executable | iPhone 8 16.1 filesystem | System/Library/DriverExtensions/com.apple.DriverKit-AppleBCMWLAN.dext/com.apple.DriverKit-AppleBCMWLAN | Patched by wlanhax; original entitlements extracted and applied with ldid | Direct script observation |
| BackBoard service | iPhone 8 16.1 filesystem | usr/libexec/backboardd | Patched by backboarddpatcher; entitlements preserved using ldid | Direct script observation |
| Original SE kernel reference | iPhone SE 15.8.8 | kernelcache.release.iphone8b in the SE IPSW staging directory | Decrypted to work/kernel-SE.raw; supplied as input to kextport | Direct script observation |
| Kernel base | iPad 5 16.1 | kernelcache.release.ipad6f | Decrypted, passed through kernel patch stages, and used as base for generated kernelcache variants | Direct script observation |
| Cryptex OS | iPad 5 16.1 | 078-64804-105.dmg | Contents copied into System/Cryptexes/OS; dyld cache directory moved into main cache location | Direct script observation |
| Cryptex App | iPad 5 16.1 | 078-64825-107.dmg | Contents copied into System/Cryptexes/App | Direct script observation |
| ISP framework | iPad 5 16.1 | System/Library/PrivateFrameworks/H6ISPServices.framework | Copied into new system filesystem | Direct script observation; does not prove camera works |
| A9 graphics bundle | iPad 5 16.1 | System/Library/Extensions/AGXMetalA9.bundle | Copied into new system filesystem | Direct script observation; does not prove complete GPU stack compatibility |
| dyld shared caches | iPad 5 16.1 Cryptex OS | dyld_shared_cache_arm64.05, .09, .11, .13 | Each cache is processed by dscpatch | Direct script observation |
| SEP firmware | iPad 5 16.1 | sep-firmware.j72t.RELEASE.im4p, sep-firmware.j72s.RELEASE.im4p | Copied into SE restore bundle and renamed to N69/N69u paths | Direct script observation; compatibility is author-reported, not Phoenix-tested |
| Restore ramdisk | iPad 5 16.1 | 078-64668-109.dmg | Unpacked, modified, and repacked as the SE restore ramdisk | Direct script observation |
| Baseband restore helper | iPad 5 restore ramdisk | usr/lib/libTelephonyUtilDynamic.dylib | Patched by bbupdaterpatch, signed, and inserted back | Direct script observation |
| Restore executable | iPad 5 restore ramdisk | usr/local/bin/restored_external | Patched by restored_external64_patcher, entitlements preserved, and inserted back | Direct script observation |
| iBoot | iPhone SE 15.8.8 | iBoot.n69.RELEASE.im4p, iBoot.n69u.RELEASE.im4p | Decrypted with script-provided keys, patched by iBootpatch2, repacked | Direct script observation |
| Build manifest | iPhone SE 15.8.8 restore bundle | BuildManifest.plist | Product version/build set to 16.1/20B82; kernelcache paths changed to kernelcache.release.iphone8c | Direct script observation |

**Important kernel detail:** the script extracts the iPad 5 kernelcache as work/kernel.raw and the SE kernelcache as work/kernel-SE.raw. The iPad kernel is the kernel-patching base; the SE kernel is an input to kextport. The script then creates two patch-difference outputs against the original iPad kernel and emits kernelcache.release.iphone8b and kernelcache.release.iphone8c. The manifest is configured to use the iphone8c variant. This is a specific source-level reconstruction, not a statement that the iPhone 8 kernel itself is used as the final kernel.

## 3. Kernel transformation sequence

| Order | Tool | Input | Output / role | What is established |
|---:|---|---|---|---|
| 1 | img4 | iPad 5 kernelcache.release.ipad6f | work/kernel.raw | Kernel image extraction is invoked |
| 2 | img4 | SE kernelcache.release.iphone8b | work/kernel-SE.raw | SE kernel image extraction is invoked |
| 3 | pmuhax | kernel.raw | kernel.patch | PMU adaptation patch stage |
| 4 | kextport | kernel.patch, kernel-SE.raw | kernel.patch2 | SE-specific kext grafting stage |
| 5 | mthax | kernel.patch2 | kernel.patch3 | Multitouch personality adaptation stage |
| 6 | Kernel64Patcher | kernel.patch3 | kernel.patch4 | Generic kernel patcher stage |
| 7 | KPlooshFinder | kernel.patch4 | kernel.patch5 | Additional kernel patch/finder stage |
| 8 | kerneldiff2 | Original iPad kernel and patch4/patch5 | kernel.diff, kernel.diff2 | Computes patch-difference artifacts |
| 9 | img4 | Original iPad kernel plus each diff | Two N69 restore kernelcache variants | Repackages generated kernel outputs |

The names and order are visible in the build script. The exact semantic effect of each transformation must be read from its source and validated against the exact input binaries. A successful patcher exit is not proof of a bootable or stable kernel.

## 4. Active patcher source inventory

| Source file | Built executable | Target | Audit reference |
|---|---|---|---|
| patchsrc/pmuhax.c | pmuhax | Embedded PMU kext code and metadata in kernel | PATCHER_SOURCE_AUDIT.md |
| patchsrc/kextport.c | kextport | Prelinked kernel and selected SE kext metadata/code | PATCHER_SOURCE_AUDIT.md |
| patchsrc/mthax.c | mthax | Prelinked kernel multitouch personality metadata | PATCHER_SOURCE_AUDIT.md |
| patchsrc/wlanhax.c | wlanhax | AppleBCMWLAN DriverKit executable | PATCHER_SOURCE_AUDIT.md |
| patchsrc/backboardhax.c | backboarddpatcher | backboardd | PATCHER_SOURCE_AUDIT.md |
| patchsrc/bbupdaterpatch.c | bbupdaterpatch | libTelephonyUtilDynamic.dylib | PATCHER_SOURCE_AUDIT.md |
| patchsrc/dscpatch.c | dscpatch | dyld shared-cache/subcache binaries | PATCHER_SOURCE_AUDIT.md |
| obsoletepatch/sepfix.c | Not built by current script | Legacy SEP patch source | Excluded from active pipeline |

The current build script's compilation loop skips sepfix.c. Do not describe it as an active patch stage.

## 5. External build dependencies and reproducibility

The script bootstraps tools from several external sources, including iBootpatch2, img4, ldid, Kernel64Patcher, KPlooshFinder, kerneldiff2, apfs-tool, and restored_external64_patcher.

Reproducibility concerns visible in the script:

- Some Git repositories are cloned without a fixed commit ID.
- Some binaries are downloaded directly without a recorded checksum verification step.
- IPSW filenames are checked, but the script does not compare each input against a committed SHA-256 manifest.
- Compiler and SDK versions are not recorded in the generated IPSW.
- The script deletes work/ and tmp1/–tmp3/ at startup, requests sudo, and uses fixed mount-point names.

Phoenix must not execute the upstream script as-is. A later reproduction effort needs a disposable workspace, verified input hashes, pinned tool revisions, mount cleanup, and a full recovery plan.

## 6. Reported functionality versus source evidence

The reference README author-reports baseband, flashlight, Bluetooth, Wi-Fi, Apple services, SEP, and Touch ID as working to varying degrees. Cellular is explicitly not fully tested. Device audio and camera are reported not working; Bluetooth audio is reported working. Other features may be untested.

The build script demonstrates that patches and donor files are applied; it does not independently prove their runtime effect. The reference README does not explicitly certify touchscreen operation. These claims are not Phoenix device-test results.

## 7. Newer-iOS transferability

This map describes the exact iOS 16.1 proof-of-concept lineage. It does not imply that its donor choices, kernel patches, SEP firmware, Cryptex layout, dyld-cache patchers, or restore components can be reused on a later iOS release.

Before a newer target is selected, Phoenix must independently establish:

1. Target IPSW build and component inventory.
2. Kernel/Device Tree support for N69 and the A9 platform.
3. Driver and firmware availability for each physical subsystem.
4. SEP, iBoot, restore ramdisk, and baseband compatibility.
5. Cryptex, APFS, dyld shared-cache, and userspace ABI compatibility.
6. Memory and runtime feasibility on the device.
7. A recoverable test strategy using a dedicated research device.

## 8. Source provenance

- Upstream repository: https://github.com/pwnerblu/iphonese-ios16
- Upstream README: https://github.com/pwnerblu/iphonese-ios16/blob/main/README.md
- Upstream builder: https://github.com/pwnerblu/iphonese-ios16/blob/main/build-ipsw.sh
- Existing Phoenix audit: IOS16_REFERENCE_AUDIT.md
- Existing donor matrix: FIRMWARE_DONOR_MATRIX.md
- Existing patcher audit: PATCHER_SOURCE_AUDIT.md

**Conclusion:** the reference implementation is now mapped at the donor, filesystem, kernel, Cryptex, SEP, restore, iBoot, and patcher orchestration levels. This remains a static audit. No Phoenix IPSW has been generated, restored, booted, or hardware-validated.
