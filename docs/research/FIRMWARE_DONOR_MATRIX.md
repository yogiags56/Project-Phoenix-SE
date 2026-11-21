# Firmware Donor Matrix — iOS 16.1 Reference Build

**Project:** Project Phoenix SE  
**Reference builder:** `pwnerblu/iphonese-ios16`, branch `main`  
**Primary source:** `build-ipsw.sh`  
**Supporting source:** reference `README.md`  
**Method:** Static mapping of source IPSW inputs, extracted images, file copies, transformations, and output destinations. No IPSW was built or restored by Phoenix.

## 1. Executive summary

The reference builder is a hybrid restore-image construction pipeline. It uses three IPSWs with different roles:

- **iPhone SE iOS 15.8.8 (19H422):** device-specific source material for the original SE, including selected `n69` files, Wi-Fi firmware, original iBoot images, the original restore bundle/manifest, and a kernel image used as a donor input to the kext-porting stage.
- **iPhone 8 iOS 16.1 (20B82):** primary iOS 16.1 filesystem base.
- **iPad 5 iOS 16.1 (20B82):** kernel and Cryptex donor, source of selected A9-related graphics/ISP components, SEP firmware donor, and restore-ramdisk source.

The script then patches or relocates selected components and writes a custom iPhone SE restore IPSW labelled iOS 16.1 / build 20B82. The resulting file is a hybrid; the product/build labels do not mean every component originated from an iPhone SE iOS 16.1 firmware.

## 2. Input IPSW inventory

| Alias | IPSW filename | Product/build | Role |
|---|---|---|---|
| `SE_IPSW` | `iPhone_4.0_64bit_15.8.8_19H422_Restore.ipsw` | iPhone SE, 15.8.8 / 19H422 | Original target-device donor |
| `IPHONE_IPSW` | `iPhone_4.7_P3_16.1_20B82_Restore.ipsw` | iPhone 8, 16.1 / 20B82 | Main filesystem donor |
| `IPAD_IPSW` | `iPad_64bit_TouchID_ASTC_16.1_20B82_Restore.ipsw` | iPad 5, 16.1 / 20B82 | Kernel, Cryptex, graphics/ISP, SEP, and restore-ramdisk donor |

The reference README links to Apple-hosted IPSW downloads. The filenames and build identifiers above are taken from the reference README and builder; Phoenix has not independently verified downloaded file hashes.

## 3. Donor-to-output matrix

| Component / subsystem | Source IPSW and source path | Output / destination | Operation | Evidence level |
|---|---|---|---|---|
| Main system filesystem | iPhone 8 16.1: `078-65562-105.dmg` | Template filesystem mounted as `rootfs16` | Entire iPhone 8 filesystem copied with `rsync -a` into resized template | Explicit in build script |
| Template filesystem image | External resource `template.dmg` from `pwnerblu/extra-resources-ipad1` release 1.0 | `work/template.dmg`, later converted into SE restore filesystem image | Downloaded, resized to 11500 MB, populated with iPhone 8 system | Explicit in build script |
| SE-specific filesystem files | iPhone SE 15.8.8: `098-68807-067.dmg`, mounted as `rootfs15` | Corresponding paths under `rootfs16` | All regular files whose path matches `n69` are copied with `cp -an`; existing destination files are not overwritten | Explicit in build script; exact copied file list is not embedded |
| Wi-Fi firmware | iPhone SE 15.8.8: `usr/share/firmware/wifi/*` | `System/Library/DriverExtensions/com.apple.DriverKit-AppleBCMWLAN.dext/Firmware` | Copies SE Wi-Fi firmware files into iOS 16 DriverKit extension | Explicit in build script |
| Wi-Fi DriverKit executable | iPhone 8 16.1 base filesystem | `.../com.apple.DriverKit-AppleBCMWLAN.dext/com.apple.DriverKit-AppleBCMWLAN` | Original entitlements extracted; `wlanhax` patch applied; executable re-signed and replaced | Explicit in build script |
| BackBoard daemon | iPhone 8 16.1 base filesystem | `usr/libexec/backboardd` | `backboarddpatcher` modifies executable; original entitlements extracted and re-applied | Explicit in build script |
| Kernel donor image | iPad 5 16.1: `kernelcache.release.ipad6f` | Intermediate raw kernel and final kernelcache files inserted into SE restore bundle | Extracted with `img4`; passed through PMU, kext-port, multitouch, Kernel64Patcher, and KPlooshFinder stages; diffed against original iPad kernel and repackaged | Explicit in build script |
| SE kernel input for kext graft | iPhone SE 15.8.8: `kernelcache.release.iphone8b` | `work/kernel-SE.raw`, input to `kextport` | Extracted with `img4`; used as the source kernel for selected SE kext grafting | Explicit in build script; filename is the script's internal IPSW path |
| Cryptex OS | iPad 5 16.1: `078-64804-105.dmg` | `System/Cryptexes/OS` in target filesystem | Mounted and copied with `rsync -av` | Explicit in build script |
| Cryptex App | iPad 5 16.1: `078-64825-107.dmg` | `System/Cryptexes/App` in target filesystem | Mounted and copied with `rsync -av` | Explicit in build script |
| dyld shared cache | iPad 5 Cryptex OS: `System/Library/Caches/com.apple.dyld` | `System/Library/Caches/com.apple.dyld` in target filesystem | Directory moved out of copied Cryptex OS tree; four ARM64 cache files patched separately | Explicit in build script |
| H6 ISP framework | iPad 5 16.1 mounted filesystem: `System/Library/PrivateFrameworks/H6ISPServices.framework` | Same framework directory in target filesystem | Direct copy | Explicit in build script |
| A9 graphics bundle | iPad 5 16.1 mounted filesystem: `System/Library/Extensions/AGXMetalA9.bundle` | Same extension directory in target filesystem | Direct copy | Explicit in build script |
| SEP firmware for N69 | iPad 5 16.1: `Firmware/all_flash/sep-firmware.j72t.RELEASE.im4p` | SE restore bundle: `Firmware/all_flash/sep-firmware.n69.RELEASE.im4p` | File copied and renamed | Explicit in build script |
| SEP firmware for N69u | iPad 5 16.1: `Firmware/all_flash/sep-firmware.j72s.RELEASE.im4p` | SE restore bundle: `Firmware/all_flash/sep-firmware.n69u.RELEASE.im4p` | File copied and renamed | Explicit in build script |
| Restore ramdisk | iPad 5 16.1: `078-64668-109.dmg` | SE restore bundle: `098-68700-067.dmg` | Extracted with `img4`; internal TelephonyUtil and `restored_external` binaries patched; repackaged as restore ramdisk | Explicit in build script |
| Telephony restore helper | iPad restore ramdisk: `usr/lib/libTelephonyUtilDynamic.dylib` | Same path inside modified restore ramdisk | Extracted, patched by `bbupdaterpatch`, reinserted, and chmod 755 | Explicit in build script |
| Restore executable | iPad restore ramdisk: `usr/local/bin/restored_external` | Same path inside modified restore ramdisk | Extracted, patched by `restored_external64_patcher`, re-signed with original entitlements, and reinserted | Explicit in build script |
| iBoot images | iPhone SE 15.8.8 restore bundle: `iBoot.n69.RELEASE.im4p` and `iBoot.n69u.RELEASE.im4p` | Same SE-specific paths in output restore bundle | Decrypted using keys embedded in reference script, patched with `iBootpatch2`, repackaged | Explicit in build script |
| Build manifest | iPhone SE 15.8.8 restore bundle: `BuildManifest.plist` | Output `BuildManifest.plist` | Product version/build changed to 16.1 / 20B82; both listed kernel-cache paths changed to `kernelcache.release.iphone8c` | Explicit in build script |

## 4. Kernel transformation chain

The builder's kernel flow is especially important because the output filename can obscure the actual source lineage:

1. Extract iPad 5 `kernelcache.release.ipad6f` into `work/kernel.raw`.
2. Extract the SE kernelcache into `work/kernel-SE.raw`.
3. `pmuhax`: transform the iPad kernel into `kernel.patch`.
4. `kextport`: use `kernel.patch` plus `kernel-SE.raw` to produce `kernel.patch2`.
5. `mthax`: produce `kernel.patch3`.
6. `Kernel64Patcher`: produce `kernel.patch4`.
7. `KPlooshFinder`: produce `kernel.patch5`.
8. `kerneldiff2` compares the original iPad kernel with `kernel.patch4` and `kernel.patch5` to produce two patch-diff files.
9. `img4` applies those diffs to the original iPad kernelcache and writes `kernelcache.release.iphone8b` and `kernelcache.release.iphone8c` into the SE restore bundle.
10. The SE BuildManifest is then pointed at `kernelcache.release.iphone8c` for both listed build identities.

**Important:** despite the `iphone8b` / `iphone8c` output filenames, these are generated by applying patch diffs to the iPad 5 kernelcache. The names alone do not identify the true kernel donor.

## 5. Restore-chain donor lineage

The restore side is not sourced from a single device:

- The outer restore bundle, original SE iBoot images, and BuildManifest originate from the SE 15.8.8 IPSW.
- The restore ramdisk image is taken from the iPad 5 16.1 IPSW.
- SEP firmware files are taken from the iPad 5 IPSW and renamed to SE model filenames.
- Telephony restore logic inside the ramdisk is patched to map N69 model identity onto an existing J72s profile.
- The `restored_external` executable is separately patched and re-signed.

This is a reminder that booting the OS and successfully completing a restore are separate compatibility problems.

## 6. Donor rationale versus proven compatibility

| Donor choice | Rationale visible from source | What is not proven by the script |
|---|---|---|
| iPhone 8 16.1 filesystem | Provides the newer iOS 16.1 system base | That every iPhone 8 service, driver, and framework is suitable for SE hardware |
| SE 15.8.8 `n69` files | Preserves selected original SE platform-specific files | That the `n69` filename filter captures every required device-specific dependency |
| SE Wi-Fi firmware | Retains firmware associated with the target SE Wi-Fi hardware | Full compatibility with the iOS 16 DriverKit binary or all radio operations |
| iPad 5 kernel | Supplies an iOS 16.1 kernel used as the base of a multi-step patch workflow | That arbitrary iPad 5 kernel components are compatible with the SE board |
| SE kernel input to `kextport` | Supplies selected SE kernel extensions for grafting | That grafted drivers initialize correctly or are stable on hardware |
| iPad 5 Cryptex | Supplies OS/App Cryptex contents and associated dyld caches | That all Cryptex contents, trust assumptions, and cache dependencies are valid on SE |
| iPad 5 AGXMetalA9 / H6ISPServices | Supplies selected A9-related graphics and ISP components | Complete GPU acceleration, camera capture, or image processing |
| iPad 5 SEP firmware | Supplies firmware renamed for SE model paths | Cryptographic compatibility, Touch ID stability, or safe SEP operation across all states |
| iPad 5 restore ramdisk | Supplies newer restore environment components | Successful restore on every SE variant or recovery scenario |

## 7. Important implementation details and caveats

- `cp -an` copies only files absent at the destination. A file matching `n69` does not automatically replace an iPhone 8 file already present at the same path.
- The script's `find` expression selects regular files with `n69` anywhere in their path. It is a heuristic, not a complete device-tree or firmware dependency resolver.
- The script removes the iPhone 8 filesystem DMG after copying its contents; the output filesystem is based on the template populated from that source.
- The script moves the dyld cache directory from the copied Cryptex OS tree into the main filesystem cache directory before patching selected subcaches.
- The four patched shared caches are `.05`, `.09`, `.11`, and `.13`; the script does not claim that these are the only cache components in the system.
- SEP firmware filenames are renamed from J72 variants to N69 variants. A filename change alone does not prove SEP protocol or hardware compatibility.
- The builder updates `ProductVersion`, `ProductBuildVersion`, and kernel-cache paths in the manifest. This is metadata adaptation, not proof that every bundled component is natively from that product/build.
- The README's reported working/non-working list is author-reported and not independently reproduced by Phoenix. Cellular is explicitly described as not fully tested; device audio and camera are reported not working.

## 8. Phoenix data collection schema

Every future donor component should be recorded with these fields:

| Field | Meaning |
|---|---|
| `component_id` | Stable Phoenix identifier |
| `source_ipsw` | Exact source IPSW filename |
| `source_build` | Product version and build identifier |
| `source_path` | Path inside IPSW or extracted image |
| `destination_path` | Path in target filesystem or restore bundle |
| `operation` | Copy, rename, patch, relocate, re-sign, repack, or metadata edit |
| `hardware_dependency` | Device, board, chip, or subsystem dependency |
| `evidence` | Source line, hash, binary inspection, or test report |
| `confidence` | Explicit, inferred, unknown, or experimentally verified |
| `validation_status` | Not tested, static review, build-tested, restore-tested, boot-tested, hardware-tested |

Phoenix should add hashes and exact IPSW download metadata before any reproducible build attempt. Do not commit copyrighted firmware images, extracted proprietary binaries, private keys, or device-specific secrets to the project repository.

## 9. Phoenix follow-up tasks

- [ ] Obtain and verify the exact three IPSW files; record SHA-256 hashes and Apple download metadata.
- [ ] Generate a complete file-level inventory of each IPSW BuildManifest and restore bundle.
- [ ] Expand the `n69` copy heuristic into an explicit file list with source/destination hashes.
- [ ] Record the exact kext bundle IDs, source kernelcache lineage, and dependency graph for the three grafted SE kexts.
- [ ] Compare the iPad 5 and SE device trees, board configurations, and relevant firmware manifests.
- [ ] Map all Cryptex OS/App files and identify which dyld caches/frameworks are consumed by the target.
- [ ] Investigate SEP compatibility separately from SEP filename/model mapping.
- [ ] Identify all restore ramdisk components that are required for restore versus first boot.
- [ ] Create a subsystem test matrix for Wi-Fi, graphics, camera/ISP, touch, audio, baseband, SEP/Touch ID, sleep/wake, and power.
- [ ] Do not attempt to extrapolate this donor matrix to a newer iOS release until its IPSWs and component manifests are independently audited.

## 10. Audit conclusion

The reference build uses a deliberately mixed donor strategy: SE-specific identity and firmware are preserved selectively, iPhone 8 provides the main iOS 16.1 filesystem, and iPad 5 provides key kernel/Cryptex/graphics/ISP/SEP/restore components. The builder then patches compatibility seams across the system and restore chain.

This is the clearest architectural lesson for Project Phoenix SE: a successful hybrid firmware depends on a component-by-component compatibility map, not on finding one donor IPSW that looks close enough.

**Phoenix status:** donor lineage documented from the reference shell script; no IPSW downloaded, hashed, extracted, built, restored, or tested by Phoenix.

## Source references

- Reference README: https://github.com/pwnerblu/iphonese-ios16/blob/main/README.md
- Reference build script: https://github.com/pwnerblu/iphonese-ios16/blob/main/build-ipsw.sh
- Reference patch source: https://github.com/pwnerblu/iphonese-ios16/tree/main/patchsrc
- Apple iPhone SE 15.8.8 IPSW link is listed in the reference README.
- Apple iPhone 8 16.1 IPSW link is listed in the reference README.
- Apple iPad 5 16.1 IPSW link is listed in the reference README.

---

*Static donor-lineage audit. Re-verify upstream source, IPSW hashes, and exact build metadata before using this as a build manifest.*