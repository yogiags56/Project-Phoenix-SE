# iOS 16.1 Reference Implementation Audit

**Project:** Project Phoenix SE  
**Audit target:** `pwnerblu/iphonese-ios16`  
**Reference branch inspected:** `main`  
**Primary files inspected:** `README.md`, `build-ipsw.sh`, directory listings for `patchsrc/` and `obsoletepatch/`  
**Purpose:** Document the reference build architecture and identify what Phoenix must investigate. This is a static source audit, not a successful reproduction or device test.

## 1. Executive summary

The reference project creates a custom iOS 16.1 restore IPSW for the first-generation iPhone SE. It does not simply install an iPhone 8 image on the SE. It constructs a hybrid restore bundle by combining an iOS 16.1 filesystem base with selected iPhone SE-specific files and selected iPad 5 components, then applies patches to the kernel, DriverKit Wi-Fi component, `backboardd`, dyld shared caches, restore ramdisk, SEP firmware, and iBoot images.

The design is valuable as a compatibility-engineering case study. It is not a direct porting recipe for a newer iOS generation. Every donor component and patch depends on specific binary layouts, kernel interfaces, firmware formats, and hardware assumptions.

## 2. Reference repository inventory

### Top-level files and directories

| Path | Observed role |
|---|---|
| `README.md` | Requirements, input IPSWs, usage, and author's reported feature status |
| `build-ipsw.sh` | Main build orchestration script |
| `patchsrc/` | C source for custom binary patching utilities |
| `obsoletepatch/` | Legacy/obsolete patch source; not compiled by the current script |

### `patchsrc/` source inventory

| Source | Builder output name | Observed integration point |
|---|---|---|
| `backboardhax.c` | `backboarddpatcher` | Patches `usr/libexec/backboardd` |
| `bbupdaterpatch.c` | `bbupdaterpatch` | Patches `libTelephonyUtilDynamic.dylib` in restore ramdisk |
| `dscpatch.c` | `dscpatch` | Patches dyld shared-cache files |
| `kextport.c` | `kextport` | Kernel patch pipeline |
| `mthax.c` | `mthax` | Kernel patch pipeline |
| `pmuhax.c` | `pmuhax` | Initial kernel patch pipeline step |
| `wlanhax.c` | `wlanhax` | Patches AppleBCMWLAN DriverKit executable |

`obsoletepatch/sepfix.c` exists but is explicitly skipped by the current build script's C compilation loop. Do not assume it is part of the active build.

## 3. Input firmware matrix

| Input IPSW | Build | Role visible in script |
|---|---|---|
| iPhone SE 4.0-inch, iOS 15.8.8 | `19H422` | Original SE filesystem and SE-specific `n69` files; original SE kernel is also extracted as a kernel input |
| iPhone 8 4.7-inch, iOS 16.1 | `20B82` | Main iOS 16.1 filesystem base and initial restore bundle |
| iPad 5, iOS 16.1 | `20B82` | Kernel source, Cryptex OS/App, graphics-related files, H6 ISP framework, and SEP firmware donor |

The README asks for a modern macOS environment (preferably macOS 14+) and 40–50 GB free space. These are requirements stated by the reference author, not independently benchmarked by Phoenix.

## 4. Build pipeline reconstruction

### Stage A — Tool bootstrap

The script creates `bin/` and prepares:

- `iBootpatch2` from the `ssv-patch` branch of `crystall1nedev/ipad6-ipados18`.
- `img4` from Legacy-iOS-Kit.
- `ldid` from Procursus.
- `Kernel64Patcher` from downr1n.
- `KPlooshFinder` from Legacy-iOS-Kit.
- `kerneldiff2`, compiled from a pinned raw GitHub Gist source revision.
- `apfs-tool`, built from `LukeZGD/libdmg-apfs`.
- `restored_external64_patcher`, built from `iSuns9/restored_external64patcher` with recursive submodules.
- Local C utilities compiled from `patchsrc/*.c`, except `sepfix.c`; `backboardhax` is renamed to `backboarddpatcher`.

Important: several external repositories are cloned without a pinned commit or release tag. A later build may therefore use different tool code. A reproducible Phoenix research record should capture exact commit IDs, release versions, binary hashes, compiler versions, and download URLs.

### Stage B — Filesystem construction

1. Unpacks the SE 15.8.8 IPSW into `tmp1/` and the iPhone 8 16.1 IPSW into `tmp2/`.
2. Downloads `template.dmg`, resizes it, and mounts the SE filesystem, iPhone 8 filesystem, and template filesystem.
3. Copies the iPhone 8 16.1 filesystem into the template filesystem.
4. Searches the SE filesystem for files whose paths match `n69` and copies them into the new filesystem without overwriting existing files (`cp -an`).
5. Copies Wi-Fi firmware from the SE filesystem into the iOS 16 AppleBCMWLAN DriverKit extension firmware directory.

Interpretation: the builder preserves selected SE platform-specific files while using a newer system filesystem. The `n69` filename/path heuristic is not proof that every required SE dependency is included; a separate manifest-level audit is needed.

### Stage C — Wi-Fi and BackBoard patches

- Extracts entitlements from the AppleBCMWLAN DriverKit executable with `ldid`.
- Runs `wlanhax` to produce a patched executable, then re-signs it with the extracted entitlements.
- Runs `backboarddpatcher` on `usr/libexec/backboardd`, extracts its entitlements, re-signs the patched result, and replaces the original file.

These are targeted userspace/driver compatibility patches. The source audit should determine the exact binary patterns and assumptions used by each patcher before adapting anything to another iOS build.

### Stage D — Kernel and Cryptex integration

The script mounts the iPad 5 system image and its Cryptex OS and App images. It then:

1. Extracts the iPad 5 kernelcache into a raw kernel image.
2. Extracts the iPhone 8 kernelcache into a second raw kernel image.
3. Runs a sequence: `pmuhax` → `kextport` (using the iPhone 8 kernel as an input) → `mthax` → `Kernel64Patcher` → `KPlooshFinder`.
4. Uses `kerneldiff2` to calculate patch differences against the original iPad kernel for two resulting variants.
5. Uses `img4` to create two kernelcache outputs, named `kernelcache.release.iphone8b` and `kernelcache.release.iphone8c`.
6. Copies the iPad 5 Cryptex OS and App contents into the new filesystem, and moves the dyld cache directory into the main filesystem cache location.
7. Copies `H6ISPServices.framework` and `AGXMetalA9.bundle` from the iPad 5 filesystem into the iOS 16 filesystem.

Interpretation: the kernel pipeline is a multi-stage binary transformation, not a simple kernel swap. The presence of `AGXMetalA9.bundle` and `H6ISPServices.framework` indicates deliberate reuse of A9-relevant graphics/ISP components from the iPad donor. It does not establish that the entire iPad driver stack is compatible with the iPhone SE.

### Stage E — dyld shared-cache patching

The script invokes `dscpatch` on four cache files:

- `dyld_shared_cache_arm64.05`
- `dyld_shared_cache_arm64.09`
- `dyld_shared_cache_arm64.11`
- `dyld_shared_cache_arm64.13`

It then applies ownership and permission changes to the resulting cache files. The exact transformations must be understood by reading `patchsrc/dscpatch.c`; the build script alone does not explain the internal patch semantics.

### Stage F — Restore ramdisk, baseband helper, SEP, and iBoot

1. Converts the modified template filesystem into the restore filesystem image and runs `asr imagescan`.
2. Copies two SEP firmware files from the iPad 5 IPSW into the SE restore bundle, renaming them to the SE `n69` filenames.
3. Extracts the restore ramdisk.
4. Extracts `libTelephonyUtilDynamic.dylib`, patches it with `bbupdaterpatch`, re-signs it, and inserts it back into the ramdisk.
5. Extracts `restored_external`, runs `restored_external64_patcher`, re-signs the patched result using the original entitlements, and inserts it back into the ramdisk.
6. Repackages the ramdisk with `img4`.
7. Decrypts the existing SE iBoot images using keys embedded in the script, applies `iBootpatch2`, and repackages them.
8. Modifies `BuildManifest.plist` to identify the output as product version `16.1`, build `20B82`, and point both listed kernel-cache paths to `kernelcache.release.iphone8c`.
9. Zips the modified restore bundle into `iPhone_4.0_64bit_16.1_20B82_Restore.ipsw`.

Interpretation: restore compatibility is separately engineered. The ramdisk's baseband helper, restore executable, SEP firmware selection, iBoot, and BuildManifest all participate in getting the custom image through the restore/boot process. These components must not be treated as interchangeable across iOS versions.

## 5. Author-reported results (not independently reproduced)

The reference README reports the following:

**Reported working:** baseband (cellular not fully tested by the author), flashlight, Bluetooth, Wi-Fi, Apple services, SEP, and Touch ID.

**Reported not working:** device audio (Bluetooth audio reportedly works), camera, jailbreaking, and wallpaper. Other untested functions may have issues.

The README calls the project incomplete and a proof of concept, and warns against using it on a primary device. Phoenix records these as author-reported observations only. They are not Phoenix test results.

Touchscreen operation is not explicitly listed as a verified feature in the README. Treat touchscreen status as **unverified in the reference documentation** until supported by direct test evidence.

## 6. Reproducibility and safety findings

These are source-level observations, not claims that the script is malicious or that the reference author encountered these failures.

1. **Destructive cleanup:** `work/`, `tmp1/`, `tmp2/`, and `tmp3/` are recursively deleted near the start of the script. Run only from a clean, dedicated checkout and inspect the working directory first.
2. **Elevated privileges:** the script requests `sudo` and mounts/modifies disk images with elevated privileges.
3. **Fixed mount points:** it uses fixed mount-point names (`rootfs15`, `rootfs16base`, `rootfs16`, `rootfs16ipad`, `cryptexOS`, `cryptexApp`) and does not implement a comprehensive mount cleanup trap.
4. **Unpinned dependencies:** some Git clones track branches without pinning a commit; external tool binaries are downloaded from URLs without a recorded checksum verification step.
5. **No input integrity manifest:** the script checks for expected IPSW filenames but does not itself verify their SHA-256 hashes against a committed manifest.
6. **Embedded firmware keys:** the script contains decryption key material for the referenced iBoot images. Phoenix should not copy secrets or device-specific private material into its repository; any redistribution or reuse must be reviewed for legality and provenance.
7. **No automated validation stage:** the script's final success condition is creation of an IPSW archive. It does not automatically prove successful restore, boot, or hardware functionality.
8. **Hard-coded build assumptions:** file paths, build identifiers, component names, and binary patch patterns are tied to the exact firmware inputs used by this builder.

Phoenix should not execute this script as-is. First reproduce its logic in a disposable, isolated environment only after reviewing the destructive commands, verifying all inputs, and documenting the dependency revisions.

## 7. What this means for a newer iOS target

The reference establishes that a hybrid firmware approach was attempted for one specific iOS 16.1 build on the A9-era iPhone SE. It does not establish that a substantially newer iOS release can run on A9.

Potential major blockers to investigate independently:

- Kernel support and availability of a kernel build compatible with the A9 device tree and platform drivers.
- Boot chain and restore tooling compatibility, including iBoot, SEP, and restore ramdisk expectations.
- Cryptex format, trust/cache handling, and system volume layout changes between target releases.
- dyld shared-cache format, ABI changes, framework dependencies, and userspace service assumptions.
- Graphics and media stacks, including Metal/AGX, ISP, camera, audio, and hardware codecs.
- Memory pressure and runtime resource requirements on a 2 GB device.
- Baseband, Wi-Fi, Bluetooth, Touch ID, power management, and other hardware-specific firmware/driver interfaces.

These are investigation topics, not a declaration that each item is necessarily impossible.

## 8. Phoenix follow-up tasks

- [ ] Read and annotate each active `patchsrc/*.c` file, beginning with `pmuhax.c`, `kextport.c`, `mthax.c`, and the kernel-diff workflow.
- [ ] Trace the exact binary patch patterns and assumptions in `wlanhax.c`, `backboardhax.c`, `bbupdaterpatch.c`, and `dscpatch.c`.
- [ ] Record upstream repository commit IDs and SHA-256 hashes for all build tools.
- [ ] Create an IPSW manifest comparison for all three input firmware bundles.
- [ ] Identify all `n69` files copied and determine whether the heuristic misses required platform assets.
- [ ] Document every donor component by source IPSW, source path, destination path, and reason for reuse.
- [ ] Build a compatibility matrix for the target iPhone SE hardware and the proposed newer iOS build.
- [ ] Write a feasibility report before any custom firmware construction.

## 9. Audit conclusion

The reference project is a sophisticated, highly version-specific firmware reconstruction workflow. Its most reusable value for Project Phoenix SE is the methodology: inspect firmware inventories, understand donor/target differences, patch only identified incompatibilities, preserve restore-chain consistency, and validate each subsystem independently.

**Current Phoenix status:** reference build flow documented at a high level; custom firmware not built; no device restore or boot test performed; newer-iOS feasibility remains undetermined.

## 10. Source references

- Reference repository: https://github.com/pwnerblu/iphonese-ios16
- README: https://github.com/pwnerblu/iphonese-ios16/blob/main/README.md
- Build script: https://github.com/pwnerblu/iphonese-ios16/blob/main/build-ipsw.sh
- Active patch source directory: https://github.com/pwnerblu/iphonese-ios16/tree/main/patchsrc
- Obsolete patch source directory: https://github.com/pwnerblu/iphonese-ios16/tree/main/obsoletepatch

Reference source inventory observed during this audit:

| File | Blob SHA |
|---|---|
| `build-ipsw.sh` | `1ce3c07c24d8bd2bfd05e00084fd3e0ecf460706` |
| `patchsrc/backboardhax.c` | `d3a5ec9666d6dce658cfe3b48c8ad9980bfef73c` |
| `patchsrc/bbupdaterpatch.c` | `1d3b0b3b5c56ddf8ea1116b14903796f9ab9b32e` |
| `patchsrc/dscpatch.c` | `18de4bfdbb41ebc49d8a5ba12ac055afcaa53ef0` |
| `patchsrc/kextport.c` | `cc5bd47fd55748090abe97b9b4ee7d4c7c6138cc` |
| `patchsrc/mthax.c` | `e03b0c04df928f16fd6b5d88f3c2fe8fbc61e83b` |
| `patchsrc/pmuhax.c` | `1117445bcb8665d7a812e1bb2b22c4c213329376` |
| `patchsrc/wlanhax.c` | `061de3abf8ec655edea5b40207a2231eb28b99ba` |
| `obsoletepatch/sepfix.c` | `f3fb049ce14b64a73a429b67287c071cdaa4bfb6` |

---

*Prepared for Project Phoenix SE. This document describes the inspected source state; re-audit upstream files before relying on it for a build.*