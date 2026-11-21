# A9 Hardware Compatibility Matrix — iPhone SE (1st Generation)

**Project:** Project Phoenix SE  
**Target:** iPhone SE (1st generation), firmware identifier `iPhone8,4`, board family `N69`  
**Reference implementation:** `pwnerblu/iphonese-ios16`  
**Purpose:** Separate confirmed device characteristics, reference-project observations, and unresolved compatibility questions before attempting a newer iOS port.

## 1. Executive summary

The first-generation iPhone SE is an A9-based ARM64 device in the compact 4-inch iPhone 5s-style enclosure. Apple's published specifications confirm the A9/M9 platform, 4-inch 1136×640 IPS Multi-Touch display, 12 MP rear camera, 1.2 MP front camera, Touch ID, Wi-Fi 802.11ac, Bluetooth 4.2, NFC, and model-dependent cellular bands.

The reference iOS 16.1 project is valuable evidence that selected subsystems can be made to operate in a highly customized hybrid build. Its README reports Wi-Fi, Bluetooth, SEP, Touch ID, flashlight, Apple services, and baseband as working to varying degrees; cellular is explicitly not fully tested. It reports device audio and camera as not working. These are author-reported results, not independent Phoenix validation.

**No conclusion is made here that a newer iOS release can boot on A9.** The matrix is a research plan and evidence register, not a compatibility certification.

## 2. Hardware identity and specification baseline

| Property | Baseline | Evidence / caveat |
|---|---|---|
| Product | iPhone SE (1st generation) | Apple technical specifications |
| Firmware identifier | `iPhone8,4` | Community firmware documentation; confirm from the exact device/restore manifest |
| Board family | `N69`; variants commonly identified as `N69AP` and `N69uAP` | Reference patchers and firmware documentation; verify exact device variant |
| SoC | Apple A9, 64-bit | Apple technical specifications |
| Motion coprocessor | M9 integrated with A9 | Apple technical specifications |
| RAM | 2 GB | Commonly documented teardown/specification value; not listed in Apple's public technical specification page |
| Display | 4-inch IPS LCD, 1136×640, 326 ppi, Multi-Touch | Apple technical specifications |
| Rear camera | 12 MP, ƒ/2.2; 4K video at 30 fps | Apple technical specifications |
| Front camera | 1.2 MP, ƒ/2.4; 720p video | Apple technical specifications |
| Touch ID | Fingerprint sensor integrated into Home button | Apple technical specifications |
| Wi-Fi | 802.11ac | Apple technical specifications; exact radio/chip revision should be read from device inventory |
| Bluetooth | Bluetooth 4.2 | Apple technical specifications |
| NFC | Supported | Apple technical specifications |
| Cellular | LTE and legacy cellular bands vary by hardware model/region | Apple model-specific technical specifications; exact model number matters |
| Sensors | 3-axis gyro, accelerometer, proximity, ambient-light, Touch ID | Apple technical specifications |

Apple's public specifications do not name the GPU microarchitecture, RAM capacity, exact Wi-Fi chipset revision, PMU register map, or every board-level peripheral. Phoenix must obtain those details from trusted hardware inventories, firmware manifests, device trees, and controlled device inspection rather than treating third-party summaries as definitive.

## 3. Compatibility matrix

Status definitions:

- **Reference-reported:** the reference project's README claims the subsystem works or does not work.
- **Source-observed:** source code or build script shows a compatibility patch or donor component, but not necessarily successful hardware operation.
- **Unknown:** no adequate evidence yet.
- **High risk:** likely to require substantial platform-specific work; this is a planning classification, not proof of impossibility.

| Subsystem | Hardware / platform dependency | Reference evidence | Phoenix status | Risk / next investigation |
|---|---|---|---|---|
| Boot chain / iBoot | A9 boot ROM, N69 iBoot images, IMG4/restore chain, SEP pairing | Reference builder preserves SE iBoot images and patches them; custom IPSW is intended for tether restore | Source-observed; no Phoenix restore test | **High.** Map boot stages, image types, trust chain, restore/recovery behavior, and exact target build requirements |
| Kernel / Device Tree | A9 CPU, N69 board configuration, interrupt controllers, memory map, drivers | iPad 5 iOS 16.1 kernel is transformed; SE kexts are grafted through `kextport` | Source-observed; no Phoenix boot test | **Critical.** Compare kernel ABI, device tree, prelinked kexts, private imports, KASLR, and required N69 drivers |
| CPU / ARM64 ABI | A9 instruction set and supported exception levels/features | A9-based reference device runs a hybrid iOS 16.1 proof of concept according to author | Partially evidenced by reference project | **High for newer OS.** Verify compiler/runtime assumptions, kernel feature use, atomics, and userspace ABI |
| GPU / display acceleration | A9 GPU, display controller, framebuffer, Metal/AGX driver stack | Reference copies `AGXMetalA9.bundle` from iPad 5; no explicit graphics success claim in README | Source-observed only | **High.** Identify exact GPU family/revision, AGX userspace/kernel pairing, Metal feature set, display bring-up and acceleration logs |
| Display panel / framebuffer | 4-inch 1136×640 LCD, panel timing, backlight, display PMU | Reference grafts `AppleChestnutDisplayPMU` and `ApplePinotLCD` from SE kernel into iPad kernel | Source-observed | **Medium–high.** Validate panel identity, initialization sequence, brightness, sleep/wake, rotation and framebuffer format |
| Touchscreen / multitouch | N69 SPI touch controller, controller firmware/properties, GPIO/interrupt path, BackBoard | `mthax` replaces a multitouch SPI personality with N69 profile; `backboardhax` patches a UI sensor wrapper. README does not explicitly certify touchscreen | Source-observed; operation unverified by README | **High.** Identify controller and firmware; test touch initialization, coordinates, multitouch, gestures, Home button and wake |
| Wi-Fi | Wi-Fi chipset/revision, firmware, DriverKit extension, regulatory data | README reports Wi-Fi working; builder copies SE firmware and applies `wlanhax` to iOS 16 DriverKit executable | Reference-reported; not Phoenix-tested | **Medium–high.** Record exact firmware/chip IDs; validate association, WPA modes, DHCP, roaming, throughput, sleep/wake and regulatory behavior |
| Bluetooth | Bluetooth controller, firmware, transport and userspace services | README reports Bluetooth working; Bluetooth audio is separately reported as working | Reference-reported; not Phoenix-tested | **Medium.** Test pairing, reconnect, HID, audio profiles, coexistence with Wi-Fi and sleep/wake |
| Cellular / baseband | Exact N69 model, modem/baseband firmware, RF configuration, carrier bands, SIM | README lists baseband as working but explicitly says cellular was not fully tested; restore helper maps N69 to a J72s profile | Reference-reported with major caveat; source-observed restore mapping | **High.** Verify modem identity and firmware pairing; test SIM, registration, calls, SMS, data, VoLTE, emergency behavior and recovery |
| SEP / Touch ID | SEP firmware, Secure Enclave, sensor pairing, restore/activation path | README reports SEP and Touch ID working; builder takes iPad 5 SEP firmware and renames it to N69 paths | Reference-reported; not Phoenix-tested | **High.** Investigate exact SEP compatibility and pairing; test passcode, Touch ID enrollment/unlock, reboot, restore and recovery |
| Camera / ISP | Rear/front sensors, sensor firmware, ISP, camera drivers, H6 ISP services, AVFCapture | README reports camera not working; builder copies `H6ISPServices.framework` and patches AVFCapture capability paths | Reference-reported failure; source-observed partial adaptation | **Critical.** Inventory sensor IDs, ISP firmware, device tree, kernel drivers, camera services and capture pipeline; do not infer support from capability metadata |
| Audio | Codec, audio controller, amplifier, routing, DSP/firmware and CoreAudio services | README reports device audio not working; Bluetooth audio works | Reference-reported failure | **Critical.** Map codec/amp hardware, audio kexts, DSP firmware, route configuration, microphones, speaker, headset and Bluetooth paths |
| Flashlight / LED | Rear LED controller, camera/flash service and power control | README reports flashlight working | Reference-reported | **Medium.** Test continuous flash, thermal limits, camera/flash coordination and low-battery behavior |
| Power / PMU / charging | PMU, battery gauge, charger controller, thermal sensors and board-specific power rails | `pmuhax` adapts D2365 PMU assumptions toward D2255; `AppleSN2400Charger` is grafted; hardware test pending in source comments | Source-observed; runtime evidence incomplete | **Critical.** Identify actual PMU/charger variants; validate boot, charging, battery reporting, thermal throttling, shutdown and sleep/wake |
| Sensors / motion | M9, gyro, accelerometer, proximity, ambient light, compass and sensor fusion | No complete subsystem validation in reference README | Unknown | **Medium–high.** Map sensor drivers and calibration; test each sensor and background motion behavior |
| NFC / Apple Pay | NFC controller, Secure Element, SEP, entitlements and service support | Apple specs confirm NFC hardware; reference README says Apple services, not Apple Pay/NFC specifically | Unknown | **High.** Separate NFC detection from payment/secure-element service compatibility; do not infer Apple Pay support |
| Storage / APFS | NAND configuration, APFS, snapshots, volume groups, cryptex and storage drivers | Reference creates a custom filesystem and restore image; no full storage stress results | Source-observed only | **High for newer OS.** Audit APFS version/features, volume layout, snapshots, sealing, cryptex and available capacity |
| Memory pressure | 2 GB RAM, kernel memory layout, jetsam policy, userspace service footprint | No quantitative memory profile in reference README | Unknown | **Critical for newer OS.** Measure boot-time and steady-state memory, compressed memory, jetsam events and SpringBoard stability |
| Sensors / proximity / auto-brightness | Sensor hardware and userspace services | Apple lists sensors; reference project does not report individual test results | Unknown | **Medium.** Map driver matching and service ownership; test calls, display dimming and orientation/motion features |

## 4. Critical distinction: iPad 5 and iPhone SE share A9, not an identical platform

The iPad 5 is a useful donor because it uses an A9-generation platform and the reference builder can reuse selected A9-related components. However, shared SoC generation does not mean the two devices have identical:

- Board identifiers, device trees, GPIO maps, interrupt routing, and power domains.
- Display panel, touch controller, display/PMU wiring, and charger hardware.
- Camera sensors, ISP wiring, microphone and audio codec paths.
- Wi-Fi/Bluetooth module revisions, antennas, RF configuration, and cellular modem integration.
- NAND/storage configuration, battery gauge, thermal sensors, and accessory controllers.

Therefore, each donor component must be justified at the subsystem and board level. A9 branding alone is not a compatibility test.

## 5. N69 variant identification is mandatory

Firmware documentation distinguishes N69 variants commonly labelled `N69AP` and `N69uAP`; the reference builder also has separate N69/N69u restore paths and SEP filenames. Model identifiers and cellular band support vary by physical model number.

Before any hardware testing, record:

- Physical model number printed on the device (for example, A1662, A1723, or A1724).
- Product type and board configuration reported by trusted device diagnostics.
- `N69AP` or `N69uAP` identity where applicable.
- A9 chip identification/revision where obtainable from trusted diagnostics.
- Baseband firmware version and modem identity.
- Wi-Fi and Bluetooth chip/firmware identity.
- Display/touch and camera sensor identifiers where obtainable.

Do not assume all iPhone SE 1st generation devices have identical cellular bands or board-level components.

## 6. Minimum validation ladder

Every subsystem should progress through these evidence levels:

1. **Inventory verified:** exact hardware identity and source firmware recorded.
2. **Static compatibility reviewed:** driver, firmware, device tree, ABI and dependencies mapped.
3. **Build artifact validated:** image parses and expected components/metadata are present.
4. **Restore validated:** restore completes and recovery remains available.
5. **Boot validated:** device reaches a stable OS boot; repeat cold/warm boots.
6. **Subsystem validated:** actual hardware operation tested with logs.
7. **Stability validated:** repeated use, thermal, battery, sleep/wake, recovery and data integrity tested.

A result at one level must not be described as having passed a later level.

## 7. Proposed test matrix

| Test ID | Subsystem | Minimum test cases | Evidence to collect |
|---|---|---|---|
| `BOOT-01` | Boot / restore | Cold boot, warm reboot, recovery, restore failure recovery | Boot logs, restore logs, panic logs, boot stage reached |
| `DISP-01` | Display | Backlight, brightness, colors, sleep/wake, repeated boot | Display logs, panel identity, photos/video of test pattern |
| `TOUCH-01` | Touch | Single touch, multitouch, edges, gestures, Home button, wake | Input logs, coordinate mapping, missed/duplicate events |
| `WIFI-01` | Wi-Fi | Scan, WPA association, DHCP, DNS, throughput, roaming, sleep/wake | DriverKit logs, firmware version, network logs |
| `BT-01` | Bluetooth | Pair, reconnect, HID, audio, coexistence | Bluetooth logs, device/profile identity |
| `CELL-01` | Cellular | SIM detection, registration, voice, SMS, data, handover | Baseband logs, carrier state, radio identity; only in safe/legal test conditions |
| `SEP-01` | SEP / Touch ID | Passcode, enrollment, unlock, reboot, recovery | SEP logs, authentication results; never collect secrets |
| `CAM-01` | Camera / ISP | Rear/front preview, still image, video, flash, focus, exposure | Sensor IDs, camera service logs, sample media |
| `AUD-01` | Audio | Speaker, receiver, mic, headset, ringtone, recording, Bluetooth audio | Audio route logs, device IDs, sample recordings |
| `PWR-01` | Power | Charge/discharge, battery reporting, thermal load, sleep/wake | Power logs, temperature, battery telemetry |
| `GPU-01` | Graphics | Compositor startup, Metal device, render test, video playback | AGX/Metal logs, frame timing, crash/panic logs |
| `MEM-01` | Memory | Boot memory, idle footprint, app launch, pressure, jetsam | VM statistics, jetsam reports, kernel memory logs |

## 8. Immediate research priorities

1. **Exact target inventory:** identify the user's test device model and N69 variant before assuming the donor path applies to it.
2. **Device Tree audit:** compare N69 and J72 board descriptions for display, touch, PMU, charger, camera, audio, wireless, and sensors.
3. **Kernel/kext dependency graph:** list every N69 kext and dependency that the reference grafts, patches, or leaves untouched.
4. **GPU stack audit:** identify the exact A9 GPU/AGX family, supported Metal features, kernel driver pairing, and compositor requirements.
5. **Camera/ISP audit:** map actual sensor and firmware dependencies to explain why the reference AVFCapture capability patch does not make the camera work.
6. **Audio hardware audit:** identify codec, amplifier, audio controller, DSP and firmware dependencies behind the reported device-audio failure.
7. **Power and thermal audit:** verify PMU and charger mappings before any extended boot or load testing.
8. **Newer-iOS feasibility gate:** do not select a target build until kernel/boot-chain support, userspace ABI, memory footprint, Cryptex and signing requirements are investigated.

## 9. Safety and scope

- Do not test experimental restore images on a primary phone.
- Preserve a known-good restore path and understand recovery/DFU procedures before any device experiment.
- Do not erase, flash, or alter the user's only working device as part of this research phase.
- Do not publish proprietary firmware binaries, extracted copyrighted system files, private keys, or device-specific secrets in this repository.
- Do not bypass carrier restrictions, regulatory controls, or security boundaries as a substitute for compatibility engineering.
- A successful boot does not establish cellular emergency-call reliability, battery safety, or long-term device stability.

## 10. Audit conclusion

The iPhone SE 1st generation is not merely an A9 CPU attached to a generic iOS filesystem. It is a distinct N69 hardware platform with board-specific display, touch, power, camera, audio, radio, SEP and restore requirements. The reference iOS 16.1 project demonstrates that selected components can be adapted, while its own reported camera and device-audio failures illustrate why capability flags and partial driver reuse are not enough.

**Phoenix status:** hardware baseline and compatibility questions documented. The exact physical test-device variant has not been recorded in this audit. No Phoenix firmware build, restore, boot, or hardware test has been performed. Newer-iOS feasibility remains undetermined.

## Sources

- Apple iPhone SE technical specifications: https://support.apple.com/id-id/112005
- Apple iPhone SE introduction and A9 overview: https://www.apple.com/newsroom/2016/03/21Apple-Introduces-iPhone-SE-The-Most-Powerful-Phone-with-a-Four-inch-Display/
- iFixit iPhone SE teardown: https://www.ifixit.com/Teardown/iPhone+SE+Teardown/60902
- Reference project README: https://github.com/pwnerblu/iphonese-ios16/blob/main/README.md
- Reference builder: https://github.com/pwnerblu/iphonese-ios16/blob/main/build-ipsw.sh
- Reference patch sources: https://github.com/pwnerblu/iphonese-ios16/tree/main/patchsrc

---

*Research matrix, not a hardware certification. Confirm the exact model, board variant, firmware build, and device-specific component inventory before implementation.*