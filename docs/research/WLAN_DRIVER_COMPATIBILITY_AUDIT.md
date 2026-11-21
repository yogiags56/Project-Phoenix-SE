# WLAN Driver Compatibility Audit

**Project:** Project Phoenix SE  
**Reference:** `pwnerblu/iphonese-ios16`  
**Source reviewed:** `patchsrc/wlanhax.c` and its integration in `build-ipsw.sh`  
**Scope:** Static source analysis only. No binary was patched, compiled, restored, or tested.

## 1. Executive summary

`wlanhax.c` is a narrowly scoped patcher for the AppleBCMWLAN DriverKit executable inside `com.apple.DriverKit-AppleBCMWLAN.dext`. Its header documents two distinct modifications:

1. Redirect the local `requestImageVerify` import stub to return `IOReturn` success (`0`).
2. Replace the entry of `AppleBCMWLANCore::setLMTPC()` with an immediate return, skipping the LPC parameter write while leaving country-code handling and other commands intact.

This does not replace the Wi-Fi driver, firmware, or the complete image-validation infrastructure. It changes two selected code paths in one executable. The build script separately copies Wi-Fi firmware from the iOS 15.8.8 SE filesystem into the iOS 16.1 DriverKit extension firmware directory.

## 2. Target and build integration

Target executable:

`System/Library/DriverExtensions/com.apple.DriverKit-AppleBCMWLAN.dext/com.apple.DriverKit-AppleBCMWLAN`

Observed build flow:

1. Extract entitlements from the original DriverKit executable using `ldid -e`.
2. Run `wlanhax` to create a patched output file.
3. Replace the executable in the new filesystem with the patched file.
4. Set executable permissions and root:wheel ownership.
5. Re-sign the modified executable using the previously extracted entitlements.

Separately, the script copies files from the SE 15.8.8 Wi-Fi firmware directory into the iOS 16.1 DriverKit extension's `Firmware` directory. The patcher itself does not copy or transform those firmware files.

## 3. Patch A — `requestImageVerify` success shim

### Discovery method

- Parses a thin ARM64 Mach-O executable, or a universal binary containing exactly one plain ARM64 slice.
- Validates Mach-O load-command and segment/section bounds.
- Reads the symbol table, dynamic symbol table, indirect symbol table, and `__TEXT,__stubs` section.
- Resolves the exact mangled import symbol `__Z18requestImageVerifyPK12OSDictionaryPK29IOFileValidationTrustedFile_sm` through indirect-symbol metadata.
- Requires exactly one matching import stub.
- Validates the expected ARM64 stub shape: ADRP, LDR, and BR.
- Scans executable text for direct BL callers and requires at least one caller.

### Modification

The first eight bytes of the validated 12-byte stub are replaced with:

- `MOV W0, #0` (`0x52800000`)
- `RET` (`0xd65f03c0`)

The third instruction word is preserved. The effect is to make calls through this local import stub return success without invoking the original imported verification routine.

### Interpretation and limits

This is a targeted bypass of the DriverKit executable's local `requestImageVerify` call path. It is not evidence that the system-wide iOS code-signing policy, trust cache, AMFI, Secure Boot, or all DriverKit verification paths are bypassed.

Because image verification is a security boundary, Phoenix must treat this patch as a security-sensitive compatibility experiment. It must not be generalized to unrelated executables or used as a substitute for understanding the intended trust model.

## 4. Patch B — skip `setLMTPC` LPC write

### Discovery method

- Locates the unique defined symbol `__ZN16AppleBCMWLANCore8setLMTPCEv` in the Mach-O symbol table.
- Determines the function extent using the next defined symbol in `__TEXT,__text`.
- Requires a bounded, aligned function length and validates a specific ARM64 prologue and instruction context.
- Resolves ADRP/ADD references to `__cstring` anchors and requires the expected `lpc` and `XZ` string-reference counts.
- Scans the text section for direct BL callers to the function.

### Modification

The first instruction of the validated function is replaced with `RET` (`0xd65f03c0`). The source comments state that this skips the function before its prologue, avoiding the LPC parameter write while preserving country-code updates, other IOVars, and fault handling elsewhere.

### Interpretation and limits

This is a targeted workaround for the LPC programming path. It does not establish that the radio firmware, regulatory domain handling, channel selection, transmit power, calibration, or all wireless operations are correct.

Skipping hardware programming may have consequences that cannot be determined from source inspection alone. A real device test would need to cover different access points, bands, channels, roaming, sleep/wake, sustained transfer, thermal behavior, and regulatory compliance.

## 5. Defensive implementation details

The patcher includes several safeguards:

- Mach-O and universal-binary bounds checks.
- Exact ARM64 slice selection.
- Validation of load-command, segment, section, symbol, and indirect-symbol ranges.
- Exact-one-match requirements for the verification import and `setLMTPC` symbol.
- Validation of the expected instruction sequence and function context.
- Direct-caller checks to reduce the chance of patching dead or unrelated code.
- Recognition of an already-patched form for idempotent handling.
- Output creation with `O_EXCL`, refusing to overwrite an existing path.
- Preservation of file length and all bytes outside the selected edits.
- Explicit warning that the patched executable must be re-signed before device use.

These checks reduce accidental corruption but do not prove that the selected behavior is correct on hardware.

## 6. Phoenix compatibility implications

Wi-Fi compatibility must be treated as at least four separate layers:

| Layer | What the reference does | What Phoenix must establish |
|---|---|---|
| Driver executable | Patches two selected code paths | Exact driver build, ABI, symbols, and behavior |
| Firmware files | Copies SE Wi-Fi firmware into the newer extension directory | Firmware compatibility, version pairing, chip/revision support |
| DriverKit/runtime | Uses the newer system's DriverKit extension and signing/entitlements | Extension loading, entitlement validity, IPC and service compatibility |
| Hardware/radio behavior | Not proven by the patch source | Association, authentication, throughput, roaming, regulatory behavior, sleep/wake and stability |

Do not assume that the same two patches will match a newer iOS DriverKit executable. Symbol names, instruction sequences, function boundaries, import metadata, firmware interfaces, and security behavior may all change.

## 7. Recommended test plan (future work)

Before any device-level testing, create an isolated test fixture using legally obtained firmware and a disposable research device. Keep an unmodified input and record cryptographic hashes.

Suggested validation sequence:

1. Verify the exact model, board identifier, iOS build, DriverKit extension version, and Wi-Fi chip/firmware identity.
2. Confirm the original executable's Mach-O architecture, symbols, import stub, and function layout.
3. Test the patcher only on a copy; verify it refuses unsupported or ambiguous inputs.
4. Compare input/output hashes and confirm only the expected instruction ranges changed.
5. Verify entitlement and signing metadata after modification.
6. Confirm the DriverKit extension loads and reports the expected hardware.
7. Test association, authentication, DHCP, DNS, local network traffic, internet traffic, reconnect, roaming, sleep/wake, and sustained transfer.
8. Test regulatory behavior and verify that no unsupported radio configuration is introduced.
9. Capture system logs, DriverKit logs, crash reports, and repeatability results.

Do not claim Wi-Fi is working based only on successful IPSW creation, successful signing, or the absence of an immediate boot failure.

## 8. Open questions

- Which exact Wi-Fi chipset/revision and firmware build are present in the target SE unit?
- What is the precise compatibility reason for bypassing `requestImageVerify` in this DriverKit executable?
- What hardware behavior does `setLMTPC` control on this device, and what are the consequences of skipping it?
- Are the copied firmware files a complete matching set, or are there additional firmware/configuration dependencies?
- Does the target iOS release retain the same DriverKit architecture, validation call path, and symbol/function semantics?
- What security and regulatory guarantees are lost or changed by these workarounds?

## 9. Audit conclusion

`wlanhax.c` is a carefully targeted binary patcher with structural validation and narrow edits. Its two workarounds should be understood independently: one changes a local image-verification call path, and the other skips an LPC programming function. The reference build also imports SE-specific Wi-Fi firmware separately.

**Phoenix status:** source behavior documented; no patcher compiled or executed; no DriverKit load, Wi-Fi association, or radio test performed. The patch is not approved for reuse on a newer iOS build.

## Source references

- `wlanhax.c`: https://github.com/pwnerblu/iphonese-ios16/blob/main/patchsrc/wlanhax.c
- Build integration: https://github.com/pwnerblu/iphonese-ios16/blob/main/build-ipsw.sh
- Reference README: https://github.com/pwnerblu/iphonese-ios16/blob/main/README.md

---

*Static source audit for Project Phoenix SE. Re-verify the exact upstream revision and target firmware before implementation.*