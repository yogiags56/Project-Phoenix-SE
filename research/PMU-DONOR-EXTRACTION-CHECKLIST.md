# PMU Donor Extraction Checklist

**Purpose:** prepare a reproducible, local-only evidence package for the iOS 16.1 donor kernel used by the reference iPhone SE iOS 16.1 builder.

## 1. Correct donor identity and role

The reference builder's iPad 5 iOS 16.1 input is:

- IPSW: `iPad_64bit_TouchID_ASTC_16.1_20B82_Restore.ipsw`
- Build: `20B82`
- Product family: iPad 5 / iPad6,11 or iPad6,12 variant (confirm the exact IPSW metadata; do not infer the variant from filename alone)
- Kernelcache path used by the builder: `kernelcache.release.ipad6f`
- Role: donor kernel input for the PMU and subsequent kernel patching stages.

The original iPhone SE 15.8.8 IPSW is a separate source used for target-specific N69 material and the SE-side kernel input to the kext-port stage. Do not confuse it with the iPad 5 PMU donor.

The source builder is the authority for this mapping: `pwnerblu/iphonese-ios16/build-ipsw.sh`. Phoenix has not independently downloaded or hashed the IPSW.

## 2. Evidence handling

Keep all Apple firmware and extracted proprietary binaries on the local research machine. Do not commit IPSWs, kernelcaches, extracted kext binaries, firmware keys, or decrypted components to this repository.

For each acquired artifact, record:
- Original filename and source URL/page.
- IPSW product/build/version and exact product identifier from its BuildManifest.
- SHA-256 of the original IPSW.
- Internal archive path of the extracted component.
- SHA-256 and byte length of the extracted component.
- Extraction tool and version/commit.
- Extraction date in UTC.
- Whether the component is encrypted, decrypted, compressed, or raw.
- Any transformation performed, including exact command and output hash.

Never label an artifact as decrypted or raw unless the extraction procedure and resulting format establish that fact.

## 3. Required artifact chain

| Stage | Expected artifact | Evidence to capture |
|---|---|---|
| A | Original iPad 5 iOS 16.1 IPSW | BuildManifest product/build, file size, SHA-256 |
| B | `kernelcache.release.ipad6f` from IPSW | Archive path, size, SHA-256, IMG4 payload metadata |
| C | Decrypted/decompressed kernel image, if needed | Tool/version, exact command, output size/hash, format identification |
| D | Mach-O or kernel collection container | Magic, CPU type/subtype, file type, UUID if present, load commands |
| E | Embedded PMU executable/kext or fileset entry | Bundle identifier, executable name, UUID, segment/section map, file/VM offsets |
| F | Disassembly of relevant executable section | Disassembler/version, command line, base address, architecture, raw instruction words |
| G | LDO region around signature rules 54–69 | Matched addresses, raw words, surrounding basic blocks and branch targets |

The kernelcache may be wrapped, compressed, encrypted, or represented as a kernel collection. Do not assume it is a directly disassemblable thin Mach-O. The current Phoenix IMG4, kernel collection, and Mach-O tools are structural inspectors with documented limitations, not a universal Apple kernelcache extractor/decryptor.

## 4. Suggested inspection order

1. Inspect the IPSW ZIP central directory and confirm the exact kernelcache member path.
2. Extract the member to a private working directory without modifying the source IPSW.
3. Hash the extracted member and parse its IMG4/IM4P structure where applicable.
4. Establish whether the payload is encrypted and/or compressed before attempting further processing.
5. Use a legally obtained compatible extraction/decompression workflow; record its exact version and outputs.
6. Run the Phoenix Mach-O inspector on a verified Mach-O image. If the image is MH_FILESET, run the kernel collection inspector and record all fileset entries.
7. Identify the PMU image from its actual bundle identifier and executable metadata, not from a guessed name or device codename.
8. Disassemble the complete relevant executable range. Preserve raw words and virtual addresses.
9. Match the PMU signature catalog against the donor disassembly. A match must include enough surrounding instructions to reject ambiguous or duplicate matches.
10. Only then run register def-use and CFG analysis over the complete function.

## 5. Required disassembly format

Provide a UTF-8 text listing with one instruction per line and explicit virtual addresses. Preferred shape:

```asm
fffffff007123000: d2800015  movz x21, #0
fffffff007123004: 7100811f  cmp w8, #0x20
fffffff007123008: 54000068  b.hi 0xfffffff007123014
```

The words above are illustrative formatting only, not actual PMU donor instructions.

Keep the disassembler's raw-word output enabled. If the tool emits a different format, preserve the original output and document the conversion rather than silently rewriting addresses or words.

## 6. Acceptance criteria before claiming a donor trace

- [ ] Exact IPSW variant and build are verified from its manifest.
- [ ] Original IPSW and extracted kernelcache hashes are recorded.
- [ ] Kernelcache payload format and transformation chain are documented.
- [ ] PMU executable identity is confirmed from metadata.
- [ ] Disassembly addresses map to the executable's actual VM range.
- [ ] Signature matches are unique or ambiguity is explicitly documented.
- [ ] All relevant instructions and branch targets are included.
- [ ] Register-flow results preserve unknown instructions as barriers until their effects are implemented.
- [ ] CFG joins and loops are analyzed; a linear listing is not presented as a complete runtime trace.
- [ ] No claim of A9 electrical safety or hardware compatibility is inferred from static disassembly alone.

## 7. Current status

At the time this checklist was added, Phoenix had the source-derived PMU signature catalog, patch-rule semantic notes, LDO source trace, and text-disassembly/register-flow tools. It did **not** have a verified local copy of the donor IPSW, extracted kernelcache, PMU executable, or donor disassembly in the repository.

The next useful input is the locally extracted `kernelcache.release.ipad6f` (or a metadata/disassembly report derived from it). Proprietary binary contents should remain local; share only hashes, structural metadata, and relevant disassembly excerpts that may lawfully be shared.
