# PMU Patch Instruction Delta — Static Decode Review

**Reference:** `pwnerblu/iphonese-ios16/patchsrc/pmuhax.c`  
**Source blob:** `1117445bcb8665d7a812e1bb2b22c4c213329376`  
**Phoenix catalog:** `research/PMU-SIGNATURE-CATALOG.json`  
**Decoder report:** `research/PMU-ARM64-SEMANTIC-DECODE.json`  
**Scope:** source-derived instruction-word comparison only; no kernel binary, runtime, or hardware validation.

## Summary

The 66 mutating rules change one selected 32-bit word at the rule's `patch_word_index`. The current partial decoder classifies the original and replacement words as follows:

| Original class | Replacement class | Rules |
|---|---|---:|
| Arithmetic immediate | Arithmetic immediate | 19 |
| Move-wide immediate | Move-wide immediate | 35 |
| Unknown | Unknown | 4 |
| Move-wide immediate | NOP | 1 |
| Branch | NOP | 2 |
| Arithmetic immediate | Unknown | 1 |
| Logical register | NOP | 2 |
| Unknown | Move-wide immediate | 1 |
| Arithmetic immediate | Move-wide immediate | 1 |
| **Total** | | **66** |

The decoder reports five replacements as NOPs (AArch64 `0xd503201f`): rule indices 57, 59, 61, 62, and 65. Two of these replace branch-class instructions (59 and 65), two replace logical-register instructions (61 and 62), and one replaces a move-wide instruction (57).

This observation is important but does **not** establish the complete behavior of the LDO routine. The patcher overwrites the static placeholders for rules 59, 61, 62, and 65 with four dynamic branch instructions in `prepare_jumps()`. Rule 57 remains a NOP. The branch kinds and target rule anchors are now documented in [PMU LDO Control-Flow Reconstruction](PMU-LDO-CONTROL-FLOW.md); exact byte displacements still depend on the matched kernel offsets.

## High-confidence decoded examples

- Rule 0: `cmp w0, #0x60` becomes `cmp w0, #0x54`.
- Rule 4: `cmp x8, #0x18` becomes `cmp x8, #0x15` (register/width interpretation follows the decoded word).
- Rule 1: `movz w1, #0x12c` becomes `movz w1, #0x126`.
- Rule 54: `cmp w21, #0x20` becomes `cmp w21, #0x1c`.
- Rule 57: a `movk` instruction is replaced by `nop` and remains a NOP after dynamic jump preparation.
- Rule 59: a masked `cbz` template is replaced at runtime by an unconditional `B` to rule 66.
- Rule 65: a masked `b.ne` template is replaced at runtime by an unconditional `B` to rule 60.

The examples are decoded from the 32-bit words stored in the catalog. Register names and immediate values should be checked against the exact instruction word and the source rule context before drawing a higher-level conclusion.

## Decoder coverage and unresolved cases

The current Phoenix decoder supports a selected subset: B/BL, B.cond, CBZ/CBNZ, TBZ/TBNZ, ADR/ADRP, ADD/SUB immediate and CMP/CMN aliases, MOVN/MOVZ/MOVK, selected logical shifted-register operations, integer unsigned-immediate loads/stores, BR/BLR/RET, and NOP.

It is not a complete AArch64 decoder. The report contains 103 words classified as unknown across the 630 signature words. Five of the 66 replacement words are also currently unknown under the limited decoder. Rule 60's replacement `0x9ada2508` is `LSRV X8, X8, X26`; its higher-level purpose still needs surrounding data-flow context.

Two mutating signature words have non-full masks. Their variable fields are templates, not exact original instruction operands. This particularly matters for branch encodings, where displacement bits are deliberately masked.

## What can and cannot be concluded

### Supported by the source and static decode

1. The PMU patcher changes immediate arithmetic and move-wide constants across GPIO, PMU event/mask, and LDO rule groups.
2. Five replacement words are NOP encodings.
3. The LDO group includes instruction replacements and four separately calculated branch redirects (59→66, 61→67 via TBZ, 62→68, and 65→60).
4. Signature masks and patch-word indices are explicit in the source and preserved in the catalog.

### Not established

1. The physical meaning of each changed constant (pin count, rail identifier, register index, event count, or buffer size).
2. Whether each individual edit is necessary or sufficient.
3. The complete LDO control-flow graph after all dynamic redirects.
4. Register liveness, NZCV flag dependencies, stack state, exception behavior, or ABI correctness.
5. Whether the patch works on other iOS 16 builds, another donor device, or any later iOS release.
6. Whether the patched PMU behaves safely on physical hardware.

## Next required analysis

- Run LLVM or another full AArch64 disassembler against the exact extracted donor kernel and embedded PMU kext.
- Resolve every signature match to an address and retain the exact surrounding instructions.
- Decode all 66 replacements and the four dynamically generated branch instructions in place.
- Reconstruct the LDO routine's basic blocks, successors, register liveness, and NZCV dependencies.
- Correlate PMU and LDO data with device-tree properties and hardware documentation.
- Compare a target-build PMU implementation before considering any port.

**Safety boundary:** This is a static source audit. Phoenix has not patched or restored firmware and has not validated this code on an iPhone SE.
