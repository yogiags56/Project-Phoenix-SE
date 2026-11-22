# PMU LDO Register Trace — Source-Derived

**Primary source:** `pwnerblu/iphonese-ios16/patchsrc/pmuhax.c`  
**Source blob:** `1117445bcb8665d7a812e1bb2b22c4c213329376`  
**Phoenix inputs:** `PMU-SIGNATURE-CATALOG.json`, `PMU-LDO-CONTROL-FLOW.md`  
**Scope:** exact source signature words, patch replacements, and ARM64 instruction semantics. No extracted donor kernel/disassembly was available during this analysis. No dynamic register values or physical rail behavior are claimed.

## 1. Why this trace is source-derived, not a runtime trace

The PMU patcher stores nine-word signatures around each patch site. The LDO signatures overlap, allowing several adjacent patch instructions to be read as a local instruction sequence. They do not provide the complete function, all basic blocks, concrete branch destinations for masked original branches, or runtime register values.

This document therefore distinguishes:
- **Certain:** exact instruction word, exact replacement word, and semantics of a fully constrained instruction.
- **Source-structure inference:** relationship implied by overlapping signatures and patcher redirect table.
- **Unresolved:** reaching definitions, path conditions, data values, and hardware meaning requiring the extracted donor kernel.

## 2. LDO index boundary — rule 54

Original/replacement:

```asm
cmp w21, #0x20       // original
cmp w21, #0x1c       // patched
b.hi <masked target>
```

The comparison constant changes from 32 to 28. `B.HI` is an unsigned condition (strictly higher), so this changes the unsigned upper-bound check. The masked branch displacement is not a reliable target and must not be reconstructed from the signature placeholder.

**Certain:** compare immediate 32 → 28 and condition class B.HI.  
**Unresolved:** whether W21 is always a zero-based rail index at this point, the exact accepted set, and the branch destination's complete behavior.

## 3. X8 mask-construction chain — rules 55–58

The patch sites form an adjacent instruction sequence in the overlapping signatures:

| Rule | Original instruction | Replacement | Effect |
|---:|---|---|---|
| 55 | `movz x8, #0x800` | `movz w8, #0x800` | Change destination width to W8 |
| 56 | `movk x8, #0x3e00, lsl #16` | `movk w8, #0x1f00, lsl #16` | Change width and upper-halfword constant |
| 57 | `movk x8, #1, lsl #32` | `nop` | Remove the high 32-bit insertion |
| 58 | `movk w8, #0xc1ff, lsl #16` | `movk w8, #0xff, lsl #16` | Change the W-register upper-halfword constant |

### Important architectural consequence

A write to a W register zero-extends into the corresponding X register. Therefore rules 55 and 56 write W8 and clear X8[63:32]. Rule 57's original instruction would then insert a one into the high 32-bit portion of X8; replacing it with NOP prevents that insertion. Rule 58 subsequently writes W8 again, also zero-extending into X8.

This is a strong instruction-level explanation for why the 64-bit high-word insertion is removed, but it does **not** identify the physical rail mask's meaning without the full consumer code and descriptor semantics.

## 4. Variable shift and bit test — rules 60–62

Rule 60 changes:

```asm
// Original
add w8, w21, #1

// Replacement
lsrv x8, x8, x26
```

`LSRV` performs a logical right shift of X8 by the shift amount in X26 and writes X8. It does not update NZCV flags. This is a substantive semantic change, not a simple immediate adjustment.

The next two patch sites are replaced by dynamic redirects:

```asm
// Rule 61 replacement
tbz w8, #0, <rule 67: normal-path anchor>

// Rule 62 replacement
b <rule 68: option-path anchor>
```

Thus the source-level branch logic is:
- If bit 0 of W8 is clear, rule 61 branches to the normal-path anchor.
- If bit 0 of W8 is set, TBZ is not taken; execution falls through to rule 62, which unconditionally branches to the option-path anchor.

This explains the **branch predicate** at the patched site. It does not establish the origin of W8's runtime value.

## 5. W26 candidate definition

The rule 66 / rule 69 overlapping main-path signatures include:

```asm
cmp  w21, #0x20       // patched to #0x1c at rule 54
b.hi <masked target>
mov  w26, w21
adrp x10, <table page>
add  x10, x10, <table offset>
```

The exact instruction `mov w26, w21` establishes a local definition of W26 from W21 at that matched main-path location. However, rule 60 consumes X26. W-register writes zero-extend to X26, but the available signature snippets do not prove that this particular definition reaches rule 60 on every relevant path. A full CFG and reaching-definition analysis are required before claiming that relationship.

## 6. Alternate-enable rail edits — rules 63–65

The patcher changes two instruction words in the alternate-enable rail sequence:

| Rule | Original | Replacement |
|---:|---|---|
| 63 | `0x121d7aa8` (logical-immediate AND class) | `movz w8, #0x4022` |
| 64 | `cmp w8, #1` | `movk w8, #0x20, lsl #16` |
| 65 | `b.ne <masked target>` | dynamic unconditional `b <rule 60>` |

The exact logical-immediate mask represented by `0x121d7aa8` is intentionally not guessed here. Rule 64 removes the compare operation and substitutes a move-wide write, so the subsequent flag-dependent behavior must be interpreted in the context of the full instruction stream.

Rule 65's dynamic unconditional branch means the original B.NE condition is no longer evaluated at that patch site: execution transfers to rule 60 regardless of the previous NZCV state.

The source comments label this region as the alternate-enable path for rails 1, 5, 14, and 21. That label is source provenance, not independent hardware confirmation.

## 7. Current register facts

| Register | Source-derived fact | Confidence |
|---|---|---|
| W21 | Compared against 32 (patched to 28); copied to W26 in the main-path signature | Exact instruction facts; reaching path unresolved |
| X8/W8 | Constructed and modified by rules 55–58; shifted by X26 at rule 60; bit 0 tested at rule 61 | Exact local instruction sequence; runtime value unresolved |
| X26/W26 | W26 is assigned from W21 in the main-path signature; X26 is the shift-count source at rule 60 | Consumer-to-definition link not proven |
| W9/W10 | Original MOV instructions at rules 61/62 are overwritten by branch instructions | Original copies do not execute at those sites after patching |
| W23 | Used by original MOV W9,W23 at rule 61; this copy is replaced by TBZ W8,#0 | Not the patched branch predicate |

## 8. What is needed to complete a real def-use trace

1. Extract the exact iPad 5 iOS 16.1 donor kernelcache used by the reference build.
2. Decompress the kernelcache and locate the embedded `AppleD2365PMU` Mach-O.
3. Record its UUID, architecture, segment map, and executable-section file/VM offsets.
4. Disassemble the complete `__TEXT_EXEC` range around rules 54–69, preserving addresses and raw words.
5. Resolve all branch targets, basic-block boundaries, and the LDO descriptor-table reference.
6. Feed the disassembly to Phoenix's register-flow analyzer only after its instruction semantics cover every opcode in the region; unknown opcodes must remain barriers.
7. Compare the source-derived expected words against the actual donor binary before any patch simulation.

## 9. Safety and conclusion

This is static reverse-engineering documentation only. It does not modify an IPSW, kernelcache, firmware, or device. It does not establish that the D2365 PMU changes are electrically safe or correct for the D2255/A9 target.

The key new result is a defensible local explanation of the X8 mask construction and the TBZ branch predicate. The next decisive artifact is the actual donor PMU disassembly; without it, a complete register def-use graph would be speculative.
