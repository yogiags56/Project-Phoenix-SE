# PMU LDO Control-Flow Reconstruction (Source-Level)

**Reference:** `pwnerblu/iphonese-ios16/patchsrc/pmuhax.c`  
**Reference blob:** `1117445bcb8665d7a812e1bb2b22c4c213329376`  
**Related:** [PMU signature catalog](PMU-SIGNATURE-CATALOG.json), [semantic decode report](PMU-ARM64-SEMANTIC-DECODE.json), [instruction delta](PMU-PATCH-INSTRUCTION-DELTA.md).

## Critical patcher behavior

The `rules[]` table contains placeholder replacement words. Before any mutation, `prepare_jumps()` calculates four branch instructions from the matched file offsets:

```c
d = target->found - source->found;
source->replacement = test_bit
    ? 0x36000008 | ((d / 4) & 0x3fff) << 5
    : 0x14000000 | ((d / 4) & 0x3ffffff);
```

Therefore, the static `0xd503201f` placeholders at rules 59, 61, 62, and 65 are **not** the final kernel words. The only one of the five LDO NOP replacements that remains a NOP is rule 57.

## Four dynamic redirects

| Source rule | Source-level original | Runtime replacement | Target rule | Interpretation |
|---:|---|---|---:|---|
| 59 | `CBZ W8, imm` (masked) | `B target` | 66 | Unconditional transfer to LDO main anchor |
| 61 | `MOV W9, W23` | `TBZ W8, #0, target` | 67 | If bit 0 of W8 is clear, branch to normal-path anchor |
| 62 | `MOV W10, W20` | `B target` | 68 | Unconditional transfer to option-path anchor |
| 65 | `B.NE imm` (masked) | `B target` | 60 | Unconditional transfer to alternate-enable mask test |

The original branch words for rules 59 and 65 are masked templates: their wildcard displacement bits are not a reliable concrete destination. The table reports only the opcode class and the exact destination rule selected by the C patcher.

## Source-level edge model

```text
Rule 59  ── B ───────────────> Rule 66 (LDO main anchor)

Rule 61  ── TBZ W8, #0 ──────> Rule 67 (normal-path anchor)
   │
   └── bit 0 set: fall through to Rule 62
                         │
                         └── B ─> Rule 68 (option-path anchor)

Rule 65  ── B ───────────────> Rule 60 (alternate-enable mask test)
```

This graph describes the patcher's intended redirect edges and the immediate fall-through relationship implied by the adjacent matched instruction patterns. It is **not** a fully reconstructed CFG: the full function boundaries, all basic blocks, and all incoming/outgoing edges have not been recovered from an actual extracted kernel binary.

## Rule 60: decoded variable shift

The replacement word `0x9ada2508` decodes as:

```asm
lsrv x8, x8, x26
```

This is a 64-bit logical right shift of X8 by the amount in X26. The result is written to X8. It does not update NZCV flags. The source comment labels the rule as an alternate-enable mask test, but the exact mask semantics require surrounding code and data-flow analysis; do not infer a rail mask meaning from this instruction alone.

## Rule 57: actual NOP replacement

Rule 57 changes a 64-bit MOVK operation that writes the high 16-bit halfword of X8 into a NOP. Unlike rules 59, 61, 62, and 65, it is not overwritten by `prepare_jumps()`. This removes that high-halfword insertion from the register-construction sequence. The resulting value depends on the earlier writes to X8 and must be evaluated with the exact preceding instructions.

## What this establishes

- Four static placeholder values are replaced by dynamically encoded branches before patch writes.
- The branch targets are rules 66, 67, 68, and 60 respectively.
- Rule 61 is a `TBZ W8, #0` conditional edge; the set-bit case falls through to rule 62, which branches to rule 68.
- Rule 60's replacement is `LSRV X8, X8, X26`.
- Rule 57 remains a NOP mutation.

## What remains unresolved

1. Exact branch displacements and final instruction words; these depend on signature match addresses in the target kernel.
2. The full basic-block graph and all paths into/out of these anchors.
3. Register liveness and the origin/meaning of X8, X26, W8, W23, W9, and W10 at each point.
4. NZCV flag producers/consumers around the original masked branch sites.
5. Whether the altered LDO logic is electrically and functionally correct for the target PMU.
6. Compatibility with any kernel other than the exact donor build used to derive the signatures.

**Safety:** This is static analysis of source code. It does not build, patch, restore, or validate firmware on an iPhone.