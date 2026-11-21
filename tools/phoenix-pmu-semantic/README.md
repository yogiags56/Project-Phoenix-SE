# Phoenix PMU ARM64 Semantic Decoder

Conservative, partial decoder for selected AArch64 instruction classes found in the reference PMU patch signatures and replacement words.

## Run

    python phoenix_pmu_semantic.py ../../research/PMU-SIGNATURE-CATALOG.json \
      --output ../../research/PMU-ARM64-SEMANTIC-DECODE.json

Python 3.10+, standard library only.

## Decoded classes

- B / BL and B.cond
- CBZ / CBNZ and TBZ / TBNZ
- ADR / ADRP
- ADD / SUB immediate, including CMP / CMN aliases
- MOVN / MOVZ / MOVK
- Logical shifted-register operations, including MOV / TST aliases
- Integer unsigned-immediate loads/stores
- BR / BLR / RET
- NOP

Other instructions are marked \`unknown\`; no mnemonic is guessed. Signature masks are retained and any non-\`0xffffffff\` mask is explicitly marked as a template with wildcard bits.

## Interpretation limits

This is not a complete AArch64 disassembler. It does not recover instruction addresses, resolve symbolic branch destinations, perform data-flow or flag analysis, identify function boundaries, or reconstruct full LDO control flow. It decodes each 32-bit signature word and the patch replacement word independently. Use a trusted full disassembler (for example LLVM) on the exact extracted kernel image for complete context before drawing patch conclusions.

The report is source-derived static analysis only. It does not patch a binary, build an IPSW, restore a device, or validate hardware compatibility.
