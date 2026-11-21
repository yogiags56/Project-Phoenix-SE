# Phoenix PMU Catalog

Extracts the exact signature words, masks, rule metadata, jump map, and LDO table byte differences from the upstream \`pmuhax.c\` source.

This is a source-inventory tool only. It does not decode ARM64 semantics, patch a kernel, build an IPSW, or validate hardware behavior.

## Run

    python phoenix_pmu_catalog.py /path/to/pmuhax.c \
      --blob-sha 1117445bcb8665d7a812e1bb2b22c4c213329376 \
      --output reports/pmu-signature-catalog.json

Python 3.10+, standard library only.

## Output

- All 70 signature arrays, including each 32-bit expected word and mask.
- All 70 rule rows, patch-word index, replacement word, and mutating/anchor classification.
- The four source/target branch redirect relationships.
- Complete before/after LDO descriptor table bytes and per-byte differences.
- Provenance: upstream blob SHA and SHA-256 of the local source text.

## Interpretation boundary

The catalog preserves source data, not inferred hardware meaning. A signature word is not automatically a standalone instruction: it is one word in a masked multi-instruction pattern. Replacement words must be decoded in context and matched to the exact rule's patch-word index. The four jump rules are assigned dynamically by the C patcher; their final branch words depend on matched addresses and must not be guessed from the static replacement field.

Never treat a successful extraction as proof that the signatures match another kernel build or that the patch is safe.
