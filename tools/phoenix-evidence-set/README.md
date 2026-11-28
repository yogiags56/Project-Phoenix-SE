# Phoenix Evidence Set Validator

Validates the provenance and exact-build consistency of Phoenix JSON reports before they are passed to cross-device comparison tools. Python 3.10+, standard library only.

## Purpose

The validator addresses a specific risk in the existing Kernel Compatibility Analyzer: six reports can be structurally valid while accidentally belonging to different firmware builds.

It validates two independent evidence sets:
- `target`: iPhone SE (2016), A9 / n69 evidence;
- `donor`: iPhone SE (2020), A13 evidence.

The target and donor are expected to be different devices and may have different build identifiers. The validator checks consistency within each set; it does not require target and donor identities to match.

## Manifest format

Create a JSON manifest beside the reports:

```json
{
  "schema_version": 1,
  "tool": "Phoenix Evidence Set Validator Manifest",
  "evidence_sets": {
    "target": {
      "role": "target",
      "identity": {
        "product_type": "iPhone8,4",
        "product_version": "REPLACE_WITH_VERIFIED_VERSION",
        "build_version": "REPLACE_WITH_VERIFIED_BUILD",
        "build_train": null,
        "board_identity": "n69"
      },
      "reports": [
        {
          "name": "macho",
          "path": "target/kernel-macho.json",
          "expected_tool": "Phoenix Mach-O Analyzer",
          "sha256": "REPLACE_WITH_64_CHARACTER_SHA256"
        }
      ]
    },
    "donor": {
      "role": "donor",
      "identity": {
        "product_type": "REPLACE_WITH_VERIFIED_PRODUCT_TYPE",
        "product_version": "REPLACE_WITH_VERIFIED_VERSION",
        "build_version": "REPLACE_WITH_VERIFIED_BUILD",
        "build_train": null,
        "board_identity": null
      },
      "reports": [
        {
          "name": "macho",
          "path": "donor/kernel-macho.json",
          "expected_tool": "Phoenix Mach-O Analyzer",
          "sha256": "REPLACE_WITH_64_CHARACTER_SHA256"
        }
      ]
    }
  }
}
```

Replace all placeholders with values obtained from the exact firmware and actual reports. Do not invent build identifiers. Add the KC and kext reports as additional entries in each set.

Each report should include an explicit top-level `firmware_identity` object with the same identity field names when its producer supports that metadata. If the field is absent, the validator records the limitation as a warning and the evidence set is `incomplete`, not `valid`.

## Run

```sh
python3 tools/phoenix-evidence-set/phoenix_evidence_set.py \
  research/kernel/evidence-set.json \
  --out reports/evidence-set-validation.json

python -m unittest discover -s tools/phoenix-evidence-set/tests -v
```

Exit codes:
- `0`: both evidence sets are valid;
- `1`: at least one set is incomplete or invalid;
- `2`: manifest or input could not be parsed.

## Status semantics

- `valid`: report hashes and declared tool names match; declared identity fields are complete and consistent; reports explicitly carry matching firmware identity.
- `incomplete`: no proven conflict, but identity fields or per-report identity evidence are missing.
- `invalid`: hash mismatch, tool mismatch, malformed manifest, or conflicting identity evidence.

## Safety and limitations

- The tool reads reports and writes only its JSON result.
- It does not inspect, decrypt, decompress, patch, sign, execute, or restore firmware.
- It validates researcher-supplied provenance metadata; it does not independently authenticate an IPSW or device.
- A valid evidence set is not proof of ABI, kernel API, CPU-feature, driver, SEP, baseband, Cryptex, restore, or hardware compatibility.
- Keep proprietary firmware and extracted binaries local. Commit only source code, synthetic fixtures, and permitted metadata.
