# Kernel Evidence Set Workflow

**Project:** Project Phoenix SE  
**Target:** iPhone SE (2016), A9 / n69  
**Prospective donor:** iPhone SE (2020), A13  
**OS target:** iOS 27.3 or later

This workflow binds the existing Phoenix kernel reports to exact firmware evidence before comparison. It does not establish hardware compatibility.

## 1. Keep target and donor inputs separate

Use separate directories and preserve the original IPSW files outside the repository:

```text
local-work/
  firmware/
    target-se1.ipsw
    donor-se2.ipsw
  reports/
    target/
    donor/
    validation/
```

Do not commit IPSWs, decrypted firmware, extracted kernel binaries, private keys, or device-specific secrets.

## 2. Inspect each IPSW

Run Phoenix Firmware Inspector independently for the target and donor. Record ProductType, ProductVersion, BuildVersion, supported product types, BuildManifest SHA-256, and IPSW SHA-256. The donor must be an iPhone SE (2020) firmware at iOS 27.3 or later before it can be considered for the selected target.

Do not assume that a firmware is available or signed; verify the actual file and its manifest.

## 3. Generate matching report sets

For each side, generate reports from the same exact IPSW/build:
- Mach-O report for the relevant kernel or executable image;
- Kernel Collection report for the corresponding kernel collection;
- kext dependency report for kexts extracted from that same firmware.

Record extraction method, tool version, source path, and SHA-256. A report without a traceable firmware source must not be silently assigned to a build.

Where supported, reports should include a top-level `firmware_identity` object:

```json
{
  "product_type": "verified ProductType",
  "product_version": "verified ProductVersion",
  "build_version": "verified BuildVersion",
  "build_train": "verified build train or null",
  "board_identity": "verified board identity or null"
}
```

Only populate values verified from the exact firmware manifest or device evidence.

## 4. Validate evidence-set provenance

Create the manifest described in [Phoenix Evidence Set Validator](../../tools/phoenix-evidence-set/README.md). Include all three reports for each side, their expected tool names, and actual SHA-256 hashes.

Run:

```sh
python3 tools/phoenix-evidence-set/phoenix_evidence_set.py \
  research/kernel/evidence-set.json \
  --out reports/validation/evidence-set-validation.json
```

Interpretation:
- `valid`: report hashes, tool names, and available per-report identity data are internally consistent;
- `incomplete`: no proven conflict, but required identity data is missing;
- `invalid`: a hash/tool mismatch or conflicting identity is present.

Do not proceed to compatibility comparison with an `invalid` set. Resolve an `incomplete` set by obtaining the missing evidence; do not fill unknown values by inference.

## 5. Run the existing compatibility analyzer

Only after manual review of a valid evidence-set report, run the existing Phoenix Kernel Compatibility Analyzer with the six report paths. Keep its output beside the validation report.

The analyzer's `Potential`, `Incompatible`, or `Unknown` indication remains a limited metadata comparison. It is not an ABI, kernel API, driver, boot, or hardware verdict.

## 6. Record the result

Archive:
- IPSW identity and checksums;
- evidence-set manifest and validation report;
- all input report hashes;
- compatibility output;
- tool versions and command lines;
- unresolved questions and reviewer notes.

Do not change the A9 profile subsystem status to `working` unless a dated test on the actual iPhone SE (2016) records device, build, method, and result.

## 7. Current project gate

At the time this workflow was added, no exact-build iOS 27.3+ iPhone SE (2020) donor report set had been verified in this repository. The workflow is ready for use with future evidence; it is not a completed donor extraction or compatibility result.
