# Phoenix Evidence Bundle Builder

Create a small metadata-only ZIP handoff from explicitly selected local reports. IPSW and firmware payloads remain on the researcher's machine.

Python 3.10+, standard library only.

## Included content

Allowed UTF-8 text formats: JSON, TXT, Markdown, CSV, LOG, YAML. Each file is limited to 2 MiB by default and the total uncompressed report content to 10 MiB by default. The bundle includes selected reports plus a generated `bundle-manifest.json` containing per-file SHA-256 hashes, sizes, source paths, labels, and user-supplied target/donor labels.

The builder refuses firmware/binary extensions, NUL-containing or non-UTF-8 files, files outside the manifest directory, duplicate names, and likely device identifiers such as ECID, UDID, IMEI, serial-number fields, and Wi-Fi/Bluetooth MAC addresses. It does not modify source files.

**Important:** automated detection is not a complete privacy review. Inspect the reports yourself before sharing. A hash proves byte identity, not authenticity or source provenance.

## Example manifest

Save as `research/handoff/manifest.json`. All paths are relative to this file:

```json
{
  "schema_version": 1,
  "tool": "Phoenix Evidence Bundle Manifest",
  "target": {
    "product_type": "iPhone8,4",
    "product_version": "verified target version",
    "build_version": "verified target build"
  },
  "donor": {
    "product_type": "verified donor product type",
    "product_version": "verified donor version",
    "build_version": "verified donor build"
  },
  "files": [
    {
      "name": "target-build-manifest-summary",
      "path": "target-build-summary.json",
      "description": "Sanitized BuildManifest identity summary"
    },
    {
      "name": "target-kernel-macho-report",
      "path": "target-kernel-macho.json",
      "description": "Mach-O structural report"
    },
    {
      "name": "donor-kernel-macho-report",
      "path": "donor-kernel-macho.json",
      "description": "Mach-O structural report"
    }
  ]
}
```

Replace every example identity with verified values. Do not add ECID, serial number, UDID, IMEI, private keys, account data, or unredacted device logs.

## Run

```sh
python3 tools/phoenix-evidence-bundle/phoenix_evidence_bundle.py \
  research/handoff/manifest.json \
  --out reports/phoenix-evidence-bundle.zip
```

Optional limits:

```sh
python3 tools/phoenix-evidence-bundle/phoenix_evidence_bundle.py \
  research/handoff/manifest.json \
  --out reports/phoenix-evidence-bundle.zip \
  --max-file-mb 1 --max-total-mb 5
```

Run tests:

```sh
python -m unittest discover -s tools/phoenix-evidence-bundle/tests -v
```

## Recommended workflow

1. Keep the original IPSWs and extracted payloads in local storage.
2. Run Phoenix IPSW Evidence Inspector against each IPSW to record verified BuildManifest identity and kernelcache member hashes.
3. Extract only needed payloads locally. Do not upload raw firmware or encrypted/decrypted payloads.
4. Run Phoenix Payload Inspector and the relevant Mach-O, KC, DeviceTree, kext, and ARM64 analyzers locally.
5. Export small JSON/TXT reports. Preserve source hashes and exact firmware build identifiers.
6. Create a manifest containing only the reports needed for the current research question.
7. Build the bundle and inspect its file list and contents.
8. Review for personal/device identifiers and proprietary or sensitive material before sharing the ZIP here.

## Current limitations

- This builder packages reports; it does not inspect or extract IPSW contents itself.
- It does not decrypt IMG4/IM4P, decompress kernelcache payloads, or parse unsupported binary formats.
- It does not verify Apple signatures or authenticate the origin of report metadata.
- It does not establish compatibility or replace exact-build provenance validation.
- Keep the original firmware, keys, raw device dumps, and large binaries local.
