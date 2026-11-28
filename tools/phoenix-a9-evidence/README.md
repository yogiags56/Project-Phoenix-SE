# Phoenix A9 Platform Evidence Collector

Offline parser for researcher-supplied CPU and platform evidence exports. Python 3.10+, standard library only.

## What it does

- Parses an allowlisted set of ARM64 CPU register names and preserves numeric values.
- Parses selected Linux-style `/proc/cpuinfo` keys.
- Parses a limited key/value DeviceTree summary.
- Parses selected kernel configuration keys.
- Records source SHA-256, optional expected-hash verification, and researcher-supplied provenance.
- Reports missing evidence groups as `incomplete`; it never fills missing values from the iPhone model.

## What it does not do

This is not a device probe and cannot read privileged registers from an ordinary iOS app. It does not decode register bitfields, parse a raw DTB, validate a live kernel configuration, authenticate source origin, or establish compatibility. Input values remain claims from the source specified in the manifest.

## Manifest

Create `research/a9-evidence/manifest.json` with source paths relative to that manifest:

```json
{
  "schema_version": 1,
  "tool": "Phoenix A9 Platform Evidence Manifest",
  "sources": [
    {
      "name": "cpu-register-dump",
      "kind": "cpu_registers",
      "path": "cpu-registers.txt",
      "provenance": {
        "origin": "device diagnostic export",
        "device": "iPhone SE (2016)",
        "firmware_build": "record exact build or null",
        "collection_method": "record exact method",
        "collector_version": "record tool/version",
        "captured_at": "ISO-8601 timestamp"
      }
    },
    {
      "name": "cpuinfo-export",
      "kind": "cpuinfo",
      "path": "cpuinfo.txt",
      "provenance": {
        "origin": "local diagnostic export",
        "collection_method": "record exact method"
      }
    },
    {
      "name": "device-tree-summary",
      "kind": "device_tree_summary",
      "path": "device-tree-summary.txt",
      "provenance": {
        "origin": "target IPSW extraction",
        "firmware_build": "exact verified build"
      }
    },
    {
      "name": "kernel-config",
      "kind": "kernel_config",
      "path": "kernel-config.txt",
      "provenance": {
        "origin": "target kernel analysis",
        "firmware_build": "exact verified build"
      }
    }
  ]
}
```

The `sha256` property is optional. When supplied, it must match the exact source file bytes. If omitted, the collector still records the computed hash but marks it as not externally checked.

### Supported text formats

CPU registers (one key/value pair per line):

```text
MIDR_EL1=0x410fd030
MPIDR_EL1=0x80000000
ID_AA64PFR0_EL1=0x00000000
CTR_EL0=0x8444c004
```

The values above are format examples only, not asserted iPhone SE readings.

CPU info accepts selected colon-delimited keys, including processor, model name, CPU implementer, CPU part, CPU revision, and features.

DeviceTree summary accepts: `compatible`, `model`, `cpu_count`, `cpu_nodes`, `interrupt_parent`, `address_cells`, `size_cells`.

Kernel config accepts: `CONFIG_ARM64`, `CONFIG_ARM64_4K_PAGES`, `CONFIG_ARM64_16K_PAGES`, `CONFIG_SMP`.

## Run

```sh
python3 tools/phoenix-a9-evidence/phoenix_a9_evidence.py \
  research/a9-evidence/manifest.json \
  --out reports/a9-platform-evidence.json

python -m unittest discover -s tools/phoenix-a9-evidence/tests -v
```

Exit codes:
- `0`: all four evidence groups were supplied with no parser warnings;
- `1`: collection completed but evidence is incomplete or warnings exist;
- `2`: invalid manifest, unreadable input, unsupported kind, path escape, or hash mismatch.

## Report status

- `collected`: all four groups are present and no parser warnings were emitted;
- `incomplete`: one or more groups are absent, or parser warnings were emitted.

Neither status means that the evidence is authentic or that the A9 is compatible with any newer iOS kernel.
