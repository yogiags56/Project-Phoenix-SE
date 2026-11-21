# Phoenix Firmware Evidence Dashboard

A read-only aggregator for JSON reports produced by Phoenix tools. It creates a static HTML dashboard and a machine-readable JSON manifest. Python 3.10+, standard library only.

## Usage

Run the individual analyzers first, then pass their JSON outputs with distinct labels:

    python tools/phoenix-dashboard/phoenix_dashboard.py \
      --input firmware=reports/firmware-inspection.json \
      --input img4=reports/img4-inspection.json \
      --input device-tree=reports/fdt-analysis.json \
      --input macho=reports/kernel-macho.json \
      --input kernel-collection=reports/kernel-collection.json \
      --input kexts=reports/kext-inventory.json \
      --input kernel-compat=reports/kernel-compatibility.json \
      --input symbol-diff=reports/kernel-symbol-diff.json \
      --input dependency-graph=reports/kernel-dependency-graph.json \
      --input a9-profile=reports/a9-platform-profile.json \
      --out-json reports/phoenix-dashboard.json \
      --out-html reports/phoenix-dashboard.html

Only provide inputs that actually exist. The tool does not fabricate missing reports or assume all reports refer to the same firmware build.

Run tests:

    python -m unittest discover -s tools/phoenix-dashboard/tests -v

## Design

- Each input has a caller-supplied label, original path, SHA-256 digest, tool name, status/indication when present, and selected summary facts.
- HTML is static and self-contained; report-supplied text is HTML-escaped.
- Full source JSON reports remain separate and are not silently embedded or modified.
- The JSON manifest preserves report provenance and the limitations supplied by each analyzer.
- No single compatibility score or aggregate verdict is calculated.

## Interpretation and limitations

The dashboard is a presentation and aggregation layer, not a new compatibility analyzer. It does not independently validate source binaries, firmware build identity, device provenance, or report correctness. Inputs from different builds or device variants must not be treated as one coherent comparison set without review.

Potential means only that the source analyzer found limited positive metadata overlap. Unknown means evidence was insufficient. Missing reports are not negative evidence. Static analysis is not device testing. No firmware is decrypted, modified, patched, signed, executed, or restored.
