# Phoenix Kernel Dependency Graph

Builds an evidence-labelled graph from Phoenix Kext Dependency Analyzer reports, optionally correlating Kernel Collection entries and explicit symbol-provider mappings. Python 3.10+, standard library only.

## Usage

    python tools/phoenix-kernel-graph/phoenix_kernel_graph.py \
      --kext-report reports/kexts.json \
      --kc-report reports/kernel-collection.json \
      --out reports/kernel-dependency-graph.json \
      --mermaid-out reports/kernel-dependency-graph.mmd

The Kernel Collection report is optional. To add symbol relationships, supply a manually reviewed JSON map:

    {
      "providers": [
        {
          "symbol": "_example_symbol",
          "consumer_bundle_id": "com.example.consumer",
          "provider_bundle_id": "com.example.provider"
        }
      ]
    }

Then add `--symbol-provider-map reports/symbol-provider-map.json`.

## Graph semantics

- Kext dependency edges come from `OSBundleLibraries` and provider bundle IDs found in the scanned set.
- Missing providers become explicit external dependency nodes and unresolved edges.
- Kernel Collection correlation uses exact equality between a fileset entry identifier and `CFBundleIdentifier`.
- Symbol references/providers are included only from an explicit reviewed mapping. The graph does not guess providers based on symbol-name overlap.
- Boot-critical candidates use selected `OSBundleRequired` metadata values and must be manually verified.

JSON output includes SHA-256 hashes for each input report. Mermaid output is a convenience view of the same evidence.

## Limitations

This is a metadata graph, not a kernel loadability or compatibility verdict. It does not evaluate version constraints, ABI, symbol resolution, executable code, signatures, entitlements, device-tree bindings, SEP, baseband, or hardware behavior. Duplicate bundle IDs remain ambiguous. An exact Kernel Collection identifier match is correlation only.

No firmware or device is modified, patched, signed, executed or restored.
