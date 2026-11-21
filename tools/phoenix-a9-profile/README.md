# Phoenix A9 Platform Profiler

Evidence-first profile validator and report generator for the first-generation iPhone SE target. Requires Python 3.10+ and only the standard library.

## Quick start

Copy `profiles/iphone-se-1st-gen.template.json`, populate the exact device identity and subsystem evidence, then run:

    python3 tools/phoenix-a9-profile/phoenix_a9_profile.py profiles/my-iphone-se.json --out reports/a9-profile.json

Run tests:

    python -m unittest discover -s tools/phoenix-a9-profile/tests -v

## Evidence discipline

Subsystem statuses are limited to:

- `not_assessed`
- `researching`
- `experimental`
- `partially_working`
- `working`
- `blocked`

Evidence levels are `none`, `reference_reported`, `source_observed`, `static_analysis`, and `device_tested`.

The tool refuses a `working` status unless the entry includes a dated `device_test` record with device, build, method, result, and `device_tested` evidence level. Static source inspection or another project's README is not a hardware test.

## Required device identity fields

- `product_type`
- `board_variant` (for example N69AP or N69uAP, only after verification)
- `soc_variant` (for example S8000 or S8003, only after verification)
- `model_number`
- `firmware_build`

The report distinguishes a populated identity from an independently verified identity. It does not infer missing values.

## Subsystems

The template tracks boot/restore, kernel/device tree, CPU/ARM64, GPU/Metal, display, touch, audio, camera/ISP, Wi-Fi, Bluetooth, cellular/baseband, SEP/Touch ID, power/thermal, sensors, NFC/Secure Element, storage/APFS, memory pressure, core services and SpringBoard.

## Limitations

This tool validates JSON structure and summarizes evidence supplied by the researcher. It does not query a connected phone, inspect raw firmware, infer hardware compatibility, select donor components, patch, sign, execute or restore firmware. Do not commit private identifiers, proprietary firmware, extracted system binaries, or secrets.
