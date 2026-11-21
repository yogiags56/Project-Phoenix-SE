# Phoenix Firmware Inspector

Read-only IPSW metadata inventory and comparison tool. Requires Python 3.10+; standard library only.

## Inspect an IPSW

    python3 tools/phoenix-inspector/phoenix_inspector.py inspect firmware.ipsw \
      --out reports/firmware.json --markdown reports/firmware.md

For full archive and BuildManifest-referenced component hashes:

    python3 tools/phoenix-inspector/phoenix_inspector.py inspect firmware.ipsw \
      --hash-ipsw --hash-components --out reports/firmware.json

Compare two previously generated reports:

    python3 tools/phoenix-inspector/phoenix_inspector.py compare \
      reports/se.json reports/ipad5.json --out reports/se-vs-ipad5.json

## Captured data

- Product version/build, supported product types/devices
- Build identity device classes, variants, restore behaviors
- Component names and archive paths referenced by BuildManifest
- ZIP member paths, sizes and compression methods
- SHA-256 of BuildManifest, optionally whole IPSW and referenced components

## Safety boundary

The tool does not extract files, decrypt IMG4, mount DMGs, patch firmware, invoke restore utilities, or contact a device. It rejects unsafe ZIP paths. Metadata presence is not proof of hardware compatibility. Do not commit IPSWs, extracted proprietary firmware, or private keys.

IMG4 parsing, kernelcache parsing, Device Tree extraction, Mach-O analysis and kext dependency resolution are future milestones, not implemented capabilities.
