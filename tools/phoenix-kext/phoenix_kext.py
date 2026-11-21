#!/usr/bin/env python3
"""Phoenix Kext Dependency Analyzer: read-only inventory of local .kext bundles."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import plistlib
import sys
from pathlib import Path

MAX_PLIST_BYTES = 16 * 1024 * 1024
INFO_PLIST = "Info.plist"

class KextError(ValueError):
    pass

def safe_text(value):
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)

def load_info(path):
    try:
        size = path.stat().st_size
        if size > MAX_PLIST_BYTES:
            raise KextError("Info.plist exceeds 16 MiB safety limit: %s" % path)
        raw = path.read_bytes()
        info = plistlib.loads(raw)
    except KextError:
        raise
    except (OSError, plistlib.InvalidFileException, ValueError) as exc:
        raise KextError("Cannot parse %s: %s" % (path, exc)) from exc
    if not isinstance(info, dict):
        raise KextError("Info.plist root is not a dictionary: %s" % path)
    return info, raw

def discover_bundles(root):
    found = []
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if not os.path.islink(os.path.join(current, d)))
        if current.lower().endswith(".kext"):
            found.append(Path(current))
            dirs[:] = []
    return sorted(found, key=lambda p: str(p).lower())

def analyze(root):
    root = Path(root)
    if not root.exists() or not root.is_dir():
        raise KextError("Input must be an existing directory containing .kext bundles")
    bundles = []
    seen_ids = {}
    for bundle in discover_bundles(root):
        info_path = bundle / INFO_PLIST
        if not info_path.is_file():
            bundles.append({
                "path": str(bundle.relative_to(root)),
                "bundle_id": None,
                "valid": False,
                "error": "Info.plist not found",
                "dependencies": {},
            })
            continue
        info, raw = load_info(info_path)
        bundle_id = info.get("CFBundleIdentifier")
        if not isinstance(bundle_id, str) or not bundle_id.strip():
            bundle_id = None
        dependencies = info.get("OSBundleLibraries", {})
        if not isinstance(dependencies, dict):
            dependencies = {}
            dependency_warning = "OSBundleLibraries is not a dictionary"
        else:
            dependency_warning = None
        normalized_deps = {
            str(key): safe_text(value)
            for key, value in sorted(dependencies.items(), key=lambda item: str(item[0]))
        }
        record = {
            "path": str(bundle.relative_to(root)),
            "bundle_id": bundle_id,
            "name": safe_text(info.get("CFBundleName")),
            "executable": safe_text(info.get("CFBundleExecutable")),
            "version": safe_text(info.get("CFBundleVersion")),
            "short_version": safe_text(info.get("CFBundleShortVersionString")),
            "package_type": safe_text(info.get("CFBundlePackageType")),
            "supported_platforms": info.get("CFBundleSupportedPlatforms", []),
            "required": safe_text(info.get("OSBundleRequired")),
            "dependencies": normalized_deps,
            "info_plist_sha256": hashlib.sha256(raw).hexdigest(),
            "valid": bundle_id is not None,
        }
        if dependency_warning:
            record["warning"] = dependency_warning
        if bundle_id:
            seen_ids.setdefault(bundle_id, []).append(record["path"])
        bundles.append(record)

    edges = []
    unresolved = []
    for bundle in bundles:
        if not bundle.get("valid"):
            continue
        for dependency_id, version in bundle["dependencies"].items():
            providers = seen_ids.get(dependency_id, [])
            edge = {
                "consumer": bundle["bundle_id"],
                "dependency": dependency_id,
                "required_version": version,
                "provider_paths": providers,
                "resolved": bool(providers),
            }
            edges.append(edge)
            if not providers:
                unresolved.append(edge)

    duplicates = [
        {"bundle_id": bundle_id, "paths": paths}
        for bundle_id, paths in sorted(seen_ids.items()) if len(paths) > 1
    ]
    return {
        "schema_version": 1,
        "tool": "Phoenix Kext Dependency Analyzer",
        "root": str(root),
        "bundle_count": len(bundles),
        "valid_bundle_count": sum(1 for b in bundles if b.get("valid")),
        "invalid_bundle_count": sum(1 for b in bundles if not b.get("valid")),
        "dependency_count": len(edges),
        "resolved_dependency_count": sum(1 for e in edges if e["resolved"]),
        "unresolved_dependency_count": len(unresolved),
        "duplicate_bundle_id_count": len(duplicates),
        "bundles": bundles,
        "dependencies": edges,
        "unresolved_dependencies": unresolved,
        "duplicate_bundle_ids": duplicates,
        "limitations": [
            "Reads local .kext bundle Info.plist metadata only; it does not parse kernel binaries.",
            "Dependency resolution is by CFBundleIdentifier presence in the scanned directory, not ABI or version compatibility.",
            "OSBundleLibraries version constraints are reported but not evaluated.",
            "Does not inspect DriverKit .dext bundles, executable code, signatures, entitlements or kernel symbols.",
            "A resolved dependency is not proof that a kext can load on the target device.",
            "Read-only: no bundle or firmware files are modified."
        ]
    }

def main(argv=None):
    parser = argparse.ArgumentParser(description="Inventory .kext metadata and OSBundleLibraries dependencies")
    parser.add_argument("root", type=Path, help="Directory containing extracted .kext bundles")
    parser.add_argument("--out", type=Path, default=Path("phoenix-kext-report.json"))
    args = parser.parse_args(argv)
    try:
        report = analyze(args.root)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print("Bundles:", report["bundle_count"])
        print("Dependencies:", report["dependency_count"])
        print("Resolved:", report["resolved_dependency_count"])
        print("Unresolved:", report["unresolved_dependency_count"])
        print("Report written:", args.out)
        return 0
    except (OSError, KextError) as exc:
        print("phoenix-kext: error:", exc, file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
