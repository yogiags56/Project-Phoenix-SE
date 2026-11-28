#!/usr/bin/env python3
"""Build a small, sanitized, metadata-only Phoenix evidence bundle.

The tool deliberately refuses firmware images and binary payloads. It packages
only explicitly listed text/JSON reports so large IPSWs remain on the researcher's
local machine.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

TOOL = "Phoenix Evidence Bundle Builder"
SCHEMA_VERSION = 1
ALLOWED_SUFFIXES = {".json", ".txt", ".md", ".csv", ".log", ".yaml", ".yml"}
DEFAULT_MAX_FILE = 2 * 1024 * 1024
DEFAULT_MAX_TOTAL = 10 * 1024 * 1024
SENSITIVE_PATTERNS = [
    re.compile(r"(?i)\b(?:ECID|UDID|IMEI|MEID|SERIAL(?:_NUMBER)?)\s*[:=]\s*[^\s,;]+"),
    re.compile(r"(?i)\b(?:wifi|wi-fi|bluetooth)[ _-]?mac\s*[:=]\s*(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}"),
]


class BundleError(ValueError):
    pass


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_manifest(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BundleError(f"cannot read manifest: {exc}") from exc
    if not isinstance(value, dict):
        raise BundleError("manifest root must be an object")
    if value.get("schema_version") != SCHEMA_VERSION or value.get("tool") != "Phoenix Evidence Bundle Manifest":
        raise BundleError("unsupported manifest schema or tool name")
    entries = value.get("files")
    if not isinstance(entries, list) or not entries:
        raise BundleError("manifest files must be a non-empty array")
    return value


def inspect_entry(entry: Any, base: Path, max_file: int) -> tuple[str, bytes, dict[str, Any]]:
    if not isinstance(entry, dict):
        raise BundleError("each file entry must be an object")
    label = entry.get("name")
    rel = entry.get("path")
    if not isinstance(label, str) or not label.strip():
        raise BundleError("each file entry needs a non-empty name")
    if not isinstance(rel, str) or not rel.strip():
        raise BundleError(f"{label}: path must be a non-empty string")
    source = (base / rel).resolve()
    if not source.is_relative_to(base.resolve()):
        raise BundleError(f"{label}: path escapes manifest directory")
    if source.suffix.lower() not in ALLOWED_SUFFIXES:
        raise BundleError(f"{label}: refused file type {source.suffix or '(no extension)'}; firmware and binary files are not allowed")
    try:
        if source.is_symlink() or not source.is_file():
            raise BundleError(f"{label}: source must be a regular file, not a symlink")
        raw = source.read_bytes()
    except OSError as exc:
        raise BundleError(f"{label}: cannot read source: {exc}") from exc
    if len(raw) > max_file:
        raise BundleError(f"{label}: file is {len(raw)} bytes; per-file limit is {max_file}")
    if b"\x00" in raw:
        raise BundleError(f"{label}: binary-looking content refused")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BundleError(f"{label}: only UTF-8 text reports can be bundled: {exc}") from exc
    matches = [pattern.search(text) for pattern in SENSITIVE_PATTERNS]
    if any(matches):
        raise BundleError(f"{label}: possible device identifier or hardware address found; sanitize locally before bundling")
    arcname = PurePosixPath("reports") / Path(rel).name
    metadata = {
        "name": label,
        "source_path": rel,
        "bundle_path": str(arcname),
        "bytes": len(raw),
        "sha256": digest(raw),
        "description": entry.get("description"),
        "classification": entry.get("classification", "research-report"),
    }
    return str(arcname), raw, metadata


def build(manifest_path: Path, output: Path, max_file: int, max_total: int) -> dict[str, Any]:
    manifest = load_manifest(manifest_path)
    base = manifest_path.resolve().parent
    prepared = []
    seen_names: set[str] = set()
    seen_paths: set[str] = set()
    total = 0
    for entry in manifest["files"]:
        arcname, raw, metadata = inspect_entry(entry, base, max_file)
        if metadata["name"] in seen_names:
            raise BundleError(f"duplicate report name: {metadata['name']}")
        if metadata["bundle_path"] in seen_paths:
            raise BundleError(f"duplicate bundle filename: {metadata['bundle_path']}")
        seen_names.add(metadata["name"])
        seen_paths.add(metadata["bundle_path"])
        total += len(raw)
        if total > max_total:
            raise BundleError(f"bundle would exceed total limit of {max_total} bytes")
        prepared.append((arcname, raw, metadata))

    bundle_manifest = {
        "schema_version": 1,
        "tool": TOOL,
        "project": "Project Phoenix SE",
        "purpose": "metadata-only research handoff; source firmware remains local",
        "target": manifest.get("target"),
        "donor": manifest.get("donor"),
        "reports": [item[2] for item in prepared],
        "limits": {
            "allowed_suffixes": sorted(ALLOWED_SUFFIXES),
            "max_file_bytes": max_file,
            "max_total_bytes": max_total,
            "raw_firmware_included": False,
        },
        "limitations": [
            "Hashes identify the included report bytes; they do not authenticate the firmware or report origin.",
            "Review every report for personal or device-identifying information before sharing.",
            "No IPSW, IMG4, IM4P, kernelcache, DeviceTree binary, executable, or other raw firmware payload is included.",
            "The bundle is an analysis handoff, not proof of compatibility."
        ]
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
            for arcname, raw, _ in prepared:
                archive.writestr(arcname, raw)
            archive.writestr("bundle-manifest.json", json.dumps(bundle_manifest, indent=2, sort_keys=True) + "\n")
    except OSError as exc:
        raise BundleError(f"cannot write output bundle: {exc}") from exc
    bundle_manifest["bundle_sha256"] = digest(output.read_bytes())
    return bundle_manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package selected small Phoenix text/JSON reports; never package firmware")
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--out", type=Path, default=Path("phoenix-evidence-bundle.zip"))
    parser.add_argument("--max-file-mb", type=float, default=2.0)
    parser.add_argument("--max-total-mb", type=float, default=10.0)
    args = parser.parse_args(argv)
    try:
        if args.max_file_mb <= 0 or args.max_total_mb <= 0:
            raise BundleError("size limits must be positive")
        report = build(args.manifest, args.out, int(args.max_file_mb * 1024 * 1024), int(args.max_total_mb * 1024 * 1024))
        print("Bundle created:", args.out)
        print("Reports:", len(report["reports"]))
        print("Bundle SHA-256:", report["bundle_sha256"])
        print("Raw firmware included: no")
        return 0
    except (BundleError, OSError) as exc:
        print("phoenix-evidence-bundle:", exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
