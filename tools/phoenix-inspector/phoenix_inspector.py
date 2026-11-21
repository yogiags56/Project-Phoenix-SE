#!/usr/bin/env python3
"""Read-only IPSW metadata inspector. Python 3.10+, standard library only."""
from __future__ import annotations
import argparse, hashlib, json, plistlib, sys, zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def safe_archive_name(name: str) -> bool:
    p = PurePosixPath(name)
    return not p.is_absolute() and ".." not in p.parts and "\\" not in name

def load_manifest(z: zipfile.ZipFile):
    names = [n for n in z.namelist() if PurePosixPath(n).name == "BuildManifest.plist"]
    if len(names) != 1:
        raise ValueError(f"Expected exactly one BuildManifest.plist; found {len(names)}")
    raw = z.read(names[0])
    obj = plistlib.loads(raw)
    if not isinstance(obj, dict):
        raise ValueError("BuildManifest.plist root must be a dictionary")
    return obj, sha256_bytes(raw)

def identities(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    result = []
    for i, identity in enumerate(manifest.get("BuildIdentities", [])):
        info = identity.get("Info", {})
        components = []
        for name, entry in sorted(identity.get("Manifest", {}).items()):
            if not isinstance(entry, dict):
                continue
            meta = entry.get("Info", {}) or {}
            components.append({
                "component": name,
                "path": meta.get("Path") or entry.get("Path"),
                "digest_present": bool(entry.get("Digest")),
                "trusted": entry.get("Trusted"),
            })
        result.append({
            "index": i, "device_class": info.get("DeviceClass"),
            "variant": info.get("Variant"),
            "restore_behavior": info.get("RestoreBehavior"),
            "components": components,
        })
    return result

def inspect_ipsw(path: Path, hash_ipsw: bool = False, hash_components: bool = False):
    if not path.is_file():
        raise FileNotFoundError(path)
    if not zipfile.is_zipfile(path):
        raise ValueError(f"Not a readable ZIP/IPSW archive: {path}")
    with zipfile.ZipFile(path) as z:
        bad = z.testzip()
        if bad:
            raise ValueError(f"ZIP CRC check failed: {bad}")
        for name in z.namelist():
            if not safe_archive_name(name):
                raise ValueError(f"Unsafe archive member path: {name}")
        manifest, manifest_hash = load_manifest(z)
        members = [{
            "path": x.filename, "size": x.file_size,
            "compressed_size": x.compress_size,
            "compression": x.compress_type, "is_directory": x.is_dir()
        } for x in z.infolist()]
        component_hashes = {}
        if hash_components:
            paths = set()
            for ident in manifest.get("BuildIdentities", []):
                for entry in ident.get("Manifest", {}).values():
                    if isinstance(entry, dict):
                        meta = entry.get("Info", {}) or {}
                        p = meta.get("Path") or entry.get("Path")
                        if p:
                            paths.add(p)
            available = set(z.namelist())
            for p in sorted(paths & available):
                component_hashes[p] = sha256_bytes(z.read(p))
    return {
        "schema_version": 1, "tool": "Phoenix Firmware Inspector",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "source_file": path.name, "source_size": path.stat().st_size,
        "source_sha256": sha256_file(path) if hash_ipsw else None,
        "manifest_sha256": manifest_hash,
        "product_version": manifest.get("ProductVersion"),
        "product_build_version": manifest.get("ProductBuildVersion"),
        "supported_product_types": manifest.get("SupportedProductTypes", []),
        "supported_devices": manifest.get("SupportedDevices", []),
        "identity_count": len(manifest.get("BuildIdentities", [])),
        "build_identities": identities(manifest),
        "archive_member_count": len(members), "archive_members": members,
        "component_sha256": component_hashes,
        "limitations": [
            "Metadata-only: no IMG4 decryption or payload extraction.",
            "Manifest presence/digests do not prove runtime compatibility.",
            "No firmware is modified and no device is contacted."
        ],
    }

def markdown_report(r: dict[str, Any]) -> str:
    lines = [
        "# Phoenix Firmware Inspector Report", "",
        f"- Source: {r['source_file']}",
        f"- Size: {r['source_size']} bytes",
        f"- Product version: {r.get('product_version') or 'not declared'}",
        f"- Build: {r.get('product_build_version') or 'not declared'}",
        f"- Product types: {', '.join(r.get('supported_product_types') or [])}",
        f"- Build identities: {r['identity_count']}",
        f"- Archive members: {r['archive_member_count']}",
        f"- BuildManifest SHA-256: {r['manifest_sha256']}",
        f"- IPSW SHA-256: {r['source_sha256'] or 'not calculated'}", "",
        "## Build identities", "",
        "| Index | Device class | Variant | Restore behavior | Components |",
        "|---:|---|---|---|---:|",
    ]
    for x in r["build_identities"]:
        lines.append(f"| {x['index']} | {x.get('device_class') or ''} | {x.get('variant') or ''} | {x.get('restore_behavior') or ''} | {len(x['components'])} |")
    lines += ["", "## Component paths", ""]
    for x in r["build_identities"]:
        lines += [f"### Identity {x['index']}", "", "| Component | Path | Digest present | Trusted |", "|---|---|---:|---|"]
        for c in x["components"]:
            lines.append(f"| {c['component']} | {c.get('path') or ''} | {c['digest_present']} | {c.get('trusted')} |")
        lines.append("")
    lines += ["## Limitations", ""]
    lines.extend(f"- {x}" for x in r["limitations"])
    return "\n".join(lines) + "\n"

def compare_reports(a: dict[str, Any], b: dict[str, Any]):
    def keys(r):
        return {(str(x.get("device_class") or ""), str(x.get("variant") or ""), str(x.get("restore_behavior") or "")) for x in r.get("build_identities", [])}
    def components(r):
        return {c["component"] for x in r.get("build_identities", []) for c in x.get("components", [])}
    ak, bk, ac, bc = keys(a), keys(b), components(a), components(b)
    return {
        "schema_version": 1, "left": a.get("source_file"), "right": b.get("source_file"),
        "product_version": [a.get("product_version"), b.get("product_version")],
        "build_version": [a.get("product_build_version"), b.get("product_build_version")],
        "identity_keys_only_left": sorted(ak - bk),
        "identity_keys_only_right": sorted(bk - ak),
        "components_only_left": sorted(ac - bc),
        "components_only_right": sorted(bc - ac),
        "same_manifest_hash": a.get("manifest_sha256") == b.get("manifest_sha256"),
        "warning": "Metadata differences are not a compatibility verdict.",
    }

def write_json(data, path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")

def main(argv=None):
    p = argparse.ArgumentParser(description="Read-only IPSW metadata inventory and comparison")
    s = p.add_subparsers(dest="command", required=True)
    i = s.add_parser("inspect")
    i.add_argument("ipsw", type=Path); i.add_argument("--out", type=Path, default=Path("phoenix-report.json"))
    i.add_argument("--markdown", type=Path); i.add_argument("--hash-ipsw", action="store_true")
    i.add_argument("--hash-components", action="store_true")
    c = s.add_parser("compare")
    c.add_argument("left", type=Path); c.add_argument("right", type=Path)
    c.add_argument("--out", type=Path, default=Path("phoenix-diff.json"))
    a = p.parse_args(argv)
    try:
        if a.command == "inspect":
            report = inspect_ipsw(a.ipsw, a.hash_ipsw, a.hash_components)
            write_json(report, a.out)
            if a.markdown:
                a.markdown.parent.mkdir(parents=True, exist_ok=True)
                a.markdown.write_text(markdown_report(report), encoding="utf-8")
            print(f"Report written: {a.out}")
            if a.markdown: print(f"Markdown written: {a.markdown}")
        else:
            result = compare_reports(json.loads(a.left.read_text()), json.loads(a.right.read_text()))
            write_json(result, a.out); print(f"Comparison written: {a.out}")
        return 0
    except (OSError, ValueError, zipfile.BadZipFile, plistlib.InvalidFileException) as e:
        print(f"phoenix-inspector: error: {e}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
