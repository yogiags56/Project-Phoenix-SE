#!/usr/bin/env python3
"""Phoenix Firmware Compatibility Mapper: conservative comparison of Phoenix JSON reports."""
from __future__ import annotations
import argparse
import hashlib
import json
import sys
from pathlib import Path

REPORT_GLOBS = ("*.json",)
ARCH_KEYS = {"cpu_type", "cputype", "cpu"}
ID_KEYS = {"bundle_id", "identifier", "component", "component_name", "component_path", "path"}
VERSION_KEYS = {"product_version", "product_build_version", "build_version", "version", "short_version"}

class MapperError(ValueError):
    pass

def load_reports(root):
    root = Path(root)
    if not root.exists() or not root.is_dir():
        raise MapperError("Report input must be an existing directory: %s" % root)
    paths = sorted(p for p in root.rglob("*.json") if p.is_file())
    reports = []
    for path in paths:
        try:
            raw = path.read_bytes()
            obj = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise MapperError("Cannot read JSON report %s: %s" % (path, exc)) from exc
        if not isinstance(obj, dict):
            raise MapperError("Report root must be a JSON object: %s" % path)
        reports.append({
            "path": str(path.relative_to(root)),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "data": obj,
        })
    if not reports:
        raise MapperError("No JSON reports found under %s" % root)
    return reports

def walk(value, parent_key=""):
    if isinstance(value, dict):
        for key, child in value.items():
            yield from walk(child, str(key).lower())
    elif isinstance(value, list):
        for child in value:
            yield from walk(child, parent_key)
    else:
        yield parent_key, value

def inventory(reports):
    architectures = set()
    identifiers = set()
    versions = set()
    products = set()
    report_tools = set()
    evidence = []
    for report in reports:
        data = report["data"]
        tool = data.get("tool")
        if isinstance(tool, str):
            report_tools.add(tool)
        for key, value in walk(data):
            if key in ARCH_KEYS and isinstance(value, int) and not isinstance(value, bool):
                architectures.add(value)
            if key in ID_KEYS and isinstance(value, str) and value.strip():
                identifiers.add(value.strip())
            if key in VERSION_KEYS and isinstance(value, (str, int, float)) and not isinstance(value, bool):
                versions.add(str(value))
        for key in ("supported_product_types", "supported_devices"):
            value = data.get(key, [])
            if isinstance(value, list):
                products.update(str(x) for x in value if isinstance(x, (str, int)))
        evidence.append({
            "report": report["path"],
            "tool": tool,
            "sha256": report["sha256"],
        })
    return {
        "architectures": architectures,
        "identifiers": identifiers,
        "versions": versions,
        "products": products,
        "tools": report_tools,
        "evidence": evidence,
    }

def sorted_numeric(values):
    return sorted(values)

def compare(target_reports, donor_reports):
    target = inventory(target_reports)
    donor = inventory(donor_reports)
    shared_arch = target["architectures"] & donor["architectures"]
    target_arch_only = target["architectures"] - donor["architectures"]
    donor_arch_only = donor["architectures"] - target["architectures"]
    shared_ids = target["identifiers"] & donor["identifiers"]
    target_ids_only = target["identifiers"] - donor["identifiers"]
    donor_ids_only = donor["identifiers"] - target["identifiers"]
    arch_conflict = bool(target["architectures"] and donor["architectures"] and not shared_arch)
    if arch_conflict:
        status = "Incompatible"
        rationale = "No CPU architecture value is shared between the supplied target and donor reports."
    elif shared_arch or shared_ids:
        status = "Potential"
        rationale = "Some architecture or component identifiers overlap; this is a research lead, not proof of compatibility."
    else:
        status = "Unknown"
        rationale = "The supplied reports contain no comparable positive architecture or component-identifier evidence."
    return {
        "schema_version": 1,
        "tool": "Phoenix Firmware Compatibility Mapper",
        "status": status,
        "rationale": rationale,
        "target": {
            "report_count": len(target_reports),
            "tools": sorted(target["tools"]),
            "evidence": target["evidence"],
            "architectures": sorted_numeric(target["architectures"]),
            "identifier_count": len(target["identifiers"]),
            "product_types_or_devices": sorted(target["products"]),
            "versions": sorted(target["versions"]),
        },
        "donor": {
            "report_count": len(donor_reports),
            "tools": sorted(donor["tools"]),
            "evidence": donor["evidence"],
            "architectures": sorted_numeric(donor["architectures"]),
            "identifier_count": len(donor["identifiers"]),
            "product_types_or_devices": sorted(donor["products"]),
            "versions": sorted(donor["versions"]),
        },
        "comparison": {
            "shared_architectures": sorted_numeric(shared_arch),
            "target_only_architectures": sorted_numeric(target_arch_only),
            "donor_only_architectures": sorted_numeric(donor_arch_only),
            "shared_identifiers": sorted(shared_ids),
            "target_only_identifiers": sorted(target_ids_only),
            "donor_only_identifiers": sorted(donor_ids_only),
            "same_version_strings": sorted(target["versions"] & donor["versions"]),
            "target_product_types_or_devices_also_listed_by_donor": sorted(target["products"] & donor["products"]),
        },
        "limitations": [
            "This mapper compares metadata extracted into Phoenix JSON reports; it does not inspect raw firmware.",
            "Identifier overlap means only that strings match; it does not prove identical binary contents or behavior.",
            "Architecture overlap does not establish ABI, kernel API, device-tree, driver, SEP, baseband, Cryptex or userspace compatibility.",
            "Version strings are displayed for context and are not treated as compatibility evidence.",
            "Incompatible is emitted only when both sides declare CPU architecture values and the sets do not overlap.",
            "Potential is not a compatibility verdict. Unknown means the supplied reports do not provide enough comparable evidence.",
            "No firmware is modified, signed, executed or restored."
        ],
    }

def main(argv=None):
    parser = argparse.ArgumentParser(description="Conservatively compare Phoenix JSON inventories for target and donor firmware")
    parser.add_argument("--target", type=Path, required=True, help="Directory containing target-side Phoenix JSON reports")
    parser.add_argument("--donor", type=Path, required=True, help="Directory containing donor-side Phoenix JSON reports")
    parser.add_argument("--out", type=Path, default=Path("phoenix-compatibility-report.json"))
    args = parser.parse_args(argv)
    try:
        target_reports = load_reports(args.target)
        donor_reports = load_reports(args.donor)
        report = compare(target_reports, donor_reports)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("Compatibility indication:", report["status"])
        print("Shared architectures:", len(report["comparison"]["shared_architectures"]))
        print("Shared identifiers:", len(report["comparison"]["shared_identifiers"]))
        print("Report written:", args.out)
        return 0
    except (OSError, MapperError) as exc:
        print("phoenix-compat: error:", exc, file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
