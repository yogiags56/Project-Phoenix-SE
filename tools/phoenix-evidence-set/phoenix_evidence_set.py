#!/usr/bin/env python3
"""Validate provenance and exact-build consistency for Phoenix evidence sets.

This tool validates report files against a researcher-authored manifest. It does
not infer firmware identity from arbitrary report fields and does not determine
kernel, ABI, or hardware compatibility.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
ROLES = {"target", "donor"}
IDENTITY_FIELDS = (
    "product_type",
    "product_version",
    "build_version",
    "build_train",
    "board_identity",
)


class EvidenceSetError(ValueError):
    pass


def load_json(path: Path) -> tuple[dict[str, Any], str]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceSetError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise EvidenceSetError(f"{path}: JSON root must be an object")
    return value, hashlib.sha256(raw).hexdigest()


def normalized_identity(value: Any, label: str, errors: list[str]) -> dict[str, str | None]:
    if not isinstance(value, dict):
        errors.append(f"{label}: identity must be an object")
        return {field: None for field in IDENTITY_FIELDS}
    result: dict[str, str | None] = {}
    for field in IDENTITY_FIELDS:
        item = value.get(field)
        if item is not None and (not isinstance(item, str) or not item.strip()):
            errors.append(f"{label}: identity.{field} must be a non-empty string or null")
            result[field] = None
        else:
            result[field] = item.strip() if isinstance(item, str) else None
    return result


def report_identity(report: dict[str, Any]) -> dict[str, Any] | None:
    """Only consume the explicitly documented firmware_identity field."""
    value = report.get("firmware_identity")
    return value if isinstance(value, dict) else None


def validate_set(role: str, spec: Any, base_dir: Path) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    if not isinstance(spec, dict):
        return {"role": role, "status": "invalid", "errors": [f"{role}: evidence set must be an object"]}
    if spec.get("role") != role:
        errors.append(f"{role}: role field must equal {role!r}")

    identity = normalized_identity(spec.get("identity", {}), role, errors)
    missing_identity = [field for field, value in identity.items() if value is None]
    if missing_identity:
        warnings.append("missing identity fields: " + ", ".join(missing_identity))

    reports = spec.get("reports")
    if not isinstance(reports, list) or not reports:
        errors.append(f"{role}: reports must be a non-empty array")
        reports = []

    checked_reports: list[dict[str, Any]] = []
    observed_identities: list[tuple[str, dict[str, str | None]]] = []
    seen_names: set[str] = set()

    for index, entry in enumerate(reports):
        label = f"{role}.reports[{index}]"
        if not isinstance(entry, dict):
            errors.append(f"{label}: report entry must be an object")
            continue
        name = entry.get("name")
        path_value = entry.get("path")
        expected_tool = entry.get("expected_tool")
        expected_sha = entry.get("sha256")
        if not isinstance(name, str) or not name.strip():
            errors.append(f"{label}: name must be a non-empty string")
            name = f"report-{index}"
        if name in seen_names:
            errors.append(f"{label}: duplicate report name {name!r}")
        seen_names.add(name)
        if not isinstance(path_value, str) or not path_value.strip():
            errors.append(f"{label}: path must be a non-empty string")
            continue
        if not isinstance(expected_tool, str) or not expected_tool.strip():
            errors.append(f"{label}: expected_tool must be a non-empty string")
            continue
        if not isinstance(expected_sha, str) or len(expected_sha) != 64:
            errors.append(f"{label}: sha256 must be a 64-character hex digest")
            continue
        try:
            int(expected_sha, 16)
        except ValueError:
            errors.append(f"{label}: sha256 must contain hexadecimal characters only")
            continue

        report_path = (base_dir / path_value).resolve()
        if not report_path.is_relative_to(base_dir.resolve()):
            errors.append(f"{label}: report path escapes the manifest directory")
            continue
        try:
            report, actual_sha = load_json(report_path)
        except EvidenceSetError as exc:
            errors.append(f"{label}: {exc}")
            continue
        if actual_sha.lower() != expected_sha.lower():
            errors.append(f"{label}: SHA-256 mismatch (expected {expected_sha.lower()}, got {actual_sha})")
        actual_tool = report.get("tool")
        if actual_tool != expected_tool:
            errors.append(f"{label}: tool mismatch (expected {expected_tool!r}, got {actual_tool!r})")

        observed = report_identity(report)
        if observed is not None:
            report_id = normalized_identity(observed, label + ".firmware_identity", errors)
            observed_identities.append((str(name), report_id))
            report_missing = [field for field, value in report_id.items() if value is None]
            if report_missing:
                warnings.append(
                    f"{label}: firmware_identity is missing fields: " + ", ".join(report_missing)
                )
            for field in IDENTITY_FIELDS:
                declared = identity[field]
                found = report_id[field]
                if declared is not None and found is not None and declared != found:
                    errors.append(
                        f"{label}: firmware_identity.{field} mismatch "
                        f"(manifest {declared!r}, report {found!r})"
                    )
        else:
            warnings.append(f"{label}: report has no explicit firmware_identity object")

        checked_reports.append({
            "name": name,
            "path": path_value,
            "expected_tool": expected_tool,
            "expected_sha256": expected_sha.lower(),
            "actual_sha256": actual_sha,
            "tool_matches": actual_tool == expected_tool,
            "firmware_identity_present": observed is not None,
        })

    # Compare identity fields only when both reports explicitly provide them.
    for i, (name_a, id_a) in enumerate(observed_identities):
        for name_b, id_b in observed_identities[i + 1:]:
            for field in IDENTITY_FIELDS:
                a, b = id_a[field], id_b[field]
                if a is not None and b is not None and a != b:
                    errors.append(
                        f"{role}: report identity conflict for {field}: "
                        f"{name_a}={a!r}, {name_b}={b!r}"
                    )

    status = "invalid" if errors else ("incomplete" if warnings or missing_identity else "valid")
    return {
        "role": role,
        "status": status,
        "identity": identity,
        "missing_identity_fields": missing_identity,
        "reports": checked_reports,
        "warnings": warnings,
        "errors": errors,
    }


def validate_manifest(manifest: dict[str, Any], base_dir: Path) -> dict[str, Any]:
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise EvidenceSetError(f"schema_version must be {SCHEMA_VERSION}")
    if manifest.get("tool") != "Phoenix Evidence Set Validator Manifest":
        raise EvidenceSetError("tool must be 'Phoenix Evidence Set Validator Manifest'")
    sets = manifest.get("evidence_sets")
    if not isinstance(sets, dict):
        raise EvidenceSetError("evidence_sets must be an object")

    results = {role: validate_set(role, sets.get(role), base_dir) for role in sorted(ROLES)}
    statuses = [item["status"] for item in results.values()]
    overall = "invalid" if "invalid" in statuses else ("incomplete" if "incomplete" in statuses else "valid")
    return {
        "schema_version": 1,
        "tool": "Phoenix Evidence Set Validator",
        "status": overall,
        "evidence_sets": results,
        "limitations": [
            "Valid means manifest hashes, declared tool names, and available identity fields are internally consistent; it is not proof of firmware authenticity.",
            "Missing identity is reported as incomplete, not guessed or treated as a proven mismatch.",
            "Target and donor identities are validated independently; their build identifiers are not expected to match each other.",
            "Only an explicit report firmware_identity object is compared with the manifest.",
            "This tool does not inspect raw firmware, validate signatures, assess ABI, kernel API, CPU features, driver loadability, or hardware compatibility.",
            "A valid evidence set is provenance hygiene, not a kernel compatibility verdict.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate exact-build provenance for Phoenix target/donor reports")
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--out", type=Path, default=Path("phoenix-evidence-set-report.json"))
    args = parser.parse_args(argv)
    try:
        manifest, _ = load_json(args.manifest)
        report = validate_manifest(manifest, args.manifest.resolve().parent)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("Evidence set status:", report["status"])
        for role, result in report["evidence_sets"].items():
            print(f"{role}: {result['status']} ({len(result['reports'])} reports)")
        print("Report written:", args.out)
        return 0 if report["status"] == "valid" else 1
    except (OSError, EvidenceSetError) as exc:
        print("phoenix-evidence-set: error:", exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
