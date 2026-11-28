#!/usr/bin/env python3
"""Normalize researcher-supplied A9 platform evidence without inventing hardware facts.

This is an offline evidence collector, not a privileged device probe. It parses
small text/JSON evidence exports and records source hashes and provenance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
TOOL_NAME = "Phoenix A9 Platform Evidence Collector"
ALLOWED_KINDS = {"cpu_registers", "cpuinfo", "device_tree_summary", "kernel_config"}
REGISTER_NAMES = {
    "MIDR_EL1", "MPIDR_EL1", "ID_AA64PFR0_EL1", "ID_AA64PFR1_EL1",
    "ID_AA64ISAR0_EL1", "ID_AA64ISAR1_EL1", "ID_AA64MMFR0_EL1",
    "ID_AA64MMFR1_EL1", "CTR_EL0", "CLIDR_EL1", "PMCR_EL0",
    "CNTFRQ_EL0",
}
CPUINFO_KEYS = {
    "processor", "model name", "cpu implementer", "cpu architecture",
    "cpu variant", "cpu part", "cpu revision", "features",
}
DT_KEYS = {"compatible", "model", "cpu_count", "cpu_nodes", "interrupt_parent", "address_cells", "size_cells"}
KCONFIG_KEYS = {"CONFIG_ARM64", "CONFIG_ARM64_4K_PAGES", "CONFIG_ARM64_16K_PAGES", "CONFIG_SMP"}


class EvidenceError(ValueError):
    pass


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def read_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise EvidenceError(f"cannot read {path}: {exc}") from exc


def parse_scalar(value: str) -> Any:
    value = value.strip()
    if not value:
        return None
    if re.fullmatch(r"0[xX][0-9a-fA-F]+", value):
        return int(value, 16)
    if re.fullmatch(r"[0-9]+", value):
        return int(value, 10)
    if value.lower() in {"true", "false"}:
        return value.lower() == "true"
    return value


def parse_key_value_text(raw: bytes, allowed: set[str], label: str) -> tuple[dict[str, Any], list[str]]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EvidenceError(f"{label}: expected UTF-8 text: {exc}") from exc
    values: dict[str, Any] = {}
    warnings: list[str] = []
    for line_no, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if "=" in line:
            key, value = line.split("=", 1)
        elif ":" in line:
            key, value = line.split(":", 1)
        else:
            warnings.append(f"{label}:{line_no}: ignored line without key/value separator")
            continue
        key = key.strip()
        value = value.strip()
        if key not in allowed:
            warnings.append(f"{label}:{line_no}: ignored unrecognized key {key!r}")
            continue
        if key in values:
            warnings.append(f"{label}:{line_no}: duplicate key {key!r}; last value retained")
        values[key] = parse_scalar(value)
    return values, warnings


def parse_source(kind: str, raw: bytes, label: str) -> tuple[dict[str, Any], list[str]]:
    if kind == "cpu_registers":
        return parse_key_value_text(raw, REGISTER_NAMES, label)
    if kind == "cpuinfo":
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise EvidenceError(f"{label}: expected UTF-8 text: {exc}") from exc
        records: list[dict[str, Any]] = []
        current: dict[str, Any] = {}
        warnings: list[str] = []
        for line_no, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                if current:
                    records.append(current)
                    current = {}
                continue
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            key = key.strip().lower()
            if key not in CPUINFO_KEYS:
                continue
            if key in current:
                warnings.append(f"{label}:{line_no}: duplicate cpuinfo key {key!r}")
            current[key] = parse_scalar(value)
        if current:
            records.append(current)
        return {"processors": records}, warnings
    if kind in {"device_tree_summary", "kernel_config"}:
        allowed = DT_KEYS if kind == "device_tree_summary" else KCONFIG_KEYS
        return parse_key_value_text(raw, allowed, label)
    raise EvidenceError(f"unsupported evidence kind: {kind}")


def collect(manifest: dict[str, Any], base_dir: Path) -> dict[str, Any]:
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise EvidenceError(f"schema_version must be {SCHEMA_VERSION}")
    if manifest.get("tool") != "Phoenix A9 Platform Evidence Manifest":
        raise EvidenceError("manifest tool must be 'Phoenix A9 Platform Evidence Manifest'")
    entries = manifest.get("sources")
    if not isinstance(entries, list) or not entries:
        raise EvidenceError("sources must be a non-empty array")

    sources: list[dict[str, Any]] = []
    evidence: dict[str, Any] = {
        "cpu_registers": {},
        "cpuinfo": {"processors": []},
        "device_tree_summary": {},
        "kernel_config": {},
    }
    warnings: list[str] = []
    seen_names: set[str] = set()

    for index, entry in enumerate(entries):
        label = f"sources[{index}]"
        if not isinstance(entry, dict):
            raise EvidenceError(f"{label}: expected an object")
        name, kind, path_value = entry.get("name"), entry.get("kind"), entry.get("path")
        if not isinstance(name, str) or not name.strip():
            raise EvidenceError(f"{label}: name must be a non-empty string")
        if name in seen_names:
            raise EvidenceError(f"{label}: duplicate source name {name!r}")
        seen_names.add(name)
        if kind not in ALLOWED_KINDS:
            raise EvidenceError(f"{label}: unsupported kind {kind!r}")
        if not isinstance(path_value, str) or not path_value.strip():
            raise EvidenceError(f"{label}: path must be a non-empty string")
        path = (base_dir / path_value).resolve()
        if not path.is_relative_to(base_dir.resolve()):
            raise EvidenceError(f"{label}: source path escapes manifest directory")
        raw = read_bytes(path)
        parsed, source_warnings = parse_source(kind, raw, name)
        warnings.extend(source_warnings)
        if kind == "cpuinfo":
            evidence[kind]["processors"].extend(parsed["processors"])
        else:
            for key, value in parsed.items():
                if key in evidence[kind] and key in evidence[kind]:
                    if key in evidence[kind]:
                        warnings.append(f"{name}: repeated evidence key {key!r}; later source retained")
                evidence[kind][key] = value
        provenance = entry.get("provenance", {})
        if not isinstance(provenance, dict):
            raise EvidenceError(f"{label}: provenance must be an object")
        source_hash = sha256(raw)
        expected_hash = entry.get("sha256")
        if expected_hash is not None and expected_hash != source_hash:
            raise EvidenceError(f"{label}: SHA-256 mismatch")
        sources.append({
            "name": name,
            "kind": kind,
            "path": path_value,
            "sha256": source_hash,
            "hash_verified_against_manifest": expected_hash is not None,
            "provenance": {
                "origin": provenance.get("origin"),
                "device": provenance.get("device"),
                "firmware_build": provenance.get("firmware_build"),
                "collection_method": provenance.get("collection_method"),
                "collector_version": provenance.get("collector_version"),
                "captured_at": provenance.get("captured_at"),
            },
        })

    observed = {
        "cpu_register_names": sorted(evidence["cpu_registers"]),
        "cpuinfo_processor_records": len(evidence["cpuinfo"]["processors"]),
        "device_tree_keys": sorted(evidence["device_tree_summary"]),
        "kernel_config_keys": sorted(evidence["kernel_config"]),
    }
    missing = []
    if not evidence["cpu_registers"]:
        missing.append("cpu_registers")
    if not evidence["cpuinfo"]["processors"]:
        missing.append("cpuinfo")
    if not evidence["device_tree_summary"]:
        missing.append("device_tree_summary")
    if not evidence["kernel_config"]:
        missing.append("kernel_config")
    status = "incomplete" if missing or warnings else "collected"
    return {
        "schema_version": 1,
        "tool": TOOL_NAME,
        "status": status,
        "target_profile": {"device": "iPhone SE (1st generation)", "product_type": "iPhone8,4", "board": "n69", "soc": "A9"},
        "observed": observed,
        "missing_evidence_groups": missing,
        "sources": sources,
        "evidence": evidence,
        "warnings": warnings,
        "limitations": [
            "This tool parses researcher-supplied evidence exports; it does not access hardware registers or probe an iPhone.",
            "A source hash proves byte identity only, not authenticity, correctness, device origin, or capture method.",
            "CPU register values are not decoded into architectural feature claims by this version.",
            "DeviceTree input is a summary key/value export, not a raw DTB parser or validator.",
            "Kernel configuration values are recorded as supplied and are not proof of the active kernel configuration.",
            "No missing hardware value is inferred from the device model or SoC name.",
            "Collected evidence does not establish kernel, driver, boot, restore, or iOS compatibility."
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Normalize offline A9 CPU and platform evidence exports")
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--out", type=Path, default=Path("phoenix-a9-platform-evidence.json"))
    args = parser.parse_args(argv)
    try:
        raw = read_bytes(args.manifest)
        manifest = json.loads(raw.decode("utf-8"))
        if not isinstance(manifest, dict):
            raise EvidenceError("manifest root must be an object")
        report = collect(manifest, args.manifest.resolve().parent)
        report["manifest_sha256"] = sha256(raw)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("A9 evidence status:", report["status"])
        print("Sources:", len(report["sources"]))
        print("Missing groups:", ", ".join(report["missing_evidence_groups"]) or "none")
        print("Report written:", args.out)
        return 0 if report["status"] == "collected" else 1
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, EvidenceError) as exc:
        print("phoenix-a9-evidence: error:", exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
