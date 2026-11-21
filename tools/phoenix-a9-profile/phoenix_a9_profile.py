#!/usr/bin/env python3
"""Phoenix A9 Platform Profiler: validate and summarize evidence-backed device profiles."""
from __future__ import annotations
import argparse
import hashlib
import json
import sys
from pathlib import Path

STATUSES = {"not_assessed", "researching", "experimental", "partially_working", "working", "blocked"}
EVIDENCE_LEVELS = {"none", "reference_reported", "source_observed", "static_analysis", "device_tested"}
SUBSYSTEMS = (
    "boot_chain_restore", "kernel_device_tree", "cpu_arm64", "gpu_metal",
    "display", "touch", "audio", "camera_isp", "wifi", "bluetooth",
    "cellular_baseband", "sep_touch_id", "power_thermal", "sensors",
    "nfc_secure_element", "storage_apfs", "memory_pressure", "core_services",
    "springboard",
)
IDENTITY_FIELDS = ("product_type", "board_variant", "soc_variant", "model_number", "firmware_build")

class ProfileError(ValueError):
    pass

def read_json(path):
    try:
        raw = Path(path).read_bytes()
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProfileError("Cannot read JSON %s: %s" % (path, exc)) from exc
    if not isinstance(value, dict):
        raise ProfileError("Profile root must be a JSON object")
    return value, hashlib.sha256(raw).hexdigest()

def validate_profile(profile):
    if profile.get("schema_version") != 1:
        raise ProfileError("schema_version must be 1")
    if profile.get("profile_type") != "phoenix-a9-platform-profile":
        raise ProfileError("profile_type must be phoenix-a9-platform-profile")
    device = profile.get("device")
    if not isinstance(device, dict):
        raise ProfileError("device must be an object")
    if not isinstance(device.get("name"), str) or not device["name"].strip():
        raise ProfileError("device.name is required")
    identity = device.get("identity", {})
    if not isinstance(identity, dict):
        raise ProfileError("device.identity must be an object")
    for key in IDENTITY_FIELDS:
        item = identity.get(key)
        if item is not None and not isinstance(item, str):
            raise ProfileError("device.identity.%s must be a string or null" % key)
    subsystems = profile.get("subsystems")
    if not isinstance(subsystems, dict):
        raise ProfileError("subsystems must be an object")
    missing = sorted(set(SUBSYSTEMS) - set(subsystems))
    extra = sorted(set(subsystems) - set(SUBSYSTEMS))
    if missing:
        raise ProfileError("Missing subsystem entries: " + ", ".join(missing))
    if extra:
        raise ProfileError("Unknown subsystem entries: " + ", ".join(extra))
    normalized = []
    for name in SUBSYSTEMS:
        entry = subsystems[name]
        if not isinstance(entry, dict):
            raise ProfileError("subsystems.%s must be an object" % name)
        status = entry.get("status", "not_assessed")
        evidence_level = entry.get("evidence_level", "none")
        if status not in STATUSES:
            raise ProfileError("Invalid status for %s: %s" % (name, status))
        if evidence_level not in EVIDENCE_LEVELS:
            raise ProfileError("Invalid evidence_level for %s: %s" % (name, evidence_level))
        evidence = entry.get("evidence", [])
        if not isinstance(evidence, list):
            raise ProfileError("subsystems.%s.evidence must be an array" % name)
        for i, item in enumerate(evidence):
            if not isinstance(item, dict):
                raise ProfileError("Evidence %s[%d] must be an object" % (name, i))
            for field in ("description", "source"):
                if item.get(field) is not None and not isinstance(item[field], str):
                    raise ProfileError("%s evidence %d field %s must be a string" % (name, i, field))
        if status == "working":
            qualifying = [
                item for item in evidence
                if item.get("test_type") == "device_test"
                and all(isinstance(item.get(k), str) and item[k].strip()
                        for k in ("device", "build", "method", "result", "date"))
            ]
            if evidence_level != "device_tested" or not qualifying:
                raise ProfileError(
                    "%s cannot be marked working without device_test evidence "
                    "(device, build, method, result, date) and device_tested evidence_level" % name
                )
        normalized.append({
            "name": name,
            "status": status,
            "evidence_level": evidence_level,
            "evidence_count": len(evidence),
            "notes": entry.get("notes"),
        })
    return normalized

def build_report(profile, profile_sha256, source_name):
    rows = validate_profile(profile)
    counts = {status: sum(1 for row in rows if row["status"] == status) for status in sorted(STATUSES)}
    device = profile["device"]
    identity = device.get("identity", {})
    identity_complete = all(isinstance(identity.get(k), str) and identity[k].strip()
                            for k in IDENTITY_FIELDS)
    return {
        "schema_version": 1,
        "tool": "Phoenix A9 Platform Profiler",
        "source_profile": source_name,
        "source_profile_sha256": profile_sha256,
        "device": {
            "name": device["name"],
            "identity": identity,
            "identity_complete": identity_complete,
            "identity_missing_fields": [k for k in IDENTITY_FIELDS
                                        if not isinstance(identity.get(k), str) or not identity[k].strip()],
        },
        "subsystem_count": len(rows),
        "status_counts": counts,
        "device_tested_subsystem_count": sum(1 for row in rows if row["evidence_level"] == "device_tested"),
        "subsystems": rows,
        "interpretation": {
            "working_requires_device_test": True,
            "profile_is_not_a_compatibility_certificate": True,
            "identity_complete_means_all_identity_fields_are_recorded_not_independently_verified": True,
        },
        "limitations": [
            "The profiler validates evidence structure and summarizes user-supplied metadata; it does not inspect an iPhone or firmware.",
            "A complete identity record means fields are populated, not that the values have been independently verified.",
            "Reference-reported and source-observed evidence are not device tests.",
            "Working requires a dated device_test record with device, build, method and result.",
            "This tool does not infer compatibility, select donor firmware, patch, sign, execute or restore firmware.",
        ],
    }

def main(argv=None):
    parser = argparse.ArgumentParser(description="Validate and summarize a Phoenix A9 hardware evidence profile")
    parser.add_argument("profile", type=Path, help="JSON profile file")
    parser.add_argument("--out", type=Path, default=Path("phoenix-a9-profile-report.json"))
    args = parser.parse_args(argv)
    try:
        profile, digest = read_json(args.profile)
        report = build_report(profile, digest, args.profile.name)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("Device:", report["device"]["name"])
        print("Identity complete:", report["device"]["identity_complete"])
        print("Subsystems:", report["subsystem_count"])
        print("Device-tested:", report["device_tested_subsystem_count"])
        print("Report written:", args.out)
        return 0
    except (OSError, ProfileError) as exc:
        print("phoenix-a9-profile: error:", exc, file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
