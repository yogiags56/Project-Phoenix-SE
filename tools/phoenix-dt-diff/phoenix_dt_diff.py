#!/usr/bin/env python3
"""Phoenix Device Tree Comparator: compare two Phoenix FDT Analyzer JSON reports."""
from __future__ import annotations
import argparse
import hashlib
import json
import sys
from pathlib import Path

CRITICAL_PROPERTIES = {
    "compatible", "model", "device_type", "reg", "ranges", "interrupts",
    "interrupt-parent", "clocks", "clock-names", "resets", "reset-names",
    "power-domains", "iommus", "dma-ranges", "status", "phandle",
    "linux,phandle", "gpio-controller", "#gpio-cells", "gpios",
    "pinctrl-0", "pinctrl-names", "memory-region",
}

class CompareError(ValueError):
    pass

def load_report(path):
    try:
        raw = Path(path).read_bytes()
        report = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CompareError("Cannot read report %s: %s" % (path, exc)) from exc
    if not isinstance(report, dict):
        raise CompareError("Report root must be an object: %s" % path)
    if report.get("tool") != "Phoenix FDT Analyzer":
        raise CompareError("Expected a Phoenix FDT Analyzer report: %s" % path)
    nodes = report.get("node_index")
    if not isinstance(nodes, list) or not nodes:
        raise CompareError("Report has no non-empty node_index: %s" % path)
    index = {}
    for row in nodes:
        if not isinstance(row, dict) or not isinstance(row.get("path"), str):
            raise CompareError("Malformed node_index entry in %s" % path)
        node_path = row["path"]
        if node_path in index:
            raise CompareError("Duplicate node path %s in %s" % (node_path, path))
        props = row.get("properties", {})
        if not isinstance(props, dict):
            raise CompareError("Node properties must be an object: %s" % node_path)
        index[node_path] = row
    digest = hashlib.sha256(raw).hexdigest()
    return {"path": str(path), "sha256": digest, "report": report, "index": index}

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def property_value(value):
    if isinstance(value, dict) and "raw_hex" in value:
        return value["raw_hex"]
    return canonical(value)

def get_compatible(node):
    prop = node.get("properties", {}).get("compatible")
    if not isinstance(prop, dict):
        return []
    value = prop.get("value")
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [x for x in value if isinstance(x, str)]
    return []

def get_phandle(node):
    props = node.get("properties", {})
    for key in ("phandle", "linux,phandle"):
        value = props.get(key)
        if isinstance(value, dict):
            cells = value.get("u32_cells")
            if isinstance(cells, list) and len(cells) == 1 and isinstance(cells[0], int):
                return cells[0]
    return None

def compare(target, donor):
    ti, di = target["index"], donor["index"]
    target_paths, donor_paths = set(ti), set(di)
    shared_paths = target_paths & donor_paths
    added = sorted(donor_paths - target_paths)
    removed = sorted(target_paths - donor_paths)
    changed = []
    unchanged_count = 0
    compatible_matches = []
    critical_changes = []
    for path in sorted(shared_paths):
        tp, dp = ti[path].get("properties", {}), di[path].get("properties", {})
        tkeys, dkeys = set(tp), set(dp)
        prop_added, prop_removed, prop_changed = [], [], []
        for key in sorted(dkeys - tkeys):
            prop_added.append(key)
        for key in sorted(tkeys - dkeys):
            prop_removed.append(key)
        for key in sorted(tkeys & dkeys):
            if property_value(tp[key]) != property_value(dp[key]):
                prop_changed.append(key)
        if not (prop_added or prop_removed or prop_changed):
            unchanged_count += 1
        else:
            row = {
                "path": path,
                "properties_added_in_donor": prop_added,
                "properties_missing_from_donor": prop_removed,
                "properties_changed": prop_changed,
            }
            changed.append(row)
            critical = sorted((set(prop_added) | set(prop_removed) | set(prop_changed)) & CRITICAL_PROPERTIES)
            if critical:
                critical_changes.append({"path": path, "properties": critical})
        tc, dc = set(get_compatible(ti[path])), set(get_compatible(di[path]))
        if tc and dc and tc & dc:
            compatible_matches.append({
                "path": path,
                "shared_compatible_strings": sorted(tc & dc),
                "target_only": sorted(tc - dc),
                "donor_only": sorted(dc - tc),
            })

    target_handles = {}
    donor_handles = {}
    for path, node in ti.items():
        handle = get_phandle(node)
        if handle is not None:
            target_handles.setdefault(handle, []).append(path)
    for path, node in di.items():
        handle = get_phandle(node)
        if handle is not None:
            donor_handles.setdefault(handle, []).append(path)
    handle_changes = []
    for path in sorted(shared_paths):
        th, dh = get_phandle(ti[path]), get_phandle(di[path])
        if th != dh and (th is not None or dh is not None):
            handle_changes.append({"path": path, "target_phandle": th, "donor_phandle": dh})

    summary = {
        "target_node_count": len(ti),
        "donor_node_count": len(di),
        "shared_path_count": len(shared_paths),
        "nodes_added_in_donor": len(added),
        "nodes_missing_from_donor": len(removed),
        "nodes_with_property_differences": len(changed),
        "unchanged_shared_nodes": unchanged_count,
        "shared_compatible_node_count": len(compatible_matches),
        "critical_property_difference_count": len(critical_changes),
        "phandle_value_changes_on_shared_paths": len(handle_changes),
    }
    return {
        "schema_version": 1,
        "tool": "Phoenix Device Tree Comparator",
        "target": {"source_report": target["path"], "report_sha256": target["sha256"],
                   "fdt_sha256": target["report"].get("file_sha256")},
        "donor": {"source_report": donor["path"], "report_sha256": donor["sha256"],
                  "fdt_sha256": donor["report"].get("file_sha256")},
        "summary": summary,
        "nodes_added_in_donor": added,
        "nodes_missing_from_donor": removed,
        "shared_node_property_differences": changed,
        "critical_property_differences": critical_changes,
        "shared_compatible_nodes": compatible_matches,
        "phandle_value_changes": handle_changes,
        "phandle_inventory": {
            "target_unique_values": len(target_handles),
            "donor_unique_values": len(donor_handles),
            "target_duplicate_values": {str(k): v for k, v in target_handles.items() if len(v) > 1},
            "donor_duplicate_values": {str(k): v for k, v in donor_handles.items() if len(v) > 1},
        },
        "interpretation": [
            "A matching node path or compatible string is a structural clue, not proof of driver or hardware compatibility.",
            "Property differences are compared by encoded raw_hex where available; semantic cell interpretation is not attempted.",
            "Node additions and removals are relative to the supplied reports; donor does not mean suitable donor.",
            "Phandle values are reported, but references inside arbitrary properties are not resolved.",
        ],
        "limitations": [
            "Inputs must be JSON reports produced by Phoenix FDT Analyzer; raw DTB, compressed blobs and Apple-specific wrappers are not accepted here.",
            "The comparator does not infer address-cell or size-cell semantics, interrupt-controller topology, GPIO numbering, clocks, regulators or power sequencing.",
            "No driver matching, kernel API compatibility, boot testing, firmware patching or restore operation is performed.",
            "Results must be reviewed alongside exact board identity, SoC, kernel build and device-specific documentation.",
        ],
    }

def main(argv=None):
    parser = argparse.ArgumentParser(description="Compare target and donor Phoenix FDT Analyzer JSON reports")
    parser.add_argument("--target", type=Path, required=True, help="Target-side Phoenix FDT JSON report")
    parser.add_argument("--donor", type=Path, required=True, help="Donor-side Phoenix FDT JSON report")
    parser.add_argument("--out", type=Path, default=Path("phoenix-device-tree-diff.json"))
    args = parser.parse_args(argv)
    try:
        target, donor = load_report(args.target), load_report(args.donor)
        result = compare(target, donor)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("Target nodes:", result["summary"]["target_node_count"])
        print("Donor nodes:", result["summary"]["donor_node_count"])
        print("Shared compatible nodes:", result["summary"]["shared_compatible_node_count"])
        print("Critical property differences:", result["summary"]["critical_property_difference_count"])
        print("Report written:", args.out)
        return 0
    except (OSError, CompareError) as exc:
        print("phoenix-dt-diff: error:", exc, file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
