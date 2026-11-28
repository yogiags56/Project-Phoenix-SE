#!/usr/bin/env python3
"""Phoenix Kernel Compatibility Analyzer: correlate Phoenix Mach-O, KC and kext reports."""
from __future__ import annotations
import argparse
import hashlib
import json
import sys
from pathlib import Path

class KernelAnalysisError(ValueError):
    pass

def read_report(path, expected_tool):
    try:
        raw=Path(path).read_bytes()
        obj=json.loads(raw.decode("utf-8"))
    except (OSError,UnicodeDecodeError,json.JSONDecodeError) as exc:
        raise KernelAnalysisError("Cannot read %s: %s"%(path,exc)) from exc
    if not isinstance(obj,dict) or obj.get("tool")!=expected_tool:
        raise KernelAnalysisError("%s must be a JSON report from %s"%(path,expected_tool))
    return {"path":str(path),"sha256":hashlib.sha256(raw).hexdigest(),"data":obj}

def int_arch(value):
    return value if isinstance(value,int) and not isinstance(value,bool) else None

def macho_architectures(report):
    result=set()
    slices=report["data"].get("slices",[])
    if not isinstance(slices,list):
        raise KernelAnalysisError("Mach-O report slices must be an array")
    for item in slices:
        if not isinstance(item,dict): continue
        arch=item.get("architecture",{})
        if isinstance(arch,dict):
            cpu=int_arch(arch.get("cpu_type"))
            sub=int_arch(arch.get("cpu_subtype"))
            if cpu is not None:
                result.add((cpu,sub))
    return result

def kc_architectures(report):
    result=set()
    container=report["data"].get("container",{})
    if isinstance(container,dict):
        arch=container.get("architecture",{})
        if isinstance(arch,dict):
            cpu=int_arch(arch.get("cpu_type")); sub=int_arch(arch.get("cpu_subtype"))
            if cpu is not None: result.add((cpu,sub))
    entries=report["data"].get("entries",[])
    if not isinstance(entries,list):
        raise KernelAnalysisError("Kernel Collection entries must be an array")
    for entry in entries:
        if not isinstance(entry,dict): continue
        embedded=entry.get("embedded_macho",{})
        arch=embedded.get("architecture",{}) if isinstance(embedded,dict) else {}
        if isinstance(arch,dict):
            cpu=int_arch(arch.get("cpu_type")); sub=int_arch(arch.get("cpu_subtype"))
            if cpu is not None: result.add((cpu,sub))
    return result

def kext_inventory(report):
    data=report["data"]
    bundles=data.get("bundles",[])
    if not isinstance(bundles,list):
        raise KernelAnalysisError("Kext report bundles must be an array")
    ids=set()
    invalid=[]
    for bundle in bundles:
        if not isinstance(bundle,dict): continue
        bundle_id=bundle.get("bundle_id")
        if isinstance(bundle_id,str) and bundle_id.strip() and bundle.get("valid",True):
            ids.add(bundle_id.strip())
        else:
            invalid.append(bundle.get("path"))
    dependencies=data.get("dependencies",[])
    if not isinstance(dependencies,list):
        raise KernelAnalysisError("Kext report dependencies must be an array")
    edges=[]
    for edge in dependencies:
        if not isinstance(edge,dict): continue
        consumer=edge.get("consumer"); dependency=edge.get("dependency")
        if isinstance(consumer,str) and isinstance(dependency,str):
            edges.append({"consumer":consumer,"dependency":dependency,
                          "required_version":edge.get("required_version"),
                          "resolved_in_scan":bool(edge.get("resolved"))})
    return ids,edges,invalid

def validate_evidence_set_gate(validation_path, target, donor):
    """Require a valid provenance report bound to the exact six input report hashes."""
    try:
        raw = Path(validation_path).read_bytes()
        validation = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise KernelAnalysisError("Cannot read evidence-set validation report: %s" % exc) from exc

    if not isinstance(validation, dict) or validation.get("tool") != "Phoenix Evidence Set Validator":
        raise KernelAnalysisError("Evidence-set validation input is not a Phoenix Evidence Set Validator report")
    if validation.get("status") != "valid":
        raise KernelAnalysisError("Evidence-set status must be valid; got %r" % validation.get("status"))

    sets = validation.get("evidence_sets")
    if not isinstance(sets, dict):
        raise KernelAnalysisError("Evidence-set validation report has no evidence_sets object")

    for role, inputs in (("target", target), ("donor", donor)):
        evidence_set = sets.get(role)
        if not isinstance(evidence_set, dict) or evidence_set.get("status") != "valid":
            raise KernelAnalysisError("%s evidence set is not valid" % role)
        rows = evidence_set.get("reports")
        if not isinstance(rows, list):
            raise KernelAnalysisError("%s evidence-set reports must be an array" % role)
        by_name = {}
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("name"), str):
                raise KernelAnalysisError("%s evidence set contains a malformed report entry" % role)
            name = row["name"]
            if name in by_name:
                raise KernelAnalysisError("%s evidence set contains duplicate report name %r" % (role, name))
            by_name[name] = row
        for name, report in inputs.items():
            row = by_name.get(name)
            if row is None:
                raise KernelAnalysisError("%s evidence set is missing required %s report" % (role, name))
            if row.get("actual_sha256") != report["sha256"]:
                raise KernelAnalysisError(
                    "%s %s report hash does not match the validated evidence set" % (role, name)
                )
    return hashlib.sha256(raw).hexdigest()


def compare(target,donor):
    ta,da=macho_architectures(target["macho"]),macho_architectures(donor["macho"])
    tk,dk=kc_architectures(target["kc"]),kc_architectures(donor["kc"])
    ti,te,tinvalid=kext_inventory(target["kext"])
    di,de,dinvalid=kext_inventory(donor["kext"])
    shared_macho=ta&da
    shared_kc=tk&dk
    shared_ids=ti&di
    target_only_ids=ti-di
    donor_only_ids=di-ti
    def arch_rows(values):
        return [{"cpu_type":cpu,"cpu_subtype":sub} for cpu,sub in sorted(values)]
    if (ta and da and not shared_macho) or (tk and dk and not shared_kc):
        indication="Incompatible"
        reason="At least one supplied binary layer declares non-overlapping CPU architecture tuples."
    elif shared_macho or shared_kc or shared_ids:
        indication="Potential"
        reason="Some binary architecture or kext identifiers overlap; deeper ABI and device validation is required."
    else:
        indication="Unknown"
        reason="The reports contain insufficient comparable architecture or kext identity evidence."
    return {
      "schema_version":1,"tool":"Phoenix Kernel Compatibility Analyzer",
      "indication":indication,"rationale":reason,
      "target":{name:{"report":item["path"],"report_sha256":item["sha256"]}
                for name,item in target.items()},
      "donor":{name:{"report":item["path"],"report_sha256":item["sha256"]}
               for name,item in donor.items()},
      "architecture_comparison":{
        "mach_o":{"target":arch_rows(ta),"donor":arch_rows(da),"shared":arch_rows(shared_macho)},
        "kernel_collection":{"target":arch_rows(tk),"donor":arch_rows(dk),"shared":arch_rows(shared_kc)}},
      "kext_comparison":{
        "target_bundle_count":len(ti),"donor_bundle_count":len(di),
        "shared_bundle_ids":sorted(shared_ids),
        "target_only_bundle_ids":sorted(target_only_ids),
        "donor_only_bundle_ids":sorted(donor_only_ids),
        "target_invalid_or_missing_ids":tinvalid,"donor_invalid_or_missing_ids":dinvalid,
        "target_dependency_edges":te,"donor_dependency_edges":de},
      "summary":{
        "shared_macho_architecture_tuple_count":len(shared_macho),
        "shared_kernel_collection_architecture_tuple_count":len(shared_kc),
        "shared_kext_bundle_id_count":len(shared_ids),
        "target_only_kext_count":len(target_only_ids),
        "donor_only_kext_count":len(donor_only_ids)},
      "limitations":[
        "This tool correlates three Phoenix JSON reports; it does not inspect raw kernel or kext binaries.",
        "CPU tuple overlap is not proof of ABI, kernel API, CPU feature, platform or board compatibility.",
        "A matching CFBundleIdentifier does not prove matching executable contents, dependencies, entitlements or signatures.",
        "Kext dependency resolution is not evaluated against kernel symbols or version constraints here.",
        "The analyzer does not decode kernel collections, symbols, relocations, chained fixups, code signatures or entitlements.",
        "It does not assess device-tree bindings, SEP, baseband, Cryptex, boot chain, restore ramdisk or userspace.",
        "Incompatible means a reported architecture conflict in at least one supplied layer; Potential is not a compatibility verdict.",
        "No firmware is modified, patched, signed, executed or restored."]}
    
def main(argv=None):
    p=argparse.ArgumentParser(description="Correlate Phoenix Mach-O, Kernel Collection and kext JSON reports")
    p.add_argument("--target-macho",required=True,type=Path)
    p.add_argument("--target-kc",required=True,type=Path)
    p.add_argument("--target-kext",required=True,type=Path)
    p.add_argument("--donor-macho",required=True,type=Path)
    p.add_argument("--donor-kc",required=True,type=Path)
    p.add_argument("--donor-kext",required=True,type=Path)
    p.add_argument("--evidence-set-validation", type=Path,
                   help="require a valid Phoenix Evidence Set Validator report matching all six input hashes")
    p.add_argument("--out",type=Path,default=Path("phoenix-kernel-compatibility.json"))
    a=p.parse_args(argv)
    try:
        target={"macho":read_report(a.target_macho,"Phoenix Mach-O Analyzer"),
                "kc":read_report(a.target_kc,"Phoenix Kernel Collection Inspector"),
                "kext":read_report(a.target_kext,"Phoenix Kext Dependency Analyzer")}
        donor={"macho":read_report(a.donor_macho,"Phoenix Mach-O Analyzer"),
               "kc":read_report(a.donor_kc,"Phoenix Kernel Collection Inspector"),
               "kext":read_report(a.donor_kext,"Phoenix Kext Dependency Analyzer")}
        if a.evidence_set_validation:
            validation_sha = validate_evidence_set_gate(a.evidence_set_validation, target, donor)
        else:
            validation_sha = None
        result=compare(target,donor)
        result["evidence_set_gate"] = {
            "required": a.evidence_set_validation is not None,
            "validation_report": str(a.evidence_set_validation) if a.evidence_set_validation else None,
            "validation_report_sha256": validation_sha,
            "note": "When required, all six report hashes were matched to a valid target/donor evidence-set report." if validation_sha else "No evidence-set gate was supplied; legacy metadata-only mode was used."
        }
        a.out.parent.mkdir(parents=True,exist_ok=True)
        a.out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        print("Indication:",result["indication"])
        print("Shared Mach-O architecture tuples:",result["summary"]["shared_macho_architecture_tuple_count"])
        print("Shared KC architecture tuples:",result["summary"]["shared_kernel_collection_architecture_tuple_count"])
        print("Shared kext IDs:",result["summary"]["shared_kext_bundle_id_count"])
        print("Report written:",a.out)
        return 0
    except (OSError,KernelAnalysisError) as exc:
        print("phoenix-kernel-compat: error:",exc,file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
