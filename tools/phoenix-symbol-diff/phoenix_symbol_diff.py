#!/usr/bin/env python3
"""Phoenix Symbol Diff: compare conventional Mach-O LC_SYMTAB evidence."""
from __future__ import annotations
import argparse
import hashlib
import json
import sys
from pathlib import Path

MAX_REPORTED_NAMES = 100_000
N_STAB = 0xE0
N_TYPE = 0x0E
N_EXT = 0x01
N_UNDF = 0x00
N_ABS = 0x02
N_SECT = 0x0E
N_PBUD = 0x0C
N_INDR = 0x0A

class SymbolDiffError(ValueError):
    pass

def load_report(path):
    try:
        raw=Path(path).read_bytes()
        obj=json.loads(raw.decode("utf-8"))
    except (OSError,UnicodeDecodeError,json.JSONDecodeError) as exc:
        raise SymbolDiffError("Cannot read %s: %s"%(path,exc)) from exc
    if not isinstance(obj,dict) or obj.get("tool")!="Phoenix Mach-O Analyzer":
        raise SymbolDiffError("%s is not a Phoenix Mach-O Analyzer report"%path)
    slices=obj.get("slices")
    if not isinstance(slices,list) or not slices:
        raise SymbolDiffError("%s has no Mach-O slices"%path)
    digest=hashlib.sha256(raw).hexdigest()
    indexed={}
    for item in slices:
        if not isinstance(item,dict):
            raise SymbolDiffError("Malformed slice in %s"%path)
        arch=item.get("architecture")
        if not isinstance(arch,dict):
            raise SymbolDiffError("Slice architecture missing in %s"%path)
        cpu,sub=arch.get("cpu_type"),arch.get("cpu_subtype")
        if not isinstance(cpu,int) or isinstance(cpu,bool) or not isinstance(sub,int) or isinstance(sub,bool):
            raise SymbolDiffError("Slice CPU type/subtype missing in %s"%path)
        key=(cpu,sub)
        if key in indexed:
            raise SymbolDiffError("Duplicate architecture tuple %r in %s"%(key,path))
        macho=item.get("macho")
        if not isinstance(macho,dict):
            raise SymbolDiffError("Slice Mach-O payload missing in %s"%path)
        symbols=macho.get("symbols")
        if not isinstance(symbols,list):
            raise SymbolDiffError("Slice symbol list missing in %s; regenerate report with current Phoenix Mach-O Analyzer"%path)
        indexed[key]={"architecture":arch,"symbols":symbols,
                      "has_symbol_table":macho.get("summary",{}).get("has_symbol_table",False)}
    return {"path":str(path),"sha256":digest,"source_sha256":obj.get("file_sha256"),
            "binary_type":obj.get("binary_type"),"slices":indexed}

def classify(symbol):
    ntype=symbol.get("type")
    if not isinstance(ntype,int) or isinstance(ntype,bool):
        return "unknown"
    if ntype & N_STAB:
        return "debug"
    base=ntype & N_TYPE
    return {N_UNDF:"undefined",N_ABS:"absolute",N_SECT:"section",
            N_PBUD:"prebound_undefined",N_INDR:"indirect"}.get(base,"other")

def inventory(symbols):
    records={}
    malformed=0
    for item in symbols:
        if not isinstance(item,dict) or not isinstance(item.get("name"),str) or not item["name"]:
            malformed+=1
            continue
        name=item["name"]
        kind=classify(item)
        record={"kind":kind,"external":bool(item.get("type",0)&N_EXT)
                if isinstance(item.get("type"),int) else False}
        records.setdefault(name,[]).append(record)
    return records,malformed

def compare_slice(target,donor):
    ti,tm=inventory(target["symbols"])
    di,dm=inventory(donor["symbols"])
    target_names,donor_names=set(ti),set(di)
    shared=target_names&donor_names
    target_only=target_names-donor_names
    donor_only=donor_names-target_names
    def names_for(names,limit=MAX_REPORTED_NAMES):
        ordered=sorted(names)
        return {"names":ordered[:limit],"total":len(ordered),"truncated":len(ordered)>limit}
    def count_kind(records,kind):
        return sum(1 for values in records.values() for value in values if value["kind"]==kind)
    target_defined={name for name,values in ti.items() if any(v["kind"] in ("absolute","section","indirect") for v in values)}
    donor_defined={name for name,values in di.items() if any(v["kind"] in ("absolute","section","indirect") for v in values)}
    target_undefined={name for name,values in ti.items() if any(v["kind"]=="undefined" for v in values)}
    donor_undefined={name for name,values in di.items() if any(v["kind"]=="undefined" for v in values)}
    target_external={name for name,values in ti.items() if any(v["external"] for v in values)}
    donor_external={name for name,values in di.items() if any(v["external"] for v in values)}
    return {
      "symbol_table_present":{"target":target["has_symbol_table"],"donor":donor["has_symbol_table"]},
      "summary":{
        "target_symbol_name_count":len(ti),"donor_symbol_name_count":len(di),
        "shared_symbol_name_count":len(shared),"target_only_symbol_name_count":len(target_only),
        "donor_only_symbol_name_count":len(donor_only),
        "target_defined_name_count":len(target_defined),"donor_defined_name_count":len(donor_defined),
        "target_undefined_name_count":len(target_undefined),"donor_undefined_name_count":len(donor_undefined),
        "shared_defined_name_count":len(target_defined&donor_defined),
        "target_external_name_count":len(target_external),"donor_external_name_count":len(donor_external),
        "malformed_target_symbol_records":tm,"malformed_donor_symbol_records":dm,
        "target_debug_symbol_records":count_kind(ti,"debug"),"donor_debug_symbol_records":count_kind(di,"debug")},
      "target_only_symbols":names_for(target_only),
      "donor_only_symbols":names_for(donor_only),
      "shared_symbols":names_for(shared),
      "target_only_defined_symbols":names_for(target_defined-donor_defined),
      "donor_only_defined_symbols":names_for(donor_defined-target_defined),
      "target_only_undefined_symbols":names_for(target_undefined-donor_undefined),
      "donor_only_undefined_symbols":names_for(donor_undefined-target_undefined),
      "interpretation":[
        "Symbol-name overlap is evidence of naming overlap only; it does not establish identical ABI, calling convention, structure layout or implementation.",
        "A symbol absent from a conventional LC_SYMTAB may still exist in an exports trie, be stripped, hidden, renamed or unavailable to this parser.",
        "Undefined symbols are references recorded in this symbol table, not proof that a matching runtime provider is loadable.",
        "Local and external symbols are included; exact duplicate symbol names are collapsed for set comparisons while record counts remain visible."]}
    
def compare(target,donor):
    target_arch=set(target["slices"]); donor_arch=set(donor["slices"])
    shared=target_arch&donor_arch
    rows=[]
    for cpu,sub in sorted(shared):
        row=compare_slice(target["slices"][(cpu,sub)],donor["slices"][(cpu,sub)])
        row["architecture"]={"cpu_type":cpu,"cpu_subtype":sub,
          "name":target["slices"][(cpu,sub)]["architecture"].get("name","unknown")}
        rows.append(row)
    return {
      "schema_version":1,"tool":"Phoenix Symbol Diff",
      "target":{"report":target["path"],"report_sha256":target["sha256"],"binary_sha256":target["source_sha256"]},
      "donor":{"report":donor["path"],"report_sha256":donor["sha256"],"binary_sha256":donor["source_sha256"]},
      "architecture_summary":{
        "target_architectures":[{"cpu_type":c,"cpu_subtype":s} for c,s in sorted(target_arch)],
        "donor_architectures":[{"cpu_type":c,"cpu_subtype":s} for c,s in sorted(donor_arch)],
        "shared_architecture_count":len(shared),
        "target_only_architecture_count":len(target_arch-donor_arch),
        "donor_only_architecture_count":len(donor_arch-target_arch)},
      "slice_comparisons":rows,
      "unmatched_target_architectures":[{"cpu_type":c,"cpu_subtype":s} for c,s in sorted(target_arch-donor_arch)],
      "unmatched_donor_architectures":[{"cpu_type":c,"cpu_subtype":s} for c,s in sorted(donor_arch-target_arch)],
      "limitations":[
        "Inputs are JSON reports from Phoenix Mach-O Analyzer, not raw binaries.",
        "Only conventional LC_SYMTAB records currently emitted by Phoenix Mach-O Analyzer are compared.",
        "Exports trie, chained fixups, dyld shared cache symbol data, kernel symbol sets from external files, and stripped-symbol recovery are not implemented.",
        "No ABI, function signature, structure layout, relocation, symbol version, code-signature or entitlement validation is performed.",
        "No kernel loadability, driver binding, board compatibility or device boot test is performed.",
        "No firmware is modified, patched, signed, executed or restored."]}

def main(argv=None):
    p=argparse.ArgumentParser(description="Compare symbol-table evidence in Phoenix Mach-O JSON reports")
    p.add_argument("--target",required=True,type=Path,help="Target Mach-O Analyzer JSON report")
    p.add_argument("--donor",required=True,type=Path,help="Donor Mach-O Analyzer JSON report")
    p.add_argument("--out",type=Path,default=Path("phoenix-symbol-diff.json"))
    a=p.parse_args(argv)
    try:
        target,donor=load_report(a.target),load_report(a.donor)
        result=compare(target,donor)
        a.out.parent.mkdir(parents=True,exist_ok=True)
        a.out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        print("Shared architectures:",result["architecture_summary"]["shared_architecture_count"])
        for row in result["slice_comparisons"]:
            print("Architecture",row["architecture"],"shared symbols:",row["summary"]["shared_symbol_name_count"])
        print("Report written:",a.out)
        return 0
    except (OSError,SymbolDiffError) as exc:
        print("phoenix-symbol-diff: error:",exc,file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
