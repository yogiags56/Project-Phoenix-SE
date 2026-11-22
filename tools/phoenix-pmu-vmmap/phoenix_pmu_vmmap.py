#!/usr/bin/env python3
"""Map PMU signature file offsets into embedded Mach-O segments and VM addresses.

Read-only analysis only. VM addresses are emitted only when a complete match
maps uniquely into an executable segment of a structurally parsed ARM64 image.
"""
from __future__ import annotations
import argparse, hashlib, json, struct, sys
from pathlib import Path

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
sys.path.insert(0,str(ROOT/"tools"/"phoenix-kc"))
sys.path.insert(0,str(ROOT/"tools"/"phoenix-macho"))
try:
    from phoenix_kc import inspect_fileset, FilesetError
    from phoenix_macho import parse_macho_slice, MachOError
except ImportError:  # pragma: no cover
    inspect_fileset=parse_macho_slice=None
    FilesetError=MachOError=ValueError

MAX_INPUT=2*1024*1024*1024
MAX_RULES=10000
MAX_WORDS=4096
VM_PROT_EXECUTE=0x4

class MappingError(ValueError): pass

def load_catalog(path: Path):
    try: obj=json.loads(path.read_text(encoding="utf-8"))
    except (OSError,json.JSONDecodeError) as exc: raise MappingError(f"cannot read catalog: {exc}") from exc
    rules=obj.get("rules") if isinstance(obj,dict) else None
    if not isinstance(rules,list) or not rules or len(rules)>MAX_RULES:
        raise MappingError("catalog rules missing or outside safety limits")
    out=[]
    for row in rules:
        if not isinstance(row,dict): raise MappingError("catalog rule must be an object")
        words=row.get("signature")
        if not isinstance(words,list) or not words or len(words)>MAX_WORDS:
            raise MappingError("invalid signature length")
        parsed=[]
        for word in words:
            try:
                value=int(word["value"],16);mask=int(word["mask"],16)
            except (KeyError,TypeError,ValueError) as exc:
                raise MappingError("signature values and masks must be hexadecimal") from exc
            if not (0<=value<=0xffffffff and 0<=mask<=0xffffffff):
                raise MappingError("signature word exceeds 32 bits")
            parsed.append((value,mask))
        out.append({"rule_index":row.get("index"),"rule_name":str(row.get("name","")),
                    "signature_id":row.get("signature_id"),"words":parsed})
    return out

def scan_entry(data: bytes, start: int, size: int, rules: list[dict]):
    end=start+size
    if start<0 or size<0 or end>len(data): raise MappingError("entry range exceeds input")
    found=[]
    for rule in rules:
        count=len(rule["words"]);width=count*4
        for at in range(start,end-width+1,4):
            if all((struct.unpack_from("<I",data,at+i*4)[0]&mask)==(value&mask)
                   for i,(value,mask) in enumerate(rule["words"])):
                found.append({"rule_index":rule["rule_index"],"rule_name":rule["rule_name"],
                    "signature_id":rule["signature_id"],"file_offset":at,
                    "match_size":width,"matched_words":[
                      "0x%08x"%struct.unpack_from("<I",data,at+i*4)[0] for i in range(count)]})
    return found

def map_match(match: dict, entry_file_offset: int, macho: dict):
    rel=match["file_offset"]-entry_file_offset
    match_end=rel+match["match_size"]
    candidates=[]
    for seg in macho["segments"]:
        seg_start=seg["file_offset"];seg_end=seg_start+seg["file_size"]
        if rel<seg_start or match_end>seg_end: continue
        executable=bool(seg["initial_protection"]&VM_PROT_EXECUTE)
        vm=int(seg["vm_address"],16)+(rel-seg_start)
        candidates.append({"segment":seg["name"],"segment_file_offset":seg_start,
            "segment_file_size":seg["file_size"],"segment_vm_address":seg["vm_address"],
            "initial_protection":seg["initial_protection"],"executable":executable,
            "virtual_address":"0x%x"%vm})
    if len(candidates)==1:
        chosen=candidates[0]
        return {**chosen,"mapping_status":"mapped_executable" if chosen["executable"] else "mapped_non_executable",
                "virtual_address":chosen["virtual_address"] if chosen["executable"] else None}
    if len(candidates)>1:
        return {"mapping_status":"ambiguous_overlapping_segments","candidate_segments":candidates,
                "virtual_address":None}
    return {"mapping_status":"not_covered_by_segment_file_range","virtual_address":None}

def analyze(binary: bytes, rules: list[dict], source="<memory>"):
    if inspect_fileset is None or parse_macho_slice is None:
        raise MappingError("Phoenix Mach-O/Kernel Collection parsers unavailable")
    if not binary: raise MappingError("empty input")
    if len(binary)>MAX_INPUT: raise MappingError("input exceeds 2 GiB safety limit")
    try: kc=inspect_fileset(binary,source)
    except FilesetError as exc: raise MappingError(str(exc)) from exc
    entries=[]
    for entry in kc["entries"]:
        start=entry["file_offset"];size=entry["available_size"]
        item={"identifier":entry["identifier"],"file_offset":start,"available_size":size,
              "fileset_vm_address":entry["vm_address"],"name_hint_only":False,
              "mach_o_validation":"not_attempted","architecture":None,"uuid":None,
              "segments":[],"matches":[]}
        try:
            macho=parse_macho_slice(binary,start,size)
            item["mach_o_validation"]="structural_parser_accepted"
            item["architecture"]=macho["architecture"]["name"]
            item["uuid"]=macho["uuid"]
            item["segments"]=macho["segments"]
            if item["architecture"]!="ARM64":
                item["mach_o_validation"]="parsed_non_arm64"
            hits=scan_entry(binary,start,size,rules)
            for hit in hits:
                mapping=map_match(hit,start,macho)
                item["matches"].append({**hit,"mapping":mapping})
        except MachOError as exc:
            item["mach_o_validation"]="structural_parse_failed"
            item["parse_error"]=str(exc)
        item["match_count"]=len(item["matches"])
        item["executable_mapping_count"]=sum(
            m["mapping"]["mapping_status"]=="mapped_executable" for m in item["matches"])
        entries.append(item)
    return {"schema_version":1,"tool":"Phoenix PMU Virtual Address Mapper",
      "source":{"path":source,"size_bytes":len(binary),"sha256":hashlib.sha256(binary).hexdigest()},
      "kernel_collection":{"format":kc["container"]["format"],"entry_count":len(entries)},
      "entries":entries,
      "interpretation":[
        "A VM address is emitted only for a complete signature match uniquely covered by one executable segment.",
        "Mach-O segment file offsets are interpreted relative to the embedded fileset image; this assumption must be checked against the target kernel collection format.",
        "Fileset entry vm_address is metadata for the embedded image and is not substituted for a segment-derived address.",
        "A mapped signature is not proof of function identity, patch safety, or hardware compatibility.",
        "Overlapping segments, non-executable mappings, malformed images, and unmatched file ranges remain explicitly unresolved.",
        "No decryption, decompression, patching, signing, execution, device access, or restore is performed."
      ],
      "scope":{"read_only":True,"patch_application":False,"device_accessed":False,
               "compatibility_assessed":False}}
def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("kernel_collection",type=Path)
    p.add_argument("--catalog",type=Path,default=ROOT/"research"/"PMU-SIGNATURE-CATALOG.json")
    p.add_argument("--out",type=Path,default=Path("phoenix-pmu-vmmap.json"))
    a=p.parse_args(argv)
    try:
        if not a.kernel_collection.is_file(): raise MappingError("kernel collection not found")
        report=analyze(a.kernel_collection.read_bytes(),load_catalog(a.catalog),str(a.kernel_collection))
        a.out.parent.mkdir(parents=True,exist_ok=True)
        if a.out.exists(): raise MappingError(f"refusing to overwrite existing report: {a.out}")
        a.out.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
        print("fileset entries:",report["kernel_collection"]["entry_count"])
        print("executable signature mappings:",sum(e["executable_mapping_count"] for e in report["entries"]))
        print("report:",a.out)
        return 0
    except (OSError,MappingError) as exc:
        print("phoenix-pmu-vmmap:",exc,file=sys.stderr);return 2
if __name__=="__main__": raise SystemExit(main())
