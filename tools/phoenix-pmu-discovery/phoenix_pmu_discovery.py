#!/usr/bin/env python3
"""Read-only masked PMU signature discovery inside Mach-O MH_FILESET entries.

Reports file offsets only. It does not infer VM addresses from file offsets,
identify a PMU solely by entry name, decrypt/decompress, patch, or restore.
"""
from __future__ import annotations
import argparse, hashlib, json, re, struct, sys
from pathlib import Path

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
sys.path.insert(0,str(ROOT/"tools"/"phoenix-kc"))
try:
    from phoenix_kc import inspect_fileset, FilesetError
except ImportError:  # pragma: no cover
    inspect_fileset=None
    FilesetError=ValueError

MAX_INPUT=2*1024*1024*1024
MAX_RULES=10000
MAX_WORDS_PER_RULE=4096
PMU_HINT=re.compile(r"pmu|power.?management|apple.*power",re.I)

class DiscoveryError(ValueError): pass

def load_catalog(path: Path):
    obj=json.loads(path.read_text(encoding="utf-8"))
    rules=obj.get("rules")
    if not isinstance(rules,list) or not rules or len(rules)>MAX_RULES:
        raise DiscoveryError("catalog rules missing or outside safety limits")
    checked=[]
    for row in rules:
        if not isinstance(row,dict): raise DiscoveryError("catalog rule is not an object")
        signature=row.get("signature")
        if not isinstance(signature,list) or not signature or len(signature)>MAX_WORDS_PER_RULE:
            raise DiscoveryError("invalid signature length")
        words=[]
        for item in signature:
            try:
                value=int(item["value"],16); mask=int(item["mask"],16)
            except (KeyError,TypeError,ValueError):
                raise DiscoveryError("signature words must contain hexadecimal value and mask")
            if not (0<=value<=0xffffffff and 0<=mask<=0xffffffff):
                raise DiscoveryError("signature word exceeds 32 bits")
            words.append((value,mask))
        checked.append({"index":row.get("index"),"name":str(row.get("name","")),
                        "signature_id":row.get("signature_id"),"words":words})
    return checked

def scan_region(data: bytes, start: int, size: int, rules: list[dict]):
    end=start+size
    if start<0 or size<0 or end>len(data): raise DiscoveryError("entry range exceeds input")
    found=[]
    # ARM64 instruction words are 4-byte aligned relative to the entry's
    # file offset. Preserve the actual file offset; do not convert it to VM.
    for rule in rules:
        pattern=rule["words"]; width=len(pattern)*4
        if width>size: continue
        last=end-width
        for at in range(start,last+1,4):
            ok=True
            for i,(value,mask) in enumerate(pattern):
                actual=struct.unpack_from("<I",data,at+i*4)[0]
                if (actual & mask)!=(value & mask):
                    ok=False;break
            if ok:
                found.append({"rule_index":rule["index"],"rule_name":rule["name"],
                    "signature_id":rule["signature_id"],"file_offset":at,
                    "word_count":len(pattern),"matched_words":[
                      "0x%08x"%struct.unpack_from("<I",data,at+i*4)[0]
                      for i in range(len(pattern))]})
    return found

def discover(binary: bytes, catalog: list[dict], source="<memory>"):
    if inspect_fileset is None: raise DiscoveryError("Phoenix Kernel Collection parser unavailable")
    if not binary: raise DiscoveryError("empty kernel collection")
    if len(binary)>MAX_INPUT: raise DiscoveryError("input exceeds 2 GiB safety limit")
    try: kc=inspect_fileset(binary,source)
    except FilesetError as exc: raise DiscoveryError(str(exc)) from exc
    entries=[]
    for entry in kc["entries"]:
        start=entry["file_offset"];size=entry["available_size"]
        matches=scan_region(binary,start,size,catalog)
        ident=entry["identifier"]
        entries.append({
          "identifier":ident,"name_hint_only":bool(PMU_HINT.search(ident)),
          "vm_address_metadata":entry["vm_address"],
          "file_offset":start,"available_size":size,
          "embedded_macho":entry["embedded_macho"],
          "signature_match_count":len(matches),
          "unique_rule_count":len({m["rule_index"] for m in matches}),
          "matches":matches
        })
    ranked=sorted(entries,key=lambda e:(e["unique_rule_count"],e["name_hint_only"],e["signature_match_count"]),reverse=True)
    return {
      "schema_version":1,"tool":"Phoenix PMU Signature Discovery",
      "source":{"path":source,"size_bytes":len(binary),"sha256":hashlib.sha256(binary).hexdigest()},
      "kernel_collection":{"entry_count":len(entries),"format":kc["container"]["format"]},
      "entries":ranked,
      "interpretation":[
        "A name hint is heuristic metadata, not proof that an entry implements the target PMU.",
        "A signature hit is a masked byte-pattern match only; it does not prove semantic or hardware compatibility.",
        "Reported file offsets are not virtual addresses. A VM mapping requires segment/section mapping from the relevant embedded Mach-O.",
        "Zero matches do not prove absence: the donor may be encrypted, compressed, transformed, or use a different build.",
        "No firmware is modified; no decryption, decompression, patching, signing, execution, or restore is performed."
      ],
      "scope":{"read_only":True,"patch_application":False,"device_accessed":False,"compatibility_assessed":False}
    }

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("kernel_collection",type=Path)
    p.add_argument("--catalog",type=Path,default=ROOT/"research"/"PMU-SIGNATURE-CATALOG.json")
    p.add_argument("--out",type=Path,default=Path("phoenix-pmu-discovery.json"))
    a=p.parse_args(argv)
    try:
        if not a.kernel_collection.is_file(): raise DiscoveryError("kernel collection not found")
        binary=a.kernel_collection.read_bytes()
        rules=load_catalog(a.catalog)
        report=discover(binary,rules,str(a.kernel_collection))
        a.out.parent.mkdir(parents=True,exist_ok=True)
        if a.out.exists(): raise DiscoveryError("refusing to overwrite existing report")
        a.out.write_text(json.dumps(report,indent=2)+"\\n",encoding="utf-8")
        print("fileset entries:",report["kernel_collection"]["entry_count"])
        print("entries with signature hits:",sum(bool(e["matches"]) for e in report["entries"]))
        print("report:",a.out)
        return 0
    except (OSError,json.JSONDecodeError,DiscoveryError) as exc:
        print("phoenix-pmu-discovery:",exc,file=sys.stderr);return 2
if __name__=="__main__": raise SystemExit(main())
