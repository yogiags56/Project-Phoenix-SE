#!/usr/bin/env python3
"""Donorless, source-catalog LDO signature overlap reconstruction.

Finds exact suffix-to-prefix overlaps among LDO signature windows. This
establishes catalog-level shared instruction sequences only, not binary
addresses, unique occurrence, or a complete kernel control-flow graph.
"""
from __future__ import annotations
import argparse,json,sys
from pathlib import Path

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
sys.path.insert(0,str(ROOT/"tools"/"phoenix-pmu-semantic"))
try:
    from phoenix_pmu_semantic import decode
except ImportError:  # pragma: no cover
    decode=None

class LDOError(ValueError): pass

def word(v):
    try:
        n=int(v,16)
    except (TypeError,ValueError) as exc:
        raise LDOError(f"invalid hexadecimal word: {v!r}") from exc
    if not 0<=n<=0xffffffff: raise LDOError("instruction word outside uint32")
    return n

def validate_rules(catalog, first=54, last=69):
    all_rules=catalog.get("rules")
    if not isinstance(all_rules,list): raise LDOError("catalog rules missing")
    selected=[]
    for r in all_rules:
        idx=r.get("index")
        if isinstance(idx,int) and first<=idx<=last:
            sig=r.get("signature")
            if not isinstance(sig,list) or not sig: raise LDOError(f"rule {idx}: signature missing")
            words=[]
            for item in sig:
                value=word(item.get("value"));mask=word(item.get("mask"))
                words.append({"value":value,"mask":mask})
            pi=r.get("patch_word_index")
            if not isinstance(pi,int) or not 0<=pi<len(words): raise LDOError(f"rule {idx}: invalid patch index")
            selected.append({"index":idx,"name":r.get("name",""),"change":bool(r.get("change")),
              "patch_word_index":pi,"replacement_word":word(r.get("replacement_word","0x0")),
              "signature":words})
    selected.sort(key=lambda x:x["index"])
    expected=list(range(first,last+1))
    actual=[x["index"] for x in selected]
    if actual!=expected: raise LDOError(f"expected rule indices {expected}, got {actual}")
    return selected

def overlaps(a,b,min_words=2):
    # Exact value AND mask equality is required; masked templates only overlap
    # when their masks also match. No fuzzy wildcard matching is inferred.
    best=0
    for n in range(min(len(a["signature"]),len(b["signature"]))+1):
        if n<min_words: continue
        left=a["signature"][-n:];right=b["signature"][:n]
        if all(x==y for x,y in zip(left,right)): best=n
    return best

def analyze(catalog):
    if decode is None: raise LDOError("Phoenix semantic decoder unavailable")
    rules=validate_rules(catalog)
    edges=[]
    for a in rules:
        for b in rules:
            if a["index"]==b["index"]: continue
            n=overlaps(a,b)
            if n:
                shared=a["signature"][-n:]
                edges.append({"from_rule":a["index"],"from_name":a["name"],
                  "to_rule":b["index"],"to_name":b["name"],"overlap_words":n,
                  "shared_words":[f"0x{x['value']:08x}" for x in shared],
                  "fully_constrained":all(x["mask"]==0xffffffff for x in shared),
                  "evidence":"exact catalog suffix/prefix equality"})
    edges.sort(key=lambda e:(-e["overlap_words"],e["from_rule"],e["to_rule"]))
    jumps=[]
    for j in catalog.get("jumps",[]):
        src=int(j.get("source_rule",j.get("source",-1)))
        dst=int(j.get("target_rule",j.get("target",-1)))
        if 54<=src<=69 or 54<=dst<=69:
            if not (54<=src<=69 and 54<=dst<=69): raise LDOError("LDO jump references rule outside LDO range")
            jumps.append({"source_rule":src,"target_rule":dst,"branch_kind":j.get("branch_kind"),
                          "evidence":"source patcher dynamic redirect"})
    patch_sites=[]
    for r in rules:
        original=r["signature"][r["patch_word_index"]]
        before=decode(original["value"])
        replacement=decode(r["replacement_word"])
        dynamic=next((j for j in jumps if j["source_rule"]==r["index"]),None)
        patch_sites.append({"rule_index":r["index"],"name":r["name"],
          "patch_word_index_in_signature":r["patch_word_index"],
          "original_word_template":f"0x{original['value']:08x}",
          "original_mask":f"0x{original['mask']:08x}",
          "original_instruction":before,
          "source_table_replacement":f"0x{r['replacement_word']:08x}",
          "source_table_replacement_instruction":replacement,
          "effective_behavior":"dynamic_branch_redirect" if dynamic else ("static_instruction_replacement" if r["change"] else "anchor_only"),
          "dynamic_redirect":dynamic,
          "binary_occurrence_verified":False})
    # Report only overlap relations, not a linearized pseudo-function.
    return {"schema_version":1,"artifact":"Phoenix donorless LDO signature overlap reconstruction",
      "provenance":catalog.get("provenance",{}),
      "scope":{"donor_binary_required":False,"source_catalog_only":True,
       "exact_signature_overlap_only":True,"binary_offsets_resolved":False,
       "unique_occurrence_proven":False,"complete_cfg_reconstructed":False,
       "hardware_behavior_validated":False,"patch_application":False},
      "summary":{"rule_range":[54,69],"rule_count":len(rules),"overlap_edge_count":len(edges),
       "overlap_edges_ge_6_words":sum(e["overlap_words"]>=6 for e in edges),
       "dynamic_redirect_count":len(jumps),"mutating_patch_site_count":sum(r["change"] for r in rules)},
      "overlap_edges":edges,"dynamic_redirects":jumps,"patch_sites":patch_sites,
      "interpretation":[
       "An overlap means the suffix words of one catalog signature exactly equal the prefix words of another, including masks.",
       "Overlapping signatures are evidence of shared local instruction windows in the source catalog, not proof of unique binary placement.",
       "Multiple outgoing overlaps can be caused by nested windows or repeated instruction sequences; do not interpret every edge as control flow.",
       "Rule patch_word_index identifies a word within its signature, not an absolute kernel offset.",
       "Dynamic redirect targets are source patcher relationships; actual displacements require matched target binary offsets.",
       "No donor binary was read and no firmware or device was modified."
      ]}

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("catalog",type=Path,nargs="?",default=ROOT/"research"/"PMU-SIGNATURE-CATALOG.json")
    p.add_argument("-o","--output",type=Path,default=ROOT/"research"/"PMU-LDO-OVERLAP-RECONSTRUCTION.json")
    a=p.parse_args(argv)
    try:
        cat=json.loads(a.catalog.read_text(encoding="utf-8"))
        report=analyze(cat)
        a.output.parent.mkdir(parents=True,exist_ok=True)
        if a.output.exists() and a.output.resolve()!=(ROOT/"research"/"PMU-LDO-OVERLAP-RECONSTRUCTION.json").resolve():
            raise LDOError(f"refusing to overwrite existing output: {a.output}")
        a.output.write_text(json.dumps(report,indent=2)+"\\n",encoding="utf-8")
        print("LDO rules:",report["summary"]["rule_count"])
        print("exact overlap edges:",report["summary"]["overlap_edge_count"])
        print("overlaps >= 6 words:",report["summary"]["overlap_edges_ge_6_words"])
        print("report:",a.output)
        return 0
    except (OSError,UnicodeError,json.JSONDecodeError,LDOError,TypeError,ValueError,KeyError) as exc:
        print("phoenix-pmu-ldo:",exc,file=sys.stderr);return 2
if __name__=="__main__": raise SystemExit(main())
