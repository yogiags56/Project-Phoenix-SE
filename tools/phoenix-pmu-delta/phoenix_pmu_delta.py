#!/usr/bin/env python3
"""Source-only audit of PMU patch instruction deltas from the Phoenix catalog.

No donor binary is required. This compares exact source catalog words and masks
with the patcher's declared replacement words and dynamic branch redirects.
It does not prove a signature occurs in any firmware image.
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

class DeltaError(ValueError): pass

FLAG_WRITERS={"cmp","cmn","tst","adds","subs","ands"}
def word(value):
    try: return int(value,16)
    except (TypeError,ValueError) as exc: raise DeltaError(f"invalid hexadecimal instruction word: {value!r}") from exc

def instruction_facts(d):
    return {"class":d.get("class"),"mnemonic":d.get("mnemonic"),
            "operands":d.get("operands",[]),"immediate":d.get("immediate"),
            "condition":d.get("condition"),"tested_bit":d.get("tested_bit"),
            "branch_displacement":d.get("branch_displacement")}

def audit(catalog: dict) -> dict:
    if decode is None: raise DeltaError("Phoenix ARM64 semantic decoder unavailable")
    rules=catalog.get("rules")
    if not isinstance(rules,list) or not rules: raise DeltaError("catalog has no rules")
    jumps={}
    for j in catalog.get("jumps",[]):
        source=int(j.get("source_rule",j.get("source",-1)))
        target=int(j.get("target_rule",j.get("target",-1)))
        kind=j.get("branch_kind")
        if source<0 or target<0 or source>=len(rules) or target>=len(rules) or kind not in ("b","tbz"):
            raise DeltaError("invalid dynamic jump redirect in catalog")
        if source in jumps: raise DeltaError("duplicate dynamic jump source")
        jumps[source]={"target_rule":target,"branch_kind":kind}
    results=[]
    counts={"anchors":0,"mutating_rules":0,"dynamic_redirects":0,
            "same_instruction_class":0,"instruction_class_changes":0,
            "mnemonic_changes":0,"unknown_original":0,"masked_original_templates":0}
    for pos,r in enumerate(rules):
        idx=int(r.get("index",pos))
        sig=r.get("signature")
        if not isinstance(sig,list) or not sig: raise DeltaError(f"rule {idx}: missing signature")
        pi=int(r.get("patch_word_index",-1))
        if pi<0 or pi>=len(sig): raise DeltaError(f"rule {idx}: patch index outside signature")
        original_word=word(sig[pi].get("value"))
        original_mask=word(sig[pi].get("mask"))
        original=decode(original_word)
        mutates=bool(r.get("change"))
        row={"rule_index":idx,"name":r.get("name",""),"signature_id":r.get("signature_id"),
             "patch_word_index":pi,"original_word":f"0x{original_word:08x}",
             "original_mask":f"0x{original_mask:08x}",
             "original_word_fully_constrained":original_mask==0xffffffff,
             "original_instruction":instruction_facts(original),
             "mutates":mutates,"evidence":"source-catalog declaration; binary occurrence not verified"}
        if not mutates:
            counts["anchors"]+=1
            row["classification"]="anchor_only"
            row["effective_replacement"]=None
            results.append(row);continue
        counts["mutating_rules"]+=1
        replacement_word=word(r.get("replacement_word"))
        replacement=decode(replacement_word)
        row["declared_replacement_word"]=f"0x{replacement_word:08x}"
        row["declared_replacement_instruction"]=instruction_facts(replacement)
        if original_mask!=0xffffffff: counts["masked_original_templates"]+=1
        if original["class"]=="unknown": counts["unknown_original"]+=1
        if idx in jumps:
            jump=jumps[idx];target=jump["target_rule"]
            target_name=rules[target].get("name","")
            if jump["branch_kind"]=="tbz":
                effective={"class":"branch","mnemonic":"tbz","operands":["w8","#0",f"<rule {target}: {target_name}>"]}
            else:
                effective={"class":"branch","mnemonic":"b","operands":[f"<rule {target}: {target_name}>"]}
            row["classification"]="dynamic_control_flow_redirect"
            row["effective_replacement"]=instruction_facts(effective)
            row["dynamic_redirect"]={"target_rule":target,"target_name":target_name,"branch_kind":jump["branch_kind"]}
            counts["dynamic_redirects"]+=1
            effective_class=effective["class"]
            effective_mnemonic=effective["mnemonic"]
        else:
            row["effective_replacement"]=instruction_facts(replacement)
            effective_class=replacement["class"]
            effective_mnemonic=replacement["mnemonic"]
            row["classification"]="instruction_replacement"
        if original["class"]==effective_class: counts["same_instruction_class"]+=1
        else: counts["instruction_class_changes"]+=1
        if original["mnemonic"]!=effective_mnemonic: counts["mnemonic_changes"]+=1
        row["instruction_class_changed"]=original["class"]!=effective_class
        row["mnemonic_changed"]=original["mnemonic"]!=effective_mnemonic
        row["flags_semantics_review_required"]=(original.get("mnemonic") in FLAG_WRITERS or effective_mnemonic in FLAG_WRITERS)
        row["original_is_masked_template"]=original_mask!=0xffffffff
        row["function_identity"]="not established"
        row["control_flow_context"]="not established without donor disassembly"
        results.append(row)
    return {"schema_version":1,"artifact":"Phoenix PMU source-only patch delta audit",
      "provenance":catalog.get("provenance",{}),
      "scope":{"donor_binary_required":False,"source_catalog_analyzed":True,
        "binary_signature_matches_verified":False,"function_boundaries_known":False,
        "complete_control_flow_known":False,"hardware_validation":False,
        "patch_application":False,"device_accessed":False},
      "summary":{"rule_count":len(results),**counts},
      "rules":results,
      "interpretation":[
        "This report compares the reference patcher's source-declared signature word and replacement, including dynamic branch redirects.",
        "A masked original word is a pattern template; wildcard bits are not known concrete operands.",
        "A source-declared rule is not evidence that its signature exists in a donor or target binary.",
        "Function identity, surrounding control flow, runtime register values, and hardware effects remain unverified.",
        "Dynamic redirect targets are rule relationships, not resolved machine addresses.",
        "No binary is modified, executed, decrypted, decompressed, signed, or restored."
      ]}

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("catalog",type=Path,nargs="?",default=ROOT/"research"/"PMU-SIGNATURE-CATALOG.json")
    p.add_argument("-o","--output",type=Path,default=ROOT/"research"/"PMU-PATCH-DELTA-AUDIT.json")
    a=p.parse_args(argv)
    try:
        cat=json.loads(a.catalog.read_text(encoding="utf-8"))
        report=audit(cat)
        a.output.parent.mkdir(parents=True,exist_ok=True)
        if a.output.exists() and a.output.resolve()!= (ROOT/"research"/"PMU-PATCH-DELTA-AUDIT.json").resolve():
            raise DeltaError(f"refusing to overwrite existing output: {a.output}")
        a.output.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
        print("rules:",report["summary"]["rule_count"])
        print("mutating:",report["summary"]["mutating_rules"],"anchors:",report["summary"]["anchors"])
        print("dynamic redirects:",report["summary"]["dynamic_redirects"])
        print("report:",a.output)
        return 0
    except (OSError,UnicodeError,json.JSONDecodeError,DeltaError,KeyError,TypeError,ValueError) as exc:
        print("phoenix-pmu-delta:",exc,file=sys.stderr);return 2
if __name__=="__main__": raise SystemExit(main())
