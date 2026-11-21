#!/usr/bin/env python3
"""Extract PMU signature and mutation metadata from the reference C source."""
from __future__ import annotations
import argparse, hashlib, json, re, sys
from collections import Counter
from pathlib import Path
WORD = re.compile(r"\{\s*(0x[0-9a-fA-F]+)u,\s*(0x[0-9a-fA-F]+)u\s*\}")
RULE = re.compile(r'\{"([^"]+)",\s*sig(\d+),\s*COUNT\(sig\d+\),\s*(\d+),\s*(0x[0-9a-fA-F]+)u,\s*([01]),\s*0\}')
def parse(source: str, blob_sha: str = "") -> dict:
    declarations = re.findall(r"static const Word\s+sig(\d+)\s*\[\]\s*=\s*\{([\s\S]*?)\};", source)
    rules_raw = list(RULE.finditer(source))
    if len(declarations) != 70 or len(rules_raw) != 70:
        raise ValueError(f"expected 70 signature arrays and 70 rules; found {len(declarations)} and {len(rules_raw)}")
    signatures = {}
    for ident, body in declarations:
        words = [{"value": a.lower(), "mask": b.lower()} for a, b in WORD.findall(body)]
        if not words or ident in signatures:
            raise ValueError(f"empty or duplicate signature array sig{ident}")
        signatures[ident] = words
    rules = []
    for index, m in enumerate(rules_raw):
        name, ident, at, replacement, change = m.groups()
        if ident not in signatures:
            raise ValueError(f"rule {index} refers to missing sig{ident}")
        words = signatures[ident]
        if int(at) >= len(words):
            raise ValueError(f"rule {index} patch word index outside signature")
        rules.append({"index": index, "name": name, "signature_id": int(ident),
          "signature_word_count": len(words), "patch_word_index": int(at),
          "replacement_word": replacement.lower(), "change": change == "1", "signature": words})
    jm = re.search(r"static const Jump jumps\[\]\s*=\s*\{([\s\S]*?)\};", source)
    if not jm: raise ValueError("missing jumps[]")
    jumps = [{"source_rule": int(a), "target_rule": int(b), "branch_kind": "tbz" if c == "1" else "b"}
             for a,b,c in re.findall(r"\{\s*(\d+),\s*(\d+),\s*([01])\s*\}", jm.group(1))]
    if len(jumps) != 4 or any(max(j["source_rule"],j["target_rule"]) >= len(rules) for j in jumps):
        raise ValueError("unexpected jump map")
    def byte_array(name):
        m = re.search(rf"static const unsigned char {name}\[\]\s*=\s*\{{([\s\S]*?)\}};", source)
        if not m: raise ValueError(f"missing {name}")
        return [int(x,16) for x in re.findall(r"0x([0-9a-fA-F]{2})",m.group(1))]
    before, after = byte_array("ldo_before"), byte_array("ldo_after")
    if len(before) != len(after): raise ValueError("LDO table lengths differ")
    changed = [{"offset":i,"before":a,"after":b} for i,(a,b) in enumerate(zip(before,after)) if a != b]
    groups = dict(Counter(r["name"] for r in rules))
    return {"schema_version":1,"artifact":"Phoenix PMU signature and mutation catalog",
      "provenance":{"repository":"pwnerblu/iphonese-ios16","path":"patchsrc/pmuhax.c","branch":"main",
        "source_blob_sha":blob_sha,"source_sha256":hashlib.sha256(source.encode()).hexdigest(),
        "source_url":"https://github.com/pwnerblu/iphonese-ios16/blob/main/patchsrc/pmuhax.c"},
      "scope":{"source_extraction_only":True,"hardware_validation":False,"patch_application":False,"arm64_semantics_decoded":False},
      "summary":{"rule_count":len(rules),"signature_declaration_count":len(signatures),
        "mutating_rule_count":sum(r["change"] for r in rules),"anchor_rule_count":sum(not r["change"] for r in rules),
        "jump_redirect_count":len(jumps),"ldo_before_bytes":len(before),"ldo_after_bytes":len(after),
        "ldo_changed_byte_count":len(changed),"groups":groups},
      "rules":rules,"jumps":jumps,
      "ldo_table":{"before_length":len(before),"after_length":len(after),
        "before_hex":"".join(f"{x:02x}" for x in before),"after_hex":"".join(f"{x:02x}" for x in after),
        "changed_bytes":changed}}
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("source",type=Path,help="reference pmuhax.c")
    p.add_argument("-o","--output",type=Path,default=Path("pmu-signature-catalog.json"))
    p.add_argument("--blob-sha",default="",help="Git blob SHA recorded from the source repository")
    a=p.parse_args()
    try:
        raw=a.source.read_bytes(); source=raw.decode("utf-8")
        result=parse(source,a.blob_sha)
        result["provenance"]["source_sha256"]=hashlib.sha256(raw).hexdigest()
        a.output.parent.mkdir(parents=True,exist_ok=True)
        a.output.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
        print(f"rules={result['summary']['rule_count']} mutating={result['summary']['mutating_rule_count']} anchors={result['summary']['anchor_rule_count']}")
        print(f"jumps={result['summary']['jump_redirect_count']} LDO bytes={result['summary']['ldo_before_bytes']} changed={result['summary']['ldo_changed_byte_count']}")
        print(f"output={a.output}")
        return 0
    except (OSError,UnicodeError,ValueError) as e:
        print(f"phoenix-pmu-catalog: {e}",file=sys.stderr); return 2
if __name__=="__main__": raise SystemExit(main())
