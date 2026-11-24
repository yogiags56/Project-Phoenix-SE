#!/usr/bin/env python3
"""Audit original-vs-patched control and register effects for PMU LDO redirects.

The catalog contains masked instruction templates and source-declared branch
targets. This report compares instruction semantics without resolving binary
addresses, runtime flags/register values, or hardware behavior.
"""
from __future__ import annotations
import argparse,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"tools"/"phoenix-pmu-semantic"))
try:
    from phoenix_pmu_semantic import decode
except ImportError:
    decode=None

class ControlDeltaError(ValueError): pass

EXPECTED={59:(66,"b"),61:(67,"tbz"),62:(68,"b"),65:(60,"b")}

def reg_effect(d):
    m=d.get("mnemonic");o=d.get("operands",[])
    if m in ("mov","movz","movn","movk","adr","adrp"):
        if not o:return {"reads":[],"writes":[]}
        reads=[o[1]] if m=="mov" and len(o)>1 else ([o[0]] if m=="movk" else [])
        return {"reads":reads,"writes":[o[0]]}
    if m in ("cbz","cbnz","tbz","tbnz"):
        return {"reads":[o[0]] if o else [],"writes":[]}
    if m and m.startswith("b"):
        return {"reads":[],"writes":[]}
    return {"reads":[],"writes":[]}

def original_condition(d):
    m=d.get("mnemonic");o=d.get("operands",[])
    if m=="cbz":return {"kind":"register_zero","expression":f"{o[0]} == 0"}
    if m=="cbnz":return {"kind":"register_nonzero","expression":f"{o[0]} != 0"}
    if m=="b.eq":return {"kind":"nzcv","expression":"Z == 1"}
    if m=="b.ne":return {"kind":"nzcv","expression":"Z == 0"}
    if m and m.startswith("b."):return {"kind":"nzcv","expression":f"condition {m[2:]}"}
    return {"kind":"unconditional" if m=="b" else "none","expression":"always" if m=="b" else None}

def patched_semantics(kind,target):
    if kind=="b":
        return {"mnemonic":"b","class":"branch","condition":{"kind":"unconditional","expression":"always"},
                "reads":[],"writes":[],"target_rule":target,"target_address_resolved":False}
    if kind=="tbz":
        return {"mnemonic":"tbz","class":"branch","condition":{"kind":"bit_zero","expression":"W8[0] == 0"},
                "reads":["W8"],"writes":[],"tested_register":"W8","tested_bit":0,
                "target_rule":target,"target_address_resolved":False}
    raise ControlDeltaError(f"unsupported dynamic branch kind: {kind}")

def build(catalog):
    if decode is None:raise ControlDeltaError("Phoenix semantic decoder unavailable")
    rules={r.get("index"):r for r in catalog.get("rules",[]) if isinstance(r.get("index"),int)}
    jumps=catalog.get("jumps")
    if not isinstance(jumps,list):raise ControlDeltaError("catalog jumps missing")
    actual={}
    for j in jumps:
        src=int(j.get("source_rule",j.get("source",-1)))
        dst=int(j.get("target_rule",j.get("target",-1)))
        kind=j.get("branch_kind")
        if src in EXPECTED:
            if (dst,kind)!=EXPECTED[src]:raise ControlDeltaError(f"rule {src}: redirect differs from source-pinned expectation")
            if src in actual:raise ControlDeltaError(f"duplicate redirect for rule {src}")
            actual[src]=(dst,kind)
    if set(actual)!=set(EXPECTED):raise ControlDeltaError("catalog must include all four LDO dynamic redirects")
    rows=[]
    for src,(dst,kind) in sorted(actual.items()):
        r=rules.get(src)
        if not r:raise ControlDeltaError(f"missing source rule {src}")
        pi=r.get("patch_word_index");sig=r.get("signature",[])
        if not isinstance(pi,int) or not 0<=pi<len(sig):raise ControlDeltaError(f"rule {src}: invalid patch index")
        item=sig[pi];word=int(item["value"],16);mask=int(item["mask"],16)
        d=decode(word)
        if d.get("class")=="unknown":raise ControlDeltaError(f"rule {src}: original instruction not decoded")
        # A masked template can safely identify an opcode only if the decoder's
        # major opcode bits are constrained. Keep all displacement fields unknown.
        if mask!=0xffffffff and (mask & 0xff000000)!=0xff000000:
            raise ControlDeltaError(f"rule {src}: mask does not fully constrain opcode byte")
        orig={"word":item["value"],"mask":item["mask"],"fully_constrained":mask==0xffffffff,
              "mnemonic":d.get("mnemonic"),"class":d.get("class"),
              "operands":d.get("operands",[]),"condition":original_condition(d),
              "register_effects":reg_effect(d)}
        if not orig["fully_constrained"]:
            orig["operands"]=[x for x in orig["operands"] if not (isinstance(x,str) and x.startswith(("+","-","0x")))]
            orig["displacement_known"]=False
        else:orig["displacement_known"]=d.get("branch_displacement") is not None
        patched=patched_semantics(kind,dst)
        rows.append({"source_rule":src,"source_name":r.get("name"),"target_rule":dst,
          "original":orig,"patched":patched,
          "delta":{"control_flow_changed":orig["class"]!="branch" or
                    orig["mnemonic"]!=patched["mnemonic"] or
                    orig["condition"]!=patched["condition"],
                   "original_condition":orig["condition"],"patched_condition":patched["condition"],
                   "original_register_effects":orig["register_effects"],
                   "patched_register_effects":{"reads":patched["reads"],"writes":patched["writes"]},
                   "interpretation":"Source-level instruction transformation; runtime reachability and correctness unverified."}})
    static57=rules.get(57)
    if not static57:raise ControlDeltaError("missing rule 57 static NOP reference")
    pi=static57["patch_word_index"];item=static57["signature"][pi]
    original57=decode(int(item["value"],16))
    replacement57=decode(int(static57["replacement_word"],16))
    return {"schema_version":1,"artifact":"Phoenix PMU LDO control-flow patch delta audit",
      "provenance":catalog.get("provenance",{}),
      "scope":{"source_catalog_only":True,"donor_binary_required":False,
       "dynamic_redirects_compared":True,"runtime_branch_targets_resolved":False,
       "complete_cfg_reconstructed":False,"runtime_registers_and_flags_known":False,
       "hardware_behavior_validated":False,"patch_application":False},
      "summary":{"dynamic_redirects":len(rows),
       "original_conditional_redirects":sum(x["original"]["condition"]["kind"] not in ("unconditional","none") for x in rows),
       "patched_conditional_redirects":sum(x["patched"]["condition"]["kind"] not in ("unconditional","none") for x in rows),
       "register_write_sites_removed":sum(bool(x["original"]["register_effects"]["writes"]) and not x["patched"]["writes"] for x in rows),
       "control_flow_transformations":sum(x["delta"]["control_flow_changed"] for x in rows)},
      "redirects":rows,
      "static_nop_contrast":{"rule":57,"original_word":item["value"],
       "original_mnemonic":original57.get("mnemonic"),"replacement_word":static57["replacement_word"],
       "replacement_mnemonic":replacement57.get("mnemonic"),
       "dynamic_redirect":False,"interpretation":"Static NOP replacement; not overwritten by prepare_jumps() according to the source audit."},
      "findings":[
       "Rule 59 replaces a masked CBZ W8 instruction with an unconditional B to rule 66; the original zero-test condition is removed.",
       "Rule 61 replaces MOV W9, W23 with TBZ W8, #0 to rule 67; a register copy becomes a conditional branch and W9 is no longer written at that patch site.",
       "Rule 62 replaces MOV W10, W20 with an unconditional B to rule 68; W10 is no longer written at that patch site.",
       "Rule 65 replaces a masked B.NE instruction with an unconditional B to rule 60; the original NZCV condition is removed.",
       "Rule 57 is a static NOP mutation, contrasting with the four dynamic redirects."],
      "limitations":["Masked original words are opcode templates; wildcard displacement bits are not reconstructed.",
       "The report compares the instruction at each source-declared patch site only; it does not prove the surrounding code's correctness.",
       "Register liveness, flag producers, branch displacements, and target file offsets require an extracted matching kernel binary.",
       "No firmware was patched and no device or PMU was tested."]}

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("catalog",nargs="?",type=Path,default=ROOT/"research"/"PMU-SIGNATURE-CATALOG.json")
    p.add_argument("-o","--output",type=Path,default=ROOT/"research"/"PMU-LDO-CONTROL-DELTA.json")
    a=p.parse_args(argv)
    try:
        report=build(json.loads(a.catalog.read_text(encoding="utf-8")))
        a.output.parent.mkdir(parents=True,exist_ok=True)
        a.output.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
        print("dynamic redirects:",report["summary"]["dynamic_redirects"])
        print("original conditional redirects:",report["summary"]["original_conditional_redirects"])
        print("patched conditional redirects:",report["summary"]["patched_conditional_redirects"])
        print("report:",a.output)
        return 0
    except (OSError,UnicodeError,json.JSONDecodeError,ControlDeltaError,ValueError,KeyError,TypeError) as exc:
        print("phoenix-pmu-cf-delta:",exc,file=sys.stderr);return 2
if __name__=="__main__":raise SystemExit(main())
