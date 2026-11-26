#!/usr/bin/env python3
"""Source-derived local liveness and flag-provenance audit for dynamic PMU patches.

This is deliberately limited to each catalog signature window. It identifies
nearby producers for branch operands and local suffix uses; it does not build a
binary CFG or prove whole-function liveness.
"""
from __future__ import annotations
import argparse,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"tools"/"phoenix-pmu-dataflow"))
try:
    from phoenix_pmu_dataflow import decode_extended,effects
except ImportError:
    decode_extended=None
    effects=None

class LivenessError(ValueError):pass
EXPECTED={59:(66,"b"),61:(67,"tbz"),62:(68,"b"),65:(60,"b")}

def canonical_name(reg):
    if reg in ("xzr","wzr"):return None
    if reg in ("sp","wsp"):return "sp"
    if len(reg)>1 and reg[0] in "xw" and reg[1:].isdigit():return "r"+reg[1:]
    return None

def patched_effect(kind):
    if kind=="b":return {"mnemonic":"b","reads":[],"writes":[],"flags_read":False,"flags_written":False}
    if kind=="tbz":return {"mnemonic":"tbz","reads":["r8"],"writes":[],"flags_read":False,"flags_written":False}
    raise LivenessError("unsupported dynamic branch kind: "+str(kind))

def decode_effect(word):
    d=decode_extended(word)
    reads,writes,fr,fw,note=effects(d)
    return d,{"reads":reads,"writes":writes,"flags_read":fr,"flags_written":fw,
              "known":d.get("class")!="unknown" and not note.startswith("unsupported"),
              "note":note}

def prelude_provenance(words,patch_index):
    defs={};flag_def=None;barriers=[]
    for i,item in enumerate(words[:patch_index]):
        d,e=decode_effect(int(item["value"],16))
        if not e["known"]:
            barriers.append({"word_index":i,"word":item["value"],"reason":e["note"]})
            defs.clear();flag_def=None
            continue
        for reg in e["reads"]:
            pass
        for reg in e["writes"]:
            defs[reg]={"word_index":i,"word":item["value"],"mnemonic":d.get("mnemonic")}
        if e["flags_written"]:
            flag_def={"word_index":i,"word":item["value"],"mnemonic":d.get("mnemonic")}
    return defs,flag_def,barriers

def suffix_liveness(words,start):
    live=set();flag_live=False;rows=[];unknown=[]
    # Backward straight-line liveness. Branches are treated as ordinary
    # instructions for operand effects; no successor graph is inferred.
    for i in range(len(words)-1,start-1,-1):
        d,e=decode_effect(int(words[i]["value"],16))
        if not e["known"]:
            unknown.append({"word_index":i,"word":words[i]["value"],"reason":e["note"]})
            rows.append({"word_index":i,"mnemonic":d.get("mnemonic"),"status":"unknown-barrier"})
            live.clear();flag_live=False
            continue
        before=set(live)
        live.difference_update(e["writes"])
        live.update(e["reads"])
        if e["flags_written"]:flag_live=False
        if e["flags_read"]:flag_live=True
        rows.append({"word_index":i,"mnemonic":d.get("mnemonic"),
          "reads":e["reads"],"writes":e["writes"],"live_after":sorted(before),
          "live_before":sorted(live),"flags_live_before":flag_live})
    rows.reverse()
    return {"live_in_registers":sorted(live) if not unknown else None,
      "flags_live_in":flag_live if not unknown else None,
      "unknown_barriers":list(reversed(unknown)),"instructions":rows,
      "certainty":"complete within decoded straight-line suffix" if not unknown else "indeterminate because suffix contains unsupported instruction"}

def build(catalog):
    if decode_extended is None or effects is None:raise LivenessError("Phoenix PMU data-flow decoder unavailable")
    rules={r.get("index"):r for r in catalog.get("rules",[]) if isinstance(r.get("index"),int)}
    actual={}
    for j in catalog.get("jumps",[]):
        src=int(j.get("source_rule",j.get("source",-1)));dst=int(j.get("target_rule",j.get("target",-1)));kind=j.get("branch_kind")
        if src in EXPECTED:
            if (dst,kind)!=EXPECTED[src]:raise LivenessError(f"rule {src}: redirect differs from pinned source metadata")
            if src in actual:raise LivenessError(f"duplicate redirect for rule {src}")
            actual[src]=(dst,kind)
    if set(actual)!=set(EXPECTED):raise LivenessError("catalog must contain all four source-declared redirects")
    rows=[]
    for src,(dst,kind) in sorted(actual.items()):
        r=rules.get(src)
        if not r:raise LivenessError(f"missing rule {src}")
        pi=r.get("patch_word_index");sig=r.get("signature",[])
        if not isinstance(pi,int) or not 0<=pi<len(sig):raise LivenessError(f"rule {src}: invalid patch index")
        item=sig[pi];mask=int(item["mask"],16);orig_d,orig_e=decode_effect(int(item["value"],16))
        if not orig_e["known"]:raise LivenessError(f"rule {src}: original patch instruction undecodable")
        if mask!=0xffffffff and (mask&0xff000000)!=0xff000000:
            raise LivenessError(f"rule {src}: opcode byte is not fully constrained")
        defs,flag_def,pre_barriers=prelude_provenance(sig,pi)
        replacement=patched_effect(kind)
        orig_uses={x:defs.get(x) for x in orig_e["reads"]}
        patched_uses={x:defs.get(x) for x in replacement["reads"]}
        suffix=suffix_liveness(sig,pi+1)
        removed_writes=sorted(set(orig_e["writes"])-set(replacement["writes"]))
        live_out={}
        for reg in removed_writes:
            if suffix["live_in_registers"] is None:status="indeterminate"
            elif reg in suffix["live_in_registers"]:status="read-on-local-fallthrough"
            else:status="not-read-in-decoded-local-suffix"
            live_out[reg]=status
        rows.append({"rule":src,"name":r.get("name"),"patch_word_index":pi,
          "original":{"word":item["value"],"mask":item["mask"],"mnemonic":orig_d.get("mnemonic"),
            "operands":orig_d.get("operands",[]),"effects":orig_e},
          "patched":{"kind":kind,"target_rule":dst,**replacement},
          "prelude":{"register_definitions":defs,"flag_definition":flag_def,
            "unknown_barriers":pre_barriers,
            "original_operand_producers":orig_uses,"patched_operand_producers":patched_uses},
          "removed_register_definitions":removed_writes,
          "local_suffix_liveness":suffix,"removed_definition_status":live_out,
          "flag_delta":{"original_reads_NZCV":orig_e["flags_read"],
            "patched_reads_NZCV":replacement["flags_read"],
            "nearest_local_NZCV_definition":flag_def if orig_e["flags_read"] else None},
          "interpretation":"Local signature-window evidence only; not whole-function liveness or runtime reachability."})
    return {"schema_version":1,"artifact":"Phoenix PMU dynamic patch local liveness and flag provenance",
      "provenance":catalog.get("provenance",{}),
      "scope":{"source_catalog_only":True,"donor_binary_required":False,
       "four_dynamic_redirects_only":True,"signature_windows_are_local_templates":True,
       "straight_line_suffix_analysis":True,"whole_function_liveness":False,
       "complete_cfg":False,"runtime_values_known":False,"binary_addresses_resolved":False,
       "hardware_behavior_validated":False,"patch_application":False},
      "summary":{"dynamic_patch_sites":len(rows),
       "sites_with_local_flag_producer":sum(bool(x["flag_delta"]["nearest_local_NZCV_definition"]) for x in rows),
       "removed_register_definitions":sum(len(x["removed_register_definitions"]) for x in rows),
       "suffixes_with_unknown_barriers":sum(bool(x["local_suffix_liveness"]["unknown_barriers"]) for x in rows)},
      "sites":rows,
      "limitations":["Signature windows are not complete basic blocks or functions.",
       "The suffix analysis is straight-line and does not follow conditional branch successors.",
       "Register definitions are tracked only from the prefix of the same signature window.",
       "Unsupported instructions invalidate local reaching-definition or liveness certainty.",
       "Masked branch displacement bits are not resolved to binary addresses.",
       "No donor firmware was read, modified, or executed."]}

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("catalog",nargs="?",type=Path,default=ROOT/"research"/"PMU-SIGNATURE-CATALOG.json")
    p.add_argument("-o","--output",type=Path,default=ROOT/"research"/"PMU-LDO-PATCH-LIVENESS.json")
    a=p.parse_args(argv)
    try:
        report=build(json.loads(a.catalog.read_text(encoding="utf-8")))
        a.output.parent.mkdir(parents=True,exist_ok=True)
        a.output.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
        print("dynamic patch sites:",report["summary"]["dynamic_patch_sites"])
        print("local NZCV producers:",report["summary"]["sites_with_local_flag_producer"])
        print("removed register definitions:",report["summary"]["removed_register_definitions"])
        print("suffixes with unknown barriers:",report["summary"]["suffixes_with_unknown_barriers"])
        print("report:",a.output)
        return 0
    except (OSError,UnicodeError,json.JSONDecodeError,LivenessError,ValueError,KeyError,TypeError) as exc:
        print("phoenix-pmu-patch-liveness:",exc,file=sys.stderr);return 2
if __name__=="__main__":raise SystemExit(main())
