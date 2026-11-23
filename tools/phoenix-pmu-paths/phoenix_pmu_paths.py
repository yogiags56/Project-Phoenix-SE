#!/usr/bin/env python3
"""Build a conservative source-derived graph of PMU LDO patch paths.

Only patcher-declared dynamic redirects and explicitly documented local
fall-through edges are emitted. Signature windows are not concatenated into
a complete CFG. No donor binary, offsets, runtime values, or hardware claims.
"""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
class PathModelError(ValueError):
    pass

def build(catalog):
    rules = catalog.get("rules")
    if not isinstance(rules, list):
        raise PathModelError("catalog rules missing")
    by_id = {r.get("index"): r for r in rules if isinstance(r.get("index"), int)}
    required = list(range(54, 70))
    if any(i not in by_id for i in required):
        raise PathModelError("catalog must contain LDO rules 54 through 69")
    jumps = catalog.get("jumps", [])
    edges = []
    seen = set()
    for j in jumps:
        src = int(j.get("source_rule", j.get("source", -1)))
        dst = int(j.get("target_rule", j.get("target", -1)))
        if src not in by_id or dst not in by_id:
            raise PathModelError(f"redirect {src}->{dst} references missing rule")
        if src not in required or dst not in required:
            continue
        kind = j.get("branch_kind")
        if kind not in ("b", "tbz"):
            raise PathModelError(f"unsupported redirect kind for {src}->{dst}: {kind}")
        condition = "always"
        predicate = None
        if kind == "tbz":
            if src != 61 or dst != 67:
                raise PathModelError("unexpected TBZ redirect; review source documentation")
            condition = "W8[0] == 0"
            predicate = {"register":"W8","bit":0,"test":"zero"}
        edge = {"from":src,"to":dst,"kind":"dynamic_redirect",
                "instruction":kind.upper(),"condition":condition,
                "evidence":"prepare_jumps() source-derived redirect table",
                "destination_address_resolved":False}
        if predicate: edge["predicate"] = predicate
        edges.append(edge); seen.add((src,dst,"dynamic_redirect"))
    # Source-derived immediate fall-through: TBZ not taken when bit 0 is set,
    # so execution reaches the following patched site (rule 62).
    if (61,67,"dynamic_redirect") not in seen:
        raise PathModelError("required rule 61 TBZ redirect missing")
    edges.append({"from":61,"to":62,"kind":"conditional_fallthrough",
        "instruction":"TBZ W8, #0, <rule 67>",
        "condition":"W8[0] == 1 (branch not taken)",
        "evidence":"adjacent rule-61/rule-62 patch-site sequence in source-derived LDO trace",
        "destination_address_resolved":False})
    edges.sort(key=lambda e:(e["from"],e["to"],e["kind"]))
    # Explicit path summaries are not inferred by graph search: these are the
    # two source-described sequences, kept separate from unknown predecessors.
    path_summaries = [
      {"id":"debug-entry-to-main","steps":[59,66],
       "condition":"unconditional dynamic branch",
       "status":"source-declared redirect; entry predecessor unknown"},
      {"id":"alternate-enable-normal","steps":[65,60,61,67],
       "condition":"W8 bit 0 is clear at rule 61",
       "status":"source-described redirect sequence; entry predecessor unknown"},
      {"id":"alternate-enable-option","steps":[65,60,61,62,68],
       "condition":"W8 bit 0 is set at rule 61, so TBZ is not taken",
       "status":"source-described redirect and fall-through sequence; entry predecessor unknown"}
    ]
    patch_sites=[]
    for i in required:
        r=by_id[i]
        patch_sites.append({"rule":i,"name":r.get("name"),
          "mutates":bool(r.get("change")),
          "patch_word_index":r.get("patch_word_index"),
          "original_word":r.get("signature",[])[r.get("patch_word_index",0)].get("value")
             if r.get("signature") else None,
          "replacement_word":r.get("replacement_word"),
          "interpretation":{
            57:"static NOP replacement; removes original MOVK instruction",
            60:"LSRV X8, X8, X26 replacement; no NZCV update",
            61:"dynamic TBZ W8, #0 redirect to rule 67",
            62:"dynamic unconditional branch to rule 68",
            65:"dynamic unconditional branch to rule 60"
          }.get(i,"source-table mutation or anchor; no additional path semantics asserted")})
    return {
      "schema_version":1,
      "artifact":"Phoenix PMU LDO conservative symbolic path model",
      "provenance":catalog.get("provenance",{}),
      "scope":{"source_catalog_only":True,"donor_binary_required":False,
        "patcher_declared_redirects_only":True,"documented_fallthrough_only":True,
        "complete_cfg_reconstructed":False,"all_predecessors_known":False,
        "branch_displacements_resolved":False,"runtime_register_values_known":False,
        "hardware_behavior_validated":False,"patch_application":False},
      "summary":{"ldo_rules":16,"dynamic_redirect_edges":len(jumps),
        "conditional_fallthrough_edges":1,"total_edges":len(edges),
        "documented_path_summaries":len(path_summaries)},
      "nodes":[{"rule":i,"name":by_id[i].get("name"),
        "kind":"anchor" if not by_id[i].get("change") else "patch_site"} for i in required],
      "edges":edges,"path_summaries":path_summaries,"patch_sites":patch_sites,
      "unresolved":["Predecessors into rules 54, 59, and 65.",
        "Complete function boundaries and unobserved edges.",
        "Exact runtime branch displacements and matched file offsets.",
        "Whether W26 at the main anchor reaches X26 at rule 60 on the relevant path.",
        "Runtime values of W8 and the physical meaning of its bit 0.",
        "Electrical correctness of the modified LDO behavior on any target PMU."],
      "interpretation":["A dynamic redirect edge is derived from the C patcher's prepare_jumps metadata.",
        "The rule-61 not-taken edge to rule 62 is explicitly documented as local fall-through.",
        "Path summaries preserve unknown entry predecessors and are not proof of complete reachability.",
        "Rules 54–58 are retained as patch sites; no unverified edge is invented between them."]
    }

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("catalog",nargs="?",type=Path,default=ROOT/"research"/"PMU-SIGNATURE-CATALOG.json")
    p.add_argument("-o","--output",type=Path,default=ROOT/"research"/"PMU-LDO-SYMBOLIC-PATHS.json")
    a=p.parse_args(argv)
    try:
        catalog=json.loads(a.catalog.read_text(encoding="utf-8"))
        report=build(catalog)
        a.output.parent.mkdir(parents=True,exist_ok=True)
        a.output.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
        print("LDO rules:",report["summary"]["ldo_rules"])
        print("edges:",report["summary"]["total_edges"])
        print("documented paths:",report["summary"]["documented_path_summaries"])
        print("report:",a.output)
        return 0
    except (OSError,UnicodeError,json.JSONDecodeError,PathModelError,ValueError,TypeError,KeyError) as exc:
        print("phoenix-pmu-paths:",exc,file=sys.stderr);return 2
if __name__=="__main__":
    raise SystemExit(main())
