#!/usr/bin/env python3
"""Build an evidence-labelled dependency graph from Phoenix kext and KC reports."""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

class GraphError(ValueError):
    pass

def load_json(path, expected_tool):
    try:
        raw=Path(path).read_bytes()
        obj=json.loads(raw.decode("utf-8"))
    except (OSError,UnicodeDecodeError,json.JSONDecodeError) as exc:
        raise GraphError("Cannot read %s: %s"%(path,exc)) from exc
    if not isinstance(obj,dict) or obj.get("tool")!=expected_tool:
        raise GraphError("%s must be a JSON report from %s"%(path,expected_tool))
    return obj,hashlib.sha256(raw).hexdigest()

def safe_id(value):
    return re.sub(r"[^A-Za-z0-9_.-]+","_",str(value)).strip("_") or "unnamed"

def build_graph(kext_report,kext_hash,kc_report=None,kc_hash=None,symbol_map=None,symbol_hash=None):
    bundles=kext_report.get("bundles",[])
    dependencies=kext_report.get("dependencies",[])
    if not isinstance(bundles,list) or not isinstance(dependencies,list):
        raise GraphError("Kext report bundles and dependencies must be arrays")
    nodes={}
    edges=[]
    bundle_ids={}
    for index,b in enumerate(bundles):
        if not isinstance(b,dict): continue
        bid=b.get("bundle_id")
        path=b.get("path","")
        key=bid if isinstance(bid,str) and bid else "invalid:"+str(path or index)
        node_id="kext:"+safe_id(key)
        # Duplicate identifiers remain separate nodes, preserving provider ambiguity.
        if node_id in nodes:
            node_id += ":"+str(index)
        required=b.get("required")
        required_text=str(required).strip().lower() if required is not None else ""
        boot_critical=required_text in {"root","local-root","network-root","console"}
        node={
          "id":node_id,"type":"kext" if bid else "invalid-kext",
          "label":bid or str(path or "unknown bundle"),
          "bundle_id":bid,"path":path,"version":b.get("version"),
          "valid":bool(b.get("valid")),"boot_required":required,
          "boot_critical_candidate":boot_critical,
          "evidence":"kext Info.plist metadata"}
        nodes[node_id]=node
        if bid: bundle_ids.setdefault(bid,[]).append(node_id)
    for dep in dependencies:
        if not isinstance(dep,dict): continue
        consumer=dep.get("consumer"); dependency=dep.get("dependency")
        if not isinstance(consumer,str) or not isinstance(dependency,str): continue
        consumers=bundle_ids.get(consumer,[])
        providers=bundle_ids.get(dependency,[])
        if not consumers: continue
        for consumer_id in consumers:
            if providers:
                for provider_id in providers:
                    edges.append({"source":consumer_id,"target":provider_id,
                      "kind":"kext-library-dependency","status":"provider-present",
                      "required_version":dep.get("required_version"),
                      "evidence":"OSBundleLibraries bundle identifier match",
                      "version_constraint_evaluated":False})
            else:
                external_id="dependency:"+safe_id(dependency)
                nodes.setdefault(external_id,{"id":external_id,"type":"external-dependency",
                  "label":dependency,"bundle_id":dependency,"evidence":"unresolved OSBundleLibraries entry"})
                edges.append({"source":consumer_id,"target":external_id,
                  "kind":"kext-library-dependency","status":"unresolved",
                  "required_version":dep.get("required_version"),
                  "evidence":"OSBundleLibraries entry; provider absent from scanned bundle set",
                  "version_constraint_evaluated":False})
    kc_entries=[]
    if kc_report is not None:
        entries=kc_report.get("entries",[])
        if not isinstance(entries,list): raise GraphError("Kernel Collection entries must be an array")
        for entry in entries:
            if not isinstance(entry,dict): continue
            ident=entry.get("identifier")
            embedded=entry.get("embedded_macho",{})
            arch=embedded.get("architecture",{}) if isinstance(embedded,dict) else {}
            kc_entries.append({"identifier":ident,"file_offset":entry.get("file_offset"),
              "embedded_macho_valid":bool(embedded.get("valid")) if isinstance(embedded,dict) else False,
              "architecture":arch if isinstance(arch,dict) else {}})
            if isinstance(ident,str) and ident in bundle_ids:
                kc_id="kc-entry:"+safe_id(ident)
                nodes.setdefault(kc_id,{"id":kc_id,"type":"kernel-collection-entry",
                  "label":ident,"identifier":ident,"evidence":"LC_FILESET_ENTRY identifier"})
                for kext_id in bundle_ids[ident]:
                    edges.append({"source":kc_id,"target":kext_id,
                      "kind":"identifier-correlation","status":"identifier-match",
                      "evidence":"Exact fileset entry identifier equals kext CFBundleIdentifier",
                      "compatibility_proven":False})
    if symbol_map is not None:
        mappings=symbol_map.get("providers",[])
        if not isinstance(mappings,list): raise GraphError("Symbol map providers must be an array")
        for item in mappings:
            if not isinstance(item,dict): continue
            symbol=item.get("symbol"); consumer=item.get("consumer_bundle_id")
            provider=item.get("provider_bundle_id")
            if not all(isinstance(x,str) and x for x in (symbol,consumer,provider)):
                continue
            consumers=bundle_ids.get(consumer,[])
            providers=bundle_ids.get(provider,[])
            if not consumers or not providers: continue
            sym_id="symbol:"+safe_id(symbol)
            nodes.setdefault(sym_id,{"id":sym_id,"type":"symbol","label":symbol,
              "symbol":symbol,"evidence":"Explicit user-supplied provider mapping"})
            for c in consumers:
                edges.append({"source":c,"target":sym_id,"kind":"symbol-reference",
                  "status":"declared-by-mapping","evidence":"Explicit provider mapping; not derived from symbol name alone"})
            for p in providers:
                edges.append({"source":sym_id,"target":p,"kind":"symbol-provider",
                  "status":"declared-by-mapping","evidence":"Explicit provider mapping; loadability not validated"})
    # Deduplicate exact edge records while retaining deterministic ordering.
    unique={}
    for edge in edges:
        key=json.dumps(edge,sort_keys=True,separators=(",",":"))
        unique[key]=edge
    edges=sorted(unique.values(),key=lambda e:(e["source"],e["kind"],e["target"],e["status"]))
    unresolved=sum(1 for e in edges if e["status"]=="unresolved")
    critical=[n["id"] for n in nodes.values() if n.get("boot_critical_candidate")]
    graph={
      "schema_version":1,"tool":"Phoenix Kernel Dependency Graph",
      "inputs":{"kext_report_sha256":kext_hash,
        "kernel_collection_report_sha256":kc_hash,
        "symbol_provider_map_sha256":symbol_hash},
      "nodes":sorted(nodes.values(),key=lambda n:n["id"]),
      "edges":edges,
      "summary":{"node_count":len(nodes),"edge_count":len(edges),
        "kext_node_count":sum(n["type"]=="kext" for n in nodes.values()),
        "unresolved_dependency_edge_count":unresolved,
        "boot_critical_candidate_count":len(critical),
        "kernel_collection_entries_correlated":sum(e["kind"]=="identifier-correlation" for e in edges),
        "explicit_symbol_mapping_edge_count":sum(e["kind"].startswith("symbol-") for e in edges)},
      "boot_critical_candidate_node_ids":sorted(critical),
      "limitations":[
        "Graph edges describe metadata evidence, not proof of runtime loadability or device compatibility.",
        "OSBundleLibraries provider presence is checked by bundle identifier only; version constraints are not evaluated.",
        "Duplicate bundle identifiers can produce multiple candidate providers and must be investigated.",
        "Kernel Collection correlation uses exact identifier equality only; it does not prove that a fileset entry is a loadable kext.",
        "Symbol relationships are included only from an explicit provider-map JSON; symbol-name overlap alone is not treated as a dependency.",
        "Boot-critical candidates are inferred only from selected OSBundleRequired metadata values; this is a review hint, not a verified boot dependency.",
        "No ABI, kernel symbol resolution, executable, signature, entitlement, device-tree, SEP, baseband or hardware validation is performed.",
        "Read-only: no firmware, bundle or device files are modified, patched, signed, executed or restored."]}
    return graph

def render_mermaid(graph):
    lines=["flowchart LR"]
    for n in graph["nodes"]:
        label=n["label"].replace('"',"'").replace("\n"," ")
        lines.append('  "%s"["%s"]'%(n["id"],label))
    styles={"kext-library-dependency":"-->","identifier-correlation":"-.->",
            "symbol-reference":"==>","symbol-provider":"==>"}
    for e in graph["edges"]:
        arrow=styles.get(e["kind"],"-->")
        label=e["kind"].replace('"',"'")
        lines.append('  "%s" %s|%s| "%s"'%(e["source"],arrow,label,e["target"]))
    return "\n".join(lines)+"\n"

def main(argv=None):
    p=argparse.ArgumentParser(description="Build an evidence-labelled Phoenix kernel dependency graph")
    p.add_argument("--kext-report",required=True,type=Path)
    p.add_argument("--kc-report",type=Path)
    p.add_argument("--symbol-provider-map",type=Path,
      help="Optional JSON: {\"providers\":[{\"symbol\":\"_foo\",\"consumer_bundle_id\":\"...\",\"provider_bundle_id\":\"...\"}]}")
    p.add_argument("--out",type=Path,default=Path("phoenix-kernel-dependency-graph.json"))
    p.add_argument("--mermaid-out",type=Path,help="Optional Mermaid flowchart output")
    a=p.parse_args(argv)
    try:
        kr,kh=load_json(a.kext_report,"Phoenix Kext Dependency Analyzer")
        kc=kc_hash=None
        if a.kc_report: kc,kc_hash=load_json(a.kc_report,"Phoenix Kernel Collection Inspector")
        sm=smh=None
        if a.symbol_provider_map:
            try:
                raw=a.symbol_provider_map.read_bytes()
                sm=json.loads(raw.decode("utf-8")); smh=hashlib.sha256(raw).hexdigest()
            except (OSError,UnicodeDecodeError,json.JSONDecodeError) as exc:
                raise GraphError("Cannot read symbol provider map: %s"%exc) from exc
            if not isinstance(sm,dict): raise GraphError("Symbol provider map root must be an object")
        graph=build_graph(kr,kh,kc,kc_hash,sm,smh)
        a.out.parent.mkdir(parents=True,exist_ok=True)
        a.out.write_text(json.dumps(graph,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
        if a.mermaid_out:
            a.mermaid_out.parent.mkdir(parents=True,exist_ok=True)
            a.mermaid_out.write_text(render_mermaid(graph),encoding="utf-8")
        print("Nodes:",graph["summary"]["node_count"])
        print("Edges:",graph["summary"]["edge_count"])
        print("Unresolved dependency edges:",graph["summary"]["unresolved_dependency_edge_count"])
        print("Report written:",a.out)
        if a.mermaid_out: print("Mermaid written:",a.mermaid_out)
        return 0
    except (OSError,GraphError) as exc:
        print("phoenix-kernel-graph: error:",exc,file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
