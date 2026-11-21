#!/usr/bin/env python3
"""Phoenix Firmware Evidence Dashboard: aggregate JSON evidence into HTML and JSON."""
from __future__ import annotations
import argparse
import hashlib
import html
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

class DashboardError(ValueError):
    pass

def parse_input(value):
    if "=" not in value:
        raise argparse.ArgumentTypeError("input must be LABEL=PATH")
    label,path=value.split("=",1)
    if not label.strip() or not path.strip():
        raise argparse.ArgumentTypeError("input label and path must be non-empty")
    return label.strip(),Path(path.strip())

def load_inputs(items):
    reports=[]
    labels=set()
    for label,path in items:
        if label in labels:
            raise DashboardError("Duplicate input label: "+label)
        labels.add(label)
        try:
            raw=path.read_bytes()
            data=json.loads(raw.decode("utf-8"))
        except (OSError,UnicodeDecodeError,json.JSONDecodeError) as exc:
            raise DashboardError("Cannot read %s: %s"%(path,exc)) from exc
        if not isinstance(data,dict):
            raise DashboardError("Report root must be a JSON object: "+str(path))
        reports.append({"label":label,"path":str(path),"sha256":hashlib.sha256(raw).hexdigest(),"data":data})
    if not reports:
        raise DashboardError("At least one report input is required")
    return reports

def scalar(value):
    if value is None: return "not provided"
    if isinstance(value,(str,int,float,bool)): return str(value)
    if isinstance(value,list): return ", ".join(str(x) for x in value[:8]) + (" …" if len(value)>8 else "")
    if isinstance(value,dict): return "{…}"
    return str(value)

def report_facts(data):
    facts=[]
    for key in ("tool","status","indication","product_version","product_build_version","source_file","source_profile","generated_utc"):
        if key in data and data[key] is not None:
            facts.append((key.replace("_"," ").title(),scalar(data[key])))
    if isinstance(data.get("summary"),dict):
        for key,value in list(data["summary"].items())[:12]:
            if isinstance(value,(str,int,float,bool)) or value is None:
                facts.append((key.replace("_"," ").title(),scalar(value)))
    if isinstance(data.get("status_counts"),dict):
        for key,value in data["status_counts"].items():
            facts.append(("Subsystems — "+key.replace("_"," "),scalar(value)))
    if isinstance(data.get("subsystem_count"),int):
        facts.append(("Subsystem count",str(data["subsystem_count"])))
    if isinstance(data.get("device_tested_subsystem_count"),int):
        facts.append(("Device-tested subsystems",str(data["device_tested_subsystem_count"])))
    if isinstance(data.get("limitations"),list):
        facts.append(("Limitations recorded",str(len(data["limitations"]))))
    return facts

def classify(data):
    status=str(data.get("status",data.get("indication",""))).lower()
    if status in {"incompatible","blocked","fail","failed","error"}: return "warning"
    if status in {"potential","unknown","not_assessed","researching","experimental"}: return "caution"
    if status in {"working","success","passed","pass"}: return "positive"
    return "neutral"

def build_manifest(reports):
    entries=[]
    for report in reports:
        data=report["data"]
        entries.append({
          "label":report["label"],"path":report["path"],"sha256":report["sha256"],
          "tool":data.get("tool"),"status":data.get("status",data.get("indication")),
          "facts":[{"name":k,"value":v} for k,v in report_facts(data)],
          "limitations":data.get("limitations",[]) if isinstance(data.get("limitations",[]),list) else [],
        })
    return {
      "schema_version":1,"tool":"Phoenix Firmware Evidence Dashboard",
      "generated_utc":datetime.now(timezone.utc).isoformat(),
      "report_count":len(entries),
      "reports":entries,
      "interpretation":{
        "aggregate_verdict":False,
        "status_is_not_inferred":True,
        "missing_reports_are_not_negative_evidence":True,
        "static_analysis_is_not_device_testing":True,
      },
      "limitations":[
        "The dashboard aggregates supplied JSON reports; it does not independently validate their underlying binary inputs.",
        "Reports may describe different firmware builds or device variants; compare provenance before interpreting them together.",
        "A Potential result is not proof of compatibility. An Unknown result is not proof of incompatibility.",
        "The dashboard does not calculate a single project compatibility verdict or infer subsystem status.",
        "A static-analysis report cannot establish that a feature works on physical iPhone SE hardware.",
        "No firmware is decrypted, modified, patched, signed, executed or restored.",
      ],
    }

def render_html(manifest):
    esc=html.escape
    cards=[]
    for item in manifest["reports"]:
        tone=classify({"status":item["status"]})
        facts="".join('<div class="fact"><span>'+esc(f["name"])+'</span><strong>'+esc(f["value"])+'</strong></div>' for f in item["facts"])
        limits="".join("<li>"+esc(str(x))+"</li>" for x in item["limitations"][:8])
        cards.append(
          '<section class="card"><div class="cardhead"><div><h2>'+esc(item["label"])+'</h2><p>'+esc(str(item["tool"] or "Unidentified report"))+'</p></div><span class="pill '+tone+'">'+esc(str(item["status"] or "No status"))+'</span></div>'
          +'<div class="facts">'+(facts or '<p>No recognized summary fields. Original JSON remains the source of truth.</p>')+'</div>'
          +'<details><summary>Provenance and limitations</summary><p class="hash">File: '+esc(item["path"])+'<br>SHA-256: '+esc(item["sha256"])+'</p>'
          +(("<ul>"+limits+"</ul>") if limits else "<p>No limitations list supplied by this report.</p>")+"</details></section>")
    limitations="".join("<li>"+esc(x)+"</li>" for x in manifest["limitations"])
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark light"><title>Phoenix Firmware Evidence Dashboard</title>
<style>
:root{font-family:system-ui,-apple-system,Segoe UI,sans-serif;color:#e7edf5;background:#101722}
body{margin:0;padding:28px;max-width:1120px;margin-inline:auto}header{padding:24px 0 18px;border-bottom:1px solid #344154}
h1{font-size:clamp(1.7rem,4vw,2.5rem);margin:0 0 8px}h2{font-size:1.1rem;margin:0}p{color:#aebbd0;line-height:1.5}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,330px),1fr));gap:16px;margin:22px 0}
.card{background:#192434;border:1px solid #344154;border-radius:14px;padding:18px;min-width:0}
.cardhead{display:flex;justify-content:space-between;gap:12px;align-items:flex-start}.cardhead p{font-size:.85rem;margin:5px 0}
.pill{font-size:.75rem;border-radius:999px;padding:5px 9px;white-space:nowrap;background:#303b4b}
.positive{background:#174b38;color:#a8f0ca}.warning{background:#63302d;color:#ffd0c8}.caution{background:#5a4821;color:#ffe3a1}
.facts{display:grid;grid-template-columns:1fr 1fr;gap:9px;margin:16px 0}
.fact{background:#111b29;border-radius:8px;padding:9px;min-width:0}.fact span{display:block;color:#9eacc0;font-size:.72rem}.fact strong{display:block;overflow-wrap:anywhere;font-size:.92rem;margin-top:3px}
details{border-top:1px solid #344154;padding-top:12px;color:#c6d1df}summary{cursor:pointer}
.hash{font-size:.75rem;overflow-wrap:anywhere}li{margin:6px 0;color:#bac6d7}
.notice{background:#202d3e;border-left:3px solid #d5a94b;padding:14px 16px;border-radius:8px}
footer{color:#91a0b5;font-size:.8rem;margin:28px 0}
@media(prefers-color-scheme:light){:root{color:#172333;background:#f4f6f9}.card{background:white;border-color:#d6deea}.fact{background:#f1f4f8}.notice{background:#fff6df}p,li,details{color:#526176}.fact span{color:#63728a}}
</style></head><body>
<header><h1>🐦‍🔥 Project Phoenix SE</h1><p>Firmware Evidence Dashboard · Read-only research summary</p>
<p>Generated: """+esc(manifest["generated_utc"])+""" · Reports: """+str(manifest["report_count"])+"""</p></header>
<div class="notice"><strong>No aggregate compatibility verdict.</strong><br>
This dashboard displays supplied evidence independently. Metadata overlap does not prove a newer iOS build can boot on the A9 iPhone SE. Missing evidence is not a negative test result.</div>
<div class="grid">"""+ "".join(cards)+"""</div>
<section class="card"><h2>Global interpretation limits</h2><ul>"""+limitations+"""</ul></section>
<footer>Generated by Phoenix Firmware Evidence Dashboard. Preserve original reports and verify device/build provenance before drawing conclusions.</footer>
</body></html>
"""

def main(argv=None):
    p=argparse.ArgumentParser(description="Aggregate Phoenix JSON evidence reports into a static HTML and JSON dashboard")
    p.add_argument("--input",action="append",type=parse_input,required=True,metavar="LABEL=PATH")
    p.add_argument("--out-json",type=Path,default=Path("phoenix-evidence-dashboard.json"))
    p.add_argument("--out-html",type=Path,default=Path("phoenix-evidence-dashboard.html"))
    a=p.parse_args(argv)
    try:
        reports=load_inputs(a.input)
        manifest=build_manifest(reports)
        a.out_json.parent.mkdir(parents=True,exist_ok=True)
        a.out_html.parent.mkdir(parents=True,exist_ok=True)
        a.out_json.write_text(json.dumps(manifest,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
        a.out_html.write_text(render_html(manifest),encoding="utf-8")
        print("Reports:",manifest["report_count"])
        print("JSON dashboard:",a.out_json)
        print("HTML dashboard:",a.out_html)
        print("Aggregate compatibility verdict: intentionally not inferred")
        return 0
    except (OSError,DashboardError) as exc:
        print("phoenix-dashboard: error:",exc,file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
