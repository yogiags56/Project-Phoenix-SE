#!/usr/bin/env python3
"""Analyze textual ARM64 disassembly (for example, llvm-objdump output)."""
from __future__ import annotations
import argparse,hashlib,json,re,sys
from datetime import datetime,timezone
from pathlib import Path
LINE=re.compile(r"^\s*(?:0x)?([0-9a-fA-F]+):\s*(.*?)\s*$")
MN=re.compile(r"^([A-Za-z][A-Za-z0-9_.]*)\s*(.*?)$")
HEXWORD=re.compile(r"^(?:[0-9a-fA-F]{2}|[0-9a-fA-F]{4}|[0-9a-fA-F]{8})$")
BR={"b","bl","br","blr","ret","cbz","cbnz","tbz","tbnz"}
COND={"b.eq","b.ne","b.cs","b.hs","b.cc","b.lo","b.mi","b.pl","b.vs","b.vc","b.hi","b.ls","b.ge","b.lt","b.gt","b.le"}
REG=re.compile(r"^(?:[xw](?:[0-9]|[12][0-9]|30)|sp|wsp|xzr|wzr)$",re.I)
def split_ops(s):
 out=[];start=0;depth=0
 for i,ch in enumerate(s):
  if ch in "[{(":depth+=1
  elif ch in "]})":depth=max(0,depth-1)
  elif ch=="," and depth==0:out.append(s[start:i].strip());start=i+1
 if s[start:].strip():out.append(s[start:].strip())
 return out
def number(s):
 s=s.strip().lstrip("#")
 try:
  if s.lower().startswith("0x"):return int(s,16)
  if re.fullmatch(r"-?\d+",s):return int(s,10)
 except ValueError:pass
 return None
def parse_instruction(rest):
 t=rest.split(None,1)
 if not t:return None
 if HEXWORD.fullmatch(t[0]) and len(t)>1:t=t[1].split(None,1)
 m=MN.match(t[0]+" "+(t[1] if len(t)>1 else ""))
 if not m:return None
 return m.group(1).lower(),split_ops(m.group(2))
def analyze(path,label):
 raw=path.read_bytes()
 try:text=raw.decode("utf-8")
 except UnicodeDecodeError as e:raise ValueError(f"{path}: disassembly must be UTF-8 text") from e
 ins=[];ignored=0
 for line_no,line in enumerate(text.splitlines(),1):
  m=LINE.match(line)
  if not m:continue
  parsed=parse_instruction(m.group(2))
  if not parsed:ignored+=1;continue
  addr=int(m.group(1),16);mnemonic,ops=parsed
  x={"address":addr,"address_hex":f"0x{addr:x}","line":line_no,"mnemonic":mnemonic,"operands":ops}
  if mnemonic in BR or mnemonic in COND or mnemonic.startswith("b."):
   target=next((number(o) for o in reversed(ops) if number(o) is not None),None)
   x["control_flow"]={"kind":"call" if mnemonic in ("bl","blr") else "return" if mnemonic=="ret" else "branch",
    "conditional":mnemonic in COND or mnemonic in ("cbz","cbnz","tbz","tbnz") or mnemonic.startswith("b."),
    "target":target,"target_hex":f"0x{target:x}" if target is not None else None}
  if mnemonic=="adrp" and len(ops)>=2:
   x["address_materialization"]={"kind":"page","destination":ops[0].lower(),"page":number(ops[1])}
  elif mnemonic in ("add","sub") and len(ops)>=3 and REG.match(ops[0]) and REG.match(ops[1]):
   imm=number(ops[2])
   if imm is not None:x["arithmetic"]={"operation":mnemonic,"destination":ops[0].lower(),"source":ops[1].lower(),"immediate":imm}
  ins.append(x)
 for i,x in enumerate(ins):
  page=x.get("address_materialization")
  if not page or page["page"] is None:continue
  for nxt in ins[i+1:i+5]:
   ar=nxt.get("arithmetic")
   if ar and ar["operation"]=="add" and ar["source"]==page["destination"]:
    absolute=page["page"]+ar["immediate"]
    page["resolved_with_add"]={"instruction":nxt["address_hex"],"destination":ar["destination"],"offset":ar["immediate"],"address":absolute,"address_hex":f"0x{absolute:x}"}
    break
 return {"label":label,"path":str(path),"sha256":hashlib.sha256(raw).hexdigest(),"line_count":len(text.splitlines()),
  "instructions":ins,"ignored_address_lines":ignored,
  "summary":{"instruction_count":len(ins),"branch_count":sum("control_flow" in x for x in ins),
   "adrp_count":sum(x["mnemonic"]=="adrp" for x in ins),
   "resolved_adrp_add_pairs":sum("resolved_with_add" in x.get("address_materialization",{}) for x in ins),
   "compare_count":sum(x["mnemonic"] in ("cmp","cmn","tst","ccmp","ccmn") for x in ins)}}
def diff(a,b):
 left={x["address"]:x for x in a["instructions"]};right={x["address"]:x for x in b["instructions"]};out=[]
 for addr in sorted(left.keys()|right.keys()):
  x=left.get(addr);y=right.get(addr)
  if x is None:status="added"
  elif y is None:status="removed"
  elif (x["mnemonic"],x["operands"])!=(y["mnemonic"],y["operands"]):status="changed"
  else:continue
  out.append({"address":f"0x{addr:x}","status":status,
   "before":f"{x['mnemonic']} {', '.join(x['operands'])}" if x else None,
   "after":f"{y['mnemonic']} {', '.join(y['operands'])}" if y else None})
 return out
def render(r):
 out=["# Phoenix ARM64 Disassembly Analysis","",f"Generated: {r['generated_utc']}","",
  "> Text disassembly analysis only. No raw binary decoding or execution is performed.",""]
 for s in r["sources"]:
  q=s["summary"];out += [f"## {s['label']}","",f"- Input: {s['path']}",f"- SHA-256: {s['sha256']}",
   f"- Instructions: {q['instruction_count']}",f"- Branch/call/return: {q['branch_count']}",
   f"- ADRP instructions: {q['adrp_count']}",f"- ADRP + ADD heuristic pairs: {q['resolved_adrp_add_pairs']}",
   f"- Compare/test instructions: {q['compare_count']}","","| Address | Instruction | Interpretation |","|---|---|---|"]
  for x in s["instructions"]:
   meaning=""
   if "control_flow" in x:
    c=x["control_flow"];meaning=f"{c['kind']}; conditional={c['conditional']}; target={c['target_hex'] or 'unresolved'}"
   elif "address_materialization" in x:
    p=x["address_materialization"];z=p.get("resolved_with_add")
    meaning=f"page {p['page']}; ADD result {z['address_hex']}" if z else "page-address construction"
   elif "arithmetic" in x:meaning=f"{x['arithmetic']['operation']} immediate {x['arithmetic']['immediate']}"
   out.append(f"| {x['address_hex']} | {x['mnemonic']} {', '.join(x['operands'])} | {meaning} |")
 if r.get("diff") is not None:
  out += ["","## Before/after instruction diff","","| Address | Status | Before | After |","|---|---|---|---|"]
  for x in r["diff"]:out.append(f"| {x['address']} | {x['status']} | {x['before'] or '—'} | {x['after'] or '—'} |")
 out += ["","## Limitations","",
  "- Branch targets are extracted only when the disassembler prints numeric operands.",
  "- ADRP+ADD association is a nearby-instruction heuristic, not symbolic execution.",
  "- Register/flag effects, memory effects, relocations, reachability, and full instruction semantics are not modeled.",
  "- Symbolic targets may remain unresolved. Before/after comparison requires comparable address spaces and disassembly settings.",
  "- The report is not proof of patch correctness, safety, or A9 compatibility.",""]
 return "\n".join(out)
def main(argv=None):
 p=argparse.ArgumentParser(description="Analyze textual ARM64 disassembly and compare before/after listings")
 p.add_argument("--source",action="append",default=[],metavar="LABEL=PATH")
 p.add_argument("--before",type=Path);p.add_argument("--after",type=Path)
 p.add_argument("--out-json",type=Path,default=Path("phoenix-arm64-analysis.json"))
 p.add_argument("--out-md",type=Path,default=Path("phoenix-arm64-analysis.md"))
 a=p.parse_args(argv)
 try:
  sources=[]
  for v in a.source:
   if "=" not in v:raise ValueError("--source expects LABEL=PATH")
   label,path=v.split("=",1)
   if not label or not path:raise ValueError("source label/path must be non-empty")
   sources.append(analyze(Path(path),label))
  if (a.before is None)!=(a.after is None):raise ValueError("--before and --after must be supplied together")
  comparison=None
  if a.before is not None:
   left=analyze(a.before,"before");right=analyze(a.after,"after");sources += [left,right];comparison=diff(left,right)
  if not sources:raise ValueError("provide --source or a --before/--after pair")
  report={"schema_version":1,"tool":"Phoenix ARM64 Disassembly Analyzer","generated_utc":datetime.now(timezone.utc).isoformat(),
   "source_count":len(sources),"sources":sources,"diff":comparison,
   "scope":{"text_disassembly_only":True,"binary_decoder":False,"code_executed":False,"firmware_modified":False}}
  a.out_json.parent.mkdir(parents=True,exist_ok=True);a.out_md.parent.mkdir(parents=True,exist_ok=True)
  a.out_json.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8");a.out_md.write_text(render(report),encoding="utf-8")
  print("Sources:",len(sources));print("Instructions:",sum(x["summary"]["instruction_count"] for x in sources))
  print("Diff entries:",len(comparison) if comparison is not None else "not requested")
  print("JSON:",a.out_json);print("Markdown:",a.out_md);return 0
 except (OSError,UnicodeError,ValueError) as e:
  print("phoenix-arm64-disasm:",e,file=sys.stderr);return 2
if __name__=="__main__":raise SystemExit(main())
