#!/usr/bin/env python3
"""Read-only lexical inventory of C patcher signatures and mutation sites."""
from __future__ import annotations
import argparse,hashlib,json,re,sys
from datetime import datetime,timezone
from pathlib import Path
class AuditError(ValueError): pass
ARRAY=re.compile(r"(?P<type>Word|Pattern|uint32_t|uint64_t)\s+(?P<name>[A-Za-z_]\w*)\s*\[\s*\]\s*=\s*\{",re.M)
NUM=re.compile(r"(?<![\w])(?:0[xX][0-9a-fA-F]+|\d+)[uUlL]*")
FUNC=re.compile(r"(?m)^[ \t]*(?:static\s+)?(?:void|int|bool|size_t|uint\w*_t|long|char\s*\*)\s+([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{")
MUT=re.compile(r"\b(edit|patch|write|put(?:8|16|32|64)|memcpy|memmove|memset|w32|write_u32|write32|replace|apply_patch)\s*\(")
def clean_comments(s):
    rx=re.compile(r'("(?:\\\\.|[^"\\\\])*"|\\x27(?:\\\\.|[^\\x27\\\\])*\\x27|//[^\\n]*|/\\*[\\s\\S]*?\\*/)')
    a=list(s)
    for m in rx.finditer(s):
        if m.group().startswith(('"',"'")): continue
        for i,c in enumerate(m.group()):
            if c not in "\r\n": a[m.start()+i]=" "
    return "".join(a)
def ln(s,o): return s.count("\n",0,o)+1
def close_brace(s,o):
    d=0
    for i in range(o,len(s)):
        if s[i]=="{": d+=1
        elif s[i]=="}":
            d-=1
            if not d:return i
    raise AuditError("unterminated array initializer")
def comment_before(s,o):
    m=re.search(r"/\*([\s\S]*?)\*/\s*$",s[:o])
    return re.sub(r"^\s*\* ?","",m.group(1),flags=re.M).strip() if m else ""
def analyze(label,path):
    raw=path.read_bytes(); src=raw.decode("utf-8"); code=clean_comments(src); arrays=[]
    for m in ARRAY.finditer(code):
        op=code.find("{",m.start()); end=close_brace(code,op); typ=m.group("type"); name=m.group("name"); words=[]
        for ent in code[op+1:end].split(","):
            ns=NUM.findall(ent)
            if not ns: continue
            v=[int(re.sub(r"[uUlL]+$","",x),0) for x in ns]
            if typ in ("Word","Pattern") and len(v)>=2: words.append({"value":v[0],"mask":v[1]})
            elif typ in ("uint32_t","uint64_t"): words.append({"value":v[0],"mask":None})
        if not words: continue
        uses=[ln(src,h.start()) for h in re.finditer(r"\b"+re.escape(name)+r"\b",code) if not m.start()<=h.start()<=m.end()]
        sig=typ in ("Word","Pattern"); exact=sum(w["mask"]==0xffffffff for w in words) if sig else 0
        arrays.append({"name":name,"type":typ,"line":ln(src,m.start()),"count":len(words),
          "comment":comment_before(src,m.start()),"exact_mask_words":exact,"masked_words":len(words)-exact if sig else 0,
          "mask_bits":sum(w["mask"].bit_count() for w in words if w["mask"] is not None),
          "words":words[:512],"truncated":len(words)>512,"use_lines":uses})
    funcs=[{"name":m.group(1),"line":ln(src,m.start())} for m in FUNC.finditer(code)]
    muts=[{"operation":m.group(1),"line":ln(src,m.start())} for m in MUT.finditer(code)]
    return {"label":label,"path":str(path),"sha256":hashlib.sha256(raw).hexdigest(),"line_count":src.count("\n")+1,
      "functions":funcs,"arrays":arrays,"mutation_sites":muts,
      "summary":{"functions":len(funcs),"arrays":len(arrays),"signature_arrays":sum(a["type"] in ("Word","Pattern") for a in arrays),
      "signature_words":sum(a["count"] for a in arrays if a["type"] in ("Word","Pattern")),"mutation_calls":len(muts)}}
def arg(v):
    if "=" not in v: raise argparse.ArgumentTypeError("expected LABEL=PATH")
    a,b=v.split("=",1)
    if not a.strip() or not b.strip(): raise argparse.ArgumentTypeError("label/path empty")
    return a.strip(),Path(b.strip())
def markdown(m):
    out=["# Phoenix Patch Pattern Audit","",f"Generated: {m['generated_utc']}","",
      "> Lexical inventory only: no ARM64 disassembly, semantic validation, patch execution, firmware build, or hardware test.","",
      "| Source | Lines | Functions | Signature arrays | Signature words | Mutation calls | SHA-256 |","|---|---:|---:|---:|---:|---:|---|"]
    for s in m["sources"]:
        q=s["summary"];out.append(f"| {s['label']} | {s['line_count']} | {q['functions']} | {q['signature_arrays']} | {q['signature_words']} | {q['mutation_calls']} | {s['sha256']} |")
    for s in m["sources"]:
        out += ["",f"## {s['label']}","",f"Source: {s['path']} · SHA-256: {s['sha256']}",""]
        if s["arrays"]:
            out += ["| Array | Line | Words | Exact masks | Masked | Use lines | Adjacent comment |","|---|---:|---:|---:|---:|---|---|"]
            for a in s["arrays"]:
                out.append(f"| {a['name']} | {a['line']} | {a['count']} | {a['exact_mask_words']} | {a['masked_words']} | {', '.join(map(str,a['use_lines'])) or '—'} | {' '.join(a['comment'].split()).replace('|','/')} |")
        out += ["","### Mutation call sites",""]
        out += ["| Line | Operation |","|---:|---|"]+[f"| {x['line']} | {x['operation']} |" for x in s["mutation_sites"]] if s["mutation_sites"] else ["No recognized calls."]
    out += ["","## Limitations","",
      "- Recognizes common Word, Pattern, uint32_t, and uint64_t initializer arrays only.",
      "- For Word/Pattern arrays, first two numeric literals in each comma-delimited initializer are interpreted as value and mask; macros and complex expressions may be missed.",
      "- Mask bit counts are structural metadata, not match probabilities.",
      "- Mutation-call counts are lexical and can include helper wrappers or non-patch operations.",
      "- Source line numbers and SHA-256 hashes identify the exact inputs.",
      "- Does not decode ARM64, resolve branches, infer hardware semantics, or prove patch safety.",""]
    return "\n".join(out)
def main(argv=None):
    p=argparse.ArgumentParser(description="Inventory masked signature arrays and mutation call sites in C patcher sources")
    p.add_argument("--source",action="append",type=arg,required=True,metavar="LABEL=PATH")
    p.add_argument("--out-json",type=Path,default=Path("phoenix-patch-patterns.json"))
    p.add_argument("--out-md",type=Path,default=Path("phoenix-patch-patterns.md"))
    a=p.parse_args(argv)
    try:
        if len({x[0] for x in a.source})!=len(a.source): raise AuditError("source labels must be unique")
        sources=[analyze(k,v) for k,v in a.source]
        m={"schema_version":1,"tool":"Phoenix Patch Pattern Analyzer","generated_utc":datetime.now(timezone.utc).isoformat(),
          "source_count":len(sources),"sources":sources,"interpretation":{"static_inventory_only":True,"arm64_decoded":False,"patcher_executed":False,"hardware_tested":False}}
        a.out_json.parent.mkdir(parents=True,exist_ok=True);a.out_md.parent.mkdir(parents=True,exist_ok=True)
        a.out_json.write_text(json.dumps(m,indent=2)+"\n",encoding="utf-8");a.out_md.write_text(markdown(m),encoding="utf-8")
        print("Sources:",len(sources));print("Signature arrays:",sum(x["summary"]["signature_arrays"] for x in sources))
        print("Signature words:",sum(x["summary"]["signature_words"] for x in sources))
        print("JSON:",a.out_json);print("Markdown:",a.out_md);print("ARM64 semantics decoded: no");return 0
    except (OSError,UnicodeError,AuditError) as e:
        print("phoenix-pattern-audit:",e,file=sys.stderr);return 2
if __name__=="__main__": raise SystemExit(main())
