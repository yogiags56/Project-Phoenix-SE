#!/usr/bin/env python3
"""Conservative sequential register def-use analysis for textual AArch64 disassembly.

This is not a binary decoder or full CFG/data-flow engine. Unknown instructions
are treated as barriers so the tool never invents cross-barrier register links.
"""
from __future__ import annotations
import argparse, hashlib, json, re, sys
from pathlib import Path

LINE = re.compile(r"^\s*(?:0x)?([0-9a-fA-F]+):\s*(.*?)\s*$")
REG = re.compile(r"(?<![A-Za-z0-9_])([xw](?:[0-9]|[12][0-9]|30)|[xw]zr|[xw]sp|sp|wsp)(?![A-Za-z0-9_])", re.I)
MEM = re.compile(r"\[[^\]]*\]")
BRANCH_COND = {"b.eq","b.ne","b.cs","b.hs","b.cc","b.lo","b.mi","b.pl","b.vs","b.vc","b.hi","b.ls","b.ge","b.lt","b.gt","b.le","b.al","b.nv"}

def canonical(r: str):
    r=r.lower()
    if r in ("xzr","wzr"): return None
    if r in ("sp","wsp"): return "sp"
    if r.startswith(("x","w")) and r[1:].isdigit(): return "r"+r[1:]
    return None

def registers(text: str):
    return [canonical(x) for x in REG.findall(text) if canonical(x) is not None]

def split_ops(s: str):
    out=[]; start=0; depth=0
    for i,ch in enumerate(s):
        if ch in "[({": depth+=1
        elif ch in "])}": depth=max(0,depth-1)
        elif ch=="," and depth==0: out.append(s[start:i].strip()); start=i+1
    if s[start:].strip(): out.append(s[start:].strip())
    return out

def parse_line(line: str):
    m=LINE.match(line)
    if not m: return None
    text=m.group(2).strip()
    # llvm-objdump may include the raw 32-bit word before the mnemonic.
    parts=text.split(None,1)
    if parts and re.fullmatch(r"(?:[0-9a-fA-F]{8})",parts[0]) and len(parts)>1:
        text=parts[1]
    parts=text.split(None,1)
    if not parts: return None
    return int(m.group(1),16),parts[0].lower(),split_ops(parts[1] if len(parts)>1 else "")

def effects(mn: str, ops: list[str]):
    """Return (reads,writes,flags_read,flags_written,known,reason)."""
    regs=[registers(o) for o in ops]
    flat=lambda xs: sorted(set(x for group in xs for x in group))
    if mn in ("nop","hint","b"): return [],[],False,False,True,"no GPR effect"
    if mn in BRANCH_COND: return [],[],True,False,True,"conditional branch reads NZCV"
    if mn in ("cbz","cbnz","tbz","tbnz"):
        return (regs[0] if regs else []),[],False,False,True,"test/compare branch"
    if mn in ("br","blr","ret"):
        reads=regs[0] if ops and regs[0] else (["r30"] if mn=="ret" else [])
        writes=["r30"] if mn=="blr" else []
        return reads,writes,False,False,True,"indirect branch/call/return"
    if mn=="bl": return [],["r30"],False,False,True,"call writes link register"
    if mn in ("adr","adrp","movz","movn"):
        return [],(regs[0] if regs else []),False,False,bool(regs),"destination-only write"
    if mn=="mov":
        return (regs[1] if len(regs)>1 else []),(regs[0] if regs else []),False,False,len(regs)>=1,"register move alias"
    if mn=="movk":
        return (regs[0] if regs else []),(regs[0] if regs else []),False,False,bool(regs),"read-modify-write move-wide"
    if mn in ("cmp","cmn","tst"):
        return flat(regs),[],False,True,True,"comparison/test writes NZCV"
    if mn in ("add","adds","sub","subs","and","ands","orr","eor","bic","bics","lsl","lsr","asr","ror","lslv","lsrv","asrv","rorv","madd","msub"):
        reads=flat(regs[1:])
        writes=regs[0] if regs else []
        fw=mn.endswith("s") and mn not in ("adds","subs") or mn in ("adds","subs")
        return reads,writes,False,fw,bool(regs),"data-processing instruction"
    if mn in ("ldr","ldrb","ldrh","ldrsw","ldur","ldurb","ldurh","ldur"):
        reads=flat(regs[1:])
        writes=regs[0] if regs else []
        return reads,writes,False,False,bool(regs),"load reads address registers and writes destination"
    if mn in ("str","strb","strh","stur","sturb","sturh"):
        return flat(regs),[],False,False,bool(regs),"store reads source and address registers"
    if mn in ("stp","ldp"):
        if mn=="stp": return flat(regs),[],False,False,bool(regs),"pair store"
        return flat(regs[2:]),flat(regs[:2]),False,False,len(regs)>=2,"pair load"
    # Unknown opcodes may read/write arbitrary architectural state. Barrier below.
    return [],[],False,False,False,"unsupported instruction; def-use chain reset"

def analyze(path: Path, label: str):
    raw=path.read_bytes()
    try: source=raw.decode("utf-8")
    except UnicodeDecodeError as e: raise ValueError(f"{path}: expected UTF-8 disassembly text") from e
    ins=[]; ignored=0
    for line_no,line in enumerate(source.splitlines(),1):
        parsed=parse_line(line)
        if not parsed: ignored+=1; continue
        addr,mn,ops=parsed
        reads,writes,fr,fw,known,reason=effects(mn,ops)
        ins.append({"address":addr,"address_hex":f"0x{addr:x}","line":line_no,"mnemonic":mn,
          "operands":ops,"reads":reads,"writes":writes,"flags_read":fr,"flags_written":fw,
          "effects_known":known,"effect_note":reason})
    reaching={}; uses=[]; barriers=[]
    for idx,x in enumerate(ins):
        if not x["effects_known"]:
            barriers.append({"instruction":x["address_hex"],"line":x["line"],"mnemonic":x["mnemonic"]})
            reaching.clear()
            continue
        for r in x["reads"]:
            if r in reaching:
                uses.append({"register":r,"definition_index":reaching[r],"use_index":idx,
                  "definition_address":ins[reaching[r]]["address_hex"],"use_address":x["address_hex"]})
        for r in x["writes"]: reaching[r]=idx
    for x in ins:
        x["read_names"]=[r for r in x["reads"]]
        x["write_names"]=[r for r in x["writes"]]
    return {"label":label,"input":str(path),"sha256":hashlib.sha256(raw).hexdigest(),
      "line_count":len(source.splitlines()),"ignored_lines":ignored,"instructions":ins,
      "def_use_links":uses,"unknown_effect_barriers":barriers,
      "summary":{"instruction_count":len(ins),"known_effect_count":sum(x["effects_known"] for x in ins),
        "unknown_effect_count":len(barriers),"register_read_count":sum(len(x["reads"]) for x in ins),
        "register_write_count":sum(len(x["writes"]) for x in ins),"def_use_link_count":len(uses),
        "flags_read_count":sum(x["flags_read"] for x in ins),"flags_written_count":sum(x["flags_written"] for x in ins)}}

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("disassembly",type=Path)
    p.add_argument("--label",default="input")
    p.add_argument("--output",type=Path,default=Path("phoenix-register-flow.json"))
    a=p.parse_args(argv)
    try:
        result=analyze(a.disassembly,a.label)
        report={"schema_version":1,"tool":"Phoenix Register Def-Use Analyzer",
          "scope":{"text_disassembly_only":True,"sequential_not_cfg_aware":True,
            "unknown_instructions_are_barriers":True,"binary_decoder":False,"code_executed":False,
            "firmware_modified":False},"result":result,
          "limitations":["Sequential analysis only; branches do not create basic blocks or merge paths.",
            "Register aliases Wn/Xn are normalized to one 64-bit architectural register.",
            "Unknown instructions reset reaching definitions to avoid unsupported assumptions.",
            "NZCV is counted but individual flag definitions/uses are not linked.",
            "Instruction semantics cover a conservative subset and require validation against full disassembly."]}
        a.output.parent.mkdir(parents=True,exist_ok=True)
        a.output.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
        print("Instructions:",result["summary"]["instruction_count"])
        print("Known effects:",result["summary"]["known_effect_count"])
        print("Unknown barriers:",result["summary"]["unknown_effect_count"])
        print("Def-use links:",result["summary"]["def_use_link_count"])
        print("JSON:",a.output)
        return 0
    except (OSError,UnicodeError,ValueError) as e:
        print("phoenix-register-flow:",e,file=sys.stderr);return 2
if __name__=="__main__": raise SystemExit(main())
