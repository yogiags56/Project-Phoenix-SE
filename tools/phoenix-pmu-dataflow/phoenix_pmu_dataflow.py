#!/usr/bin/env python3
"""Donorless symbolic register/flag analysis for PMU LDO signature windows.

This analyzes catalog instruction templates as isolated windows. It is not a
binary disassembler, CFG reconstruction, or hardware model. Unknown semantics
are explicit barriers; no values are inferred across them.
"""
from __future__ import annotations
import argparse,json,re,sys
from pathlib import Path

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
sys.path.insert(0,str(ROOT/"tools"/"phoenix-pmu-semantic"))
try:
    from phoenix_pmu_semantic import decode
except ImportError:
    decode=None

class DataflowError(ValueError): pass
REG_RE=re.compile(r"^[xw](?:[0-9]|[12][0-9]|30)$")
MEM_RE=re.compile(r"\[([^\]]+)\]")

def sx(v,b):
    sign=1<<(b-1)
    return (v^sign)-sign

def rname(n,width=64):
    if n==31:return "xzr" if width==64 else "wzr"
    return ("x" if width==64 else "w")+str(n)

def decode_extended(w):
    d=decode(w)
    # Unsigned multiply-add long: UMADDL Xd, Wn, Wm, Xa.
    if (w & 0x7fe08000)==0x1ba00000:
        rd=w&31;rn=(w>>5)&31;ra=(w>>10)&31;rm=(w>>16)&31
        d={"class":"integer-arithmetic","mnemonic":"umaddl",
           "operands":[rname(rd),rname(rn,32),rname(rm,32),rname(ra)],
           "meaning":"Unsigned 32x32 multiply plus 64-bit accumulator"}
    # Pair load/store, offset/pre-index/post-index addressing forms.
    elif (w & 0x3a000000)==0x28000000:
        opc=(w>>30)&3;load=bool((w>>22)&1);mode=(w>>23)&3
        width=32 if opc==0 else 64 if opc==2 else None
        if width is not None:
            scale=width//8;imm=sx((w>>15)&0x7f,7)*scale
            rt=w&31;rt2=(w>>10)&31;rn=(w>>5)&31
            base=rname(rn)
            if mode==1: mem=f"[{base}, #{imm}]!"
            elif mode==3: mem=f"[{base}], #{imm}"
            else: mem=f"[{base}, #{imm}]"
            d={"class":"load-store-pair","mnemonic":"ldp" if load else "stp",
               "operands":[rname(rt,width),rname(rt2,width),mem],
               "meaning":"Pair load" if load else "Pair store"}
    # Logical immediate: decode bitmask immediate only when architectural
    # bitmask construction is valid; otherwise retain unknown.
    elif (w & 0x1f800000)==0x12000000:
        sf=(w>>31)&1;opc=(w>>29)&3;n=(w>>22)&1
        immr=(w>>16)&0x3f;imms=(w>>10)&0x3f;rn=(w>>5)&31;rd=w&31
        width=64 if sf else 32
        if n==0 and sf==0 or (n==1 and sf==0):
            d={"class":"unknown","mnemonic":None,"operands":[],"meaning":"Invalid logical immediate encoding"}
        else:
            x=(n<<6)|((~imms)&0x3f)
            length=x.bit_length()-1
            if length<1:
                d={"class":"unknown","mnemonic":None,"operands":[],"meaning":"Invalid logical immediate element size"}
            else:
                levels=(1<<length)-1;s=imms&levels;r=immr&levels
                if s==levels:
                    d={"class":"unknown","mnemonic":None,"operands":[],"meaning":"Reserved logical immediate mask"}
                else:
                    esize=1<<length
                    elem=(1<<(s+1))-1
                    elem=((elem>>r)|(elem<<(esize-r)))&((1<<esize)-1)
                    mask=0
                    for shift in range(0,width,esize):mask|=elem<<shift
                    names={0:"and",1:"orr",2:"eor",3:"ands"}
                    d={"class":"logical-immediate","mnemonic":names[opc],
                       "operands":[rname(rd,width),rname(rn,width),f"#{mask:#x}"],
                       "meaning":"Logical operation with decoded bitmask immediate","immediate":mask}
    return d

def canonical(reg):
    if reg in ("xzr","wzr"):return None
    if reg in ("sp","wsp"):return "sp"
    if REG_RE.fullmatch(reg):return "r"+reg[1:]
    return None

def regs_in(op):
    out=[]
    for token in re.findall(r"(?<![A-Za-z0-9_])[xw](?:[0-9]|[12][0-9]|30)|(?<![A-Za-z0-9_])(?:sp|wsp)(?![A-Za-z0-9_])",op):
        c=canonical(token)
        if c and c not in out:out.append(c)
    return out

def effects(d):
    m=d.get("mnemonic");o=d.get("operands",[])
    if not m:return [],[],False,False,"unknown instruction"
    if m in ("nop","hint","b"):return [],[],False,False,"no tracked register effect"
    if m in ("movz","movn","adr","adrp"):return [],regs_in(o[0]) if o else [],False,False,"destination-only definition"
    if m=="movk":return (regs_in(o[0]) if o else []),(regs_in(o[0]) if o else []),False,False,"read-modify-write"
    if m=="mov":return (regs_in(o[1]) if len(o)>1 else []),(regs_in(o[0]) if o else []),False,False,"register alias"
    if m in ("add","sub","adds","subs"):
        reads=regs_in(o[1]) if len(o)>1 else []
        if len(o)>2:reads+=regs_in(o[2])
        return reads,regs_in(o[0]) if o else [],False,m in ("adds","subs"),"arithmetic"
    if m in ("and","orr","eor","ands"):
        reads=[]
        for op in o[1:]:reads+=regs_in(op)
        return reads,regs_in(o[0]) if o else [],False,m=="ands","logical operation"
    if m in ("lslv","lsrv","asrv","rorv"):
        reads=(regs_in(o[1])+regs_in(o[2])) if len(o)>2 else []
        return reads,regs_in(o[0]) if o else [],False,False,"variable shift"
    if m=="umaddl":
        reads=[]
        for op in o[1:]:reads+=regs_in(op)
        return reads,regs_in(o[0]) if o else [],False,False,"unsigned multiply-add long"
    if m in ("ldr","ldrb","ldrh","ldrsw","ldur","ldurb","ldurh"):
        reads=regs_in(o[1]) if len(o)>1 else []
        return reads,regs_in(o[0]) if o else [],False,False,"load"
    if m in ("str","strb","strh","stur","sturb","sturh"):
        reads=[]
        for op in o:reads+=regs_in(op)
        return reads,[],False,False,"store"
    if m=="ldp":
        reads=regs_in(o[2]) if len(o)>2 else []
        writes=regs_in(o[0])+regs_in(o[1]) if len(o)>1 else []
        return reads,writes,False,False,"pair load"
    if m=="stp":
        reads=[]
        for op in o:reads+=regs_in(op)
        return reads,[],False,False,"pair store"
    if m in ("cmp","cmn","tst"):
        reads=[]
        for op in o:reads+=regs_in(op)
        return reads,[],False,True,"flags definition"
    if m in ("cbz","cbnz","tbz","tbnz"):
        return regs_in(o[0]) if o else [],[],False,False,"register-test branch"
    if m.startswith("b."):return [],[],True,False,"conditional branch reads NZCV"
    if m=="bl":return [],["r30"],False,False,"call writes link register"
    if m in ("br","blr","ret"):return regs_in(o[0]) if o else (["r30"] if m=="ret" else []),(["r30"] if m=="blr" else []),False,False,"indirect control transfer"
    return [],[],False,False,"unsupported semantics; data-flow barrier"

def expression_for(d,reads,prior):
    m=d.get("mnemonic");o=d.get("operands",[])
    if not o:return None
    dst=canonical(o[0])
    if dst is None:return None
    if m in ("movz","movn"):
        imm=int(o[1].lstrip("#"),16);shift=int(o[2].split("#")[-1]) if len(o)>2 else 0
        width=32 if o[0].startswith("w") else 64
        value=(imm<<shift)&((1<<width)-1)
        if m=="movn":value=(~value)&((1<<width)-1)
        return {"kind":"constant","value":value,"width":width}
    if m=="movk":
        old=prior.get(dst)
        imm=int(o[1].lstrip("#"),16);shift=int(o[2].split("#")[-1]) if len(o)>2 else 0
        width=32 if o[0].startswith("w") else 64
        if old and old.get("kind")=="constant":
            mask=0xffff<<shift
            value=(old["value"]&~mask)|(imm<<shift)
            return {"kind":"constant","value":value&((1<<width)-1),"width":width}
        return {"kind":"expression","op":"movk","inputs":[old or {"kind":"unknown","register":dst},hex(imm),shift],"width":width}
    if m in ("lsrv","lslv","asrv","rorv"):
        return {"kind":"expression","op":m,"inputs":[prior.get(canonical(o[1]),{"kind":"unknown","register":o[1]}),{"register":o[2]}],"width":64 if o[0].startswith("x") else 32}
    if m=="umaddl":
        return {"kind":"expression","op":"umaddl","inputs":[{"register":x} for x in o[1:]],"width":64}
    if m in ("add","sub","and","orr","eor"):
        return {"kind":"expression","op":m,"inputs":[{"register":x} if canonical(x) else x for x in o[1:]],"width":64 if o[0].startswith("x") else 32}
    if m in ("ldr","ldrb","ldrh","ldrsw","ldur","ldurb","ldurh","ldp"):
        return {"kind":"loaded-value","source":o[1:] if len(o)>1 else [],"width":64 if o[0].startswith("x") else 32}
    if m=="mov":
        return prior.get(canonical(o[1]),{"kind":"unknown","register":o[1]})
    return {"kind":"expression","op":m,"inputs":[{"register":r} for r in reads],"width":64 if o[0].startswith("x") else 32}

def analyze_rule(rule):
    state={};last_flags=None;rows=[];barriers=[]
    for i,item in enumerate(rule["signature"]):
        w=int(item["value"],16);mask=int(item["mask"],16);d=decode_extended(w)
        reads,writes,fr,fw,note=effects(d)
        uses=[{"register":r,"definition":state.get(r)} for r in reads]
        before=dict(state)
        if d.get("class")=="unknown" or note.startswith("unsupported"):
            barriers.append({"word_index":i,"word":item["value"],"reason":d.get("meaning",note)})
            state.clear();last_flags=None
        else:
            for r in writes:
                state[r]=expression_for(d,reads,before) or {"kind":"defined","by":d.get("mnemonic")}
            if fw:last_flags={"defined_at_word":i,"by":d.get("mnemonic")}
        rows.append({"word_index":i,"word":item["value"],"mask":item["mask"],
          "fully_constrained":mask==0xffffffff,"mnemonic":d.get("mnemonic"),
          "operands":d.get("operands",[]),"reads":reads,"writes":writes,
          "read_definitions":uses,"flags_read":fr,"flags_written":fw,
          "flags_definition":last_flags if fr else None,"semantic_note":note,
          "barrier":d.get("class")=="unknown" or note.startswith("unsupported")})
    pi=rule["patch_word_index"];replacement=decode_extended(int(rule["replacement_word"],16))
    return {"rule_index":rule["index"],"name":rule["name"],"patch_word_index":pi,
      "original_patch_word":rule["signature"][pi]["value"],
      "replacement_word":rule["replacement_word"],"replacement_mnemonic":replacement.get("mnemonic"),
      "replacement_operands":replacement.get("operands",[]),
      "mutates":bool(rule["change"]),"instructions":rows,"barriers":barriers}

def analyze(catalog,first=54,last=69):
    selected=[r for r in catalog.get("rules",[]) if first<=r.get("index",-1)<=last]
    if [r["index"] for r in selected]!=list(range(first,last+1)):
        raise DataflowError("catalog does not contain the complete requested rule range")
    rules=[analyze_rule(r) for r in selected]
    jumps=[]
    for j in catalog.get("jumps",[]):
        src=int(j.get("source_rule",j.get("source",-1)));dst=int(j.get("target_rule",j.get("target",-1)))
        if first<=src<=last or first<=dst<=last:
            jumps.append({"source_rule":src,"target_rule":dst,"branch_kind":j.get("branch_kind"),
                          "interpretation":"patcher-defined redirect; branch destination not resolved"})
    return {"schema_version":1,"artifact":"Phoenix donorless LDO register data-flow report",
      "provenance":catalog.get("provenance",{}),
      "scope":{"source_catalog_only":True,"donor_binary_required":False,"signature_words_are_templates":True,
       "register_def_use_within_each_signature_window":True,"cross_rule_register_state_merged":False,
       "control_flow_paths_merged":False,"runtime_register_values_known":False,
       "binary_offsets_resolved":False,"hardware_behavior_validated":False,"patch_application":False},
      "summary":{"rule_range":[first,last],"rule_count":len(rules),
       "instruction_word_count":sum(len(r["instructions"]) for r in rules),
       "unknown_or_unsupported_barrier_count":sum(len(r["barriers"]) for r in rules),
       "mutating_rules":sum(r["mutates"] for r in rules),"dynamic_redirects":len(jumps)},
      "dynamic_redirects":jumps,"rules":rules,
      "limitations":["Each nine-word signature is analyzed as an isolated window; overlapping windows are not concatenated.",
       "Register aliases Wn/Xn are tracked as one architectural register but width-specific value truncation is conservative.",
       "Masked words may have wildcard fields; decoded operands are only template interpretations.",
       "The decoder implements a limited instruction subset; unsupported words reset reaching definitions.",
       "Branch paths and NZCV are annotated but not merged into a control-flow graph.",
       "A signature's patch word index is not a kernel file offset or virtual address.",
       "No donor firmware was read and no hardware behavior was tested."]}

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("catalog",type=Path,nargs="?",default=ROOT/"research"/"PMU-SIGNATURE-CATALOG.json")
    p.add_argument("-o","--output",type=Path,default=ROOT/"research"/"PMU-LDO-DATAFLOW.json")
    a=p.parse_args(argv)
    try:
        catalog=json.loads(a.catalog.read_text(encoding="utf-8"));report=analyze(catalog)
        a.output.parent.mkdir(parents=True,exist_ok=True)
        a.output.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
        print("LDO rules:",report["summary"]["rule_count"])
        print("instruction words:",report["summary"]["instruction_word_count"])
        print("barriers:",report["summary"]["unknown_or_unsupported_barrier_count"])
        print("dynamic redirects:",report["summary"]["dynamic_redirects"])
        print("report:",a.output)
        return 0
    except (OSError,UnicodeError,json.JSONDecodeError,DataflowError,ValueError,KeyError,TypeError) as exc:
        print("phoenix-pmu-dataflow:",exc,file=sys.stderr);return 2
if __name__=="__main__":raise SystemExit(main())
