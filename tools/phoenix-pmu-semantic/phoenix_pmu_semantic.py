#!/usr/bin/env python3
"""Conservative decoder for selected AArch64 instruction classes in Phoenix PMU catalogs."""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path

MASK32 = 0xffffffff
REGS = [f"x{i}" for i in range(31)] + ["sp"]
WREGS = [f"w{i}" for i in range(31)] + ["wsp"]
CONDS = ["eq","ne","cs","cc","mi","pl","vs","vc","hi","ls","ge","lt","gt","le","al","nv"]

def sx(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign

def reg(n: int, sf: int, sp: bool = False) -> str:
    if n == 31:
        return ("sp" if sf else "wsp") if sp else ("xzr" if sf else "wzr")
    return (REGS if sf else WREGS)[n]

def decode(word: int) -> dict:
    w = word & MASK32
    # Architectural NOP.
    if w == 0xd503201f:
        return {"class":"hint","mnemonic":"nop","operands":[],"meaning":"No operation"}
    # Unconditional immediate branch.
    if (w & 0x7c000000) == 0x14000000:
        link = bool(w & 0x80000000)
        disp = sx(w & 0x03ffffff,26) << 2
        return {"class":"branch","mnemonic":"bl" if link else "b","operands":[f"{disp:+#x}"],"meaning":"Branch with link" if link else "Unconditional branch","branch_displacement":disp}
    # Conditional branch.
    if (w & 0xff000010) == 0x54000000:
        cond=w&15;disp=sx((w>>5)&0x7ffff,19)<<2
        return {"class":"branch","mnemonic":"b."+CONDS[cond],"operands":[f"{disp:+#x}"],"meaning":"Conditional branch","branch_displacement":disp,"condition":CONDS[cond]}
    # Compare and branch.
    if (w & 0x7e000000) == 0x34000000:
        sf=(w>>31)&1;nonzero=(w>>24)&1;rt=w&31;disp=sx((w>>5)&0x7ffff,19)<<2
        return {"class":"branch","mnemonic":"cbnz" if nonzero else "cbz","operands":[reg(rt,sf),f"{disp:+#x}"],"meaning":"Compare register with zero and branch","branch_displacement":disp}
    # Test bit and branch.
    if (w & 0x7e000000) == 0x36000000:
        sf=(w>>31)&1;nonzero=(w>>24)&1;bit=((w>>31)&1)<<5 | ((w>>19)&31);rt=w&31;disp=sx((w>>5)&0x3fff,14)<<2
        return {"class":"branch","mnemonic":"tbnz" if nonzero else "tbz","operands":[reg(rt,sf),f"#{bit}",f"{disp:+#x}"],"meaning":"Test bit and branch","branch_displacement":disp,"tested_bit":bit}
    # ADR / ADRP.
    if (w & 0x1f000000) == 0x10000000:
        page=bool(w & 0x80000000);imm=((w>>29)&3)|(((w>>5)&0x7ffff)<<2);disp=sx(imm,21);rd=w&31
        if page:disp <<= 12
        return {"class":"address-generation","mnemonic":"adrp" if page else "adr","operands":[reg(rd,1,True),f"{disp:+#x}"],"meaning":"Form PC-relative page address" if page else "Form PC-relative address","pc_relative_displacement":disp}
    # ADD/SUB immediate.
    if (w & 0x1f000000) == 0x11000000:
        sf=(w>>31)&1;sub=(w>>30)&1;sets=(w>>29)&1;shift=(w>>22)&1;imm=(w>>10)&0xfff
        if shift:imm <<= 12
        rn=(w>>5)&31;rd=w&31
        if sets and rd==31:
            mnemonic="cmp" if sub else "cmn";ops=[reg(rn,sf,True),f"#{imm:#x}"]
        else:
            mnemonic=("sub" if sub else "add")+("s" if sets else "")
            ops=[reg(rd,sf,True),reg(rn,sf,True),f"#{imm:#x}"]
        return {"class":"arithmetic-immediate","mnemonic":mnemonic,"operands":ops,"meaning":"Immediate arithmetic","immediate":imm}
    # Move wide immediate: MOVN/MOVZ/MOVK.
    if (w & 0x1f800000) == 0x12800000:
        sf=(w>>31)&1;opc=(w>>29)&3;hw=(w>>21)&3;imm=(w>>5)&0xffff;rd=w&31
        names={0:"movn",2:"movz",3:"movk"}
        if opc in names and (sf or hw<2):
            shift=hw*16
            return {"class":"move-wide-immediate","mnemonic":names[opc],"operands":[reg(rd,sf),f"#{imm:#x}",f"lsl #{shift}"],"meaning":"Move wide immediate","immediate":imm,"shift":shift}
    # Logical shifted register: AND/ORR/EOR/ANDS.
    if (w & 0x1f000000) == 0x0a000000:
        sf=(w>>31)&1;opc=(w>>29)&3;shift=(w>>22)&3;amount=(w>>10)&63;rm=(w>>16)&31;rn=(w>>5)&31;rd=w&31
        names={0:"and",1:"orr",2:"eor",3:"ands"}
        if shift<3 and (sf or amount<32):
            m=names[opc];ops=[reg(rd,sf),reg(rn,sf),reg(rm,sf)]
            if shift or amount:ops.append(["lsl","lsr","asr"][shift]+f" #{amount}")
            if opc==1 and rn==31:m="mov";ops=[reg(rd,sf),reg(rm,sf)]
            if opc==3 and rd==31:m="tst";ops=[reg(rn,sf),reg(rm,sf)]
            return {"class":"logical-register","mnemonic":m,"operands":ops,"meaning":"Logical register operation"}
    # Load/store unsigned immediate (integer scalar).
    if (w & 0x3b000000) == 0x39000000:
        size=(w>>30)&3;opc=(w>>22)&3;imm=(w>>10)&0xfff;rn=(w>>5)&31;rt=w&31
        scale=1<<size;offset=imm*scale
        loads={1:"ldrb",2:"ldrh",3:"ldr"};stores={0:"strb",1:"strh",2:"str",3:"str"}
        if opc in loads:
            m=loads[opc];sf=1 if size==3 else 0
            return {"class":"load-store","mnemonic":m,"operands":[reg(rt,sf),f"[{reg(rn,1,True)}, #{offset:#x}]"],"meaning":"Unsigned-immediate load","memory_offset":offset}
        if opc==0 or opc==2:
            m=stores[opc];sf=1 if size==3 else 0
            return {"class":"load-store","mnemonic":m,"operands":[reg(rt,sf),f"[{reg(rn,1,True)}, #{offset:#x}]"],"meaning":"Unsigned-immediate store","memory_offset":offset}
    # Register-indirect branch family.
    if (w & 0xfffffc1f) in (0xd61f0000,0xd63f0000,0xd65f0000):
        base=w&0xfffffc1f;rn=(w>>5)&31
        m={0xd61f0000:"br",0xd63f0000:"blr",0xd65f0000:"ret"}[base]
        return {"class":"branch-register","mnemonic":m,"operands":[reg(rn,1)],"meaning":"Register-indirect control transfer"}
    return {"class":"unknown","mnemonic":None,"operands":[],"meaning":"Instruction class not implemented by this conservative decoder"}

def analyze(catalog: dict) -> dict:
    out=[];counts={}
    for rule in catalog["rules"]:
        decoded=[]
        for i,item in enumerate(rule["signature"]):
            value=int(item["value"],16);mask=int(item["mask"],16)
            d=decode(value)
            d.update({"word_index":i,"word":f"0x{value:08x}","mask":f"0x{mask:08x}","fully_constrained":mask==MASK32})
            if mask!=MASK32:
                d["meaning"] += " (masked template; wildcard bits are not known)"
            decoded.append(d)
        pi=rule["patch_word_index"]
        original=decoded[pi] if 0<=pi<len(decoded) else None
        replacement=decode(int(rule["replacement_word"],16))
        replacement.update({"word":rule["replacement_word"],"fully_constrained":True})
        if not rule["change"]:
            replacement=None
        record={"index":rule["index"],"name":rule["name"],"mutates":rule["change"],"patch_word_index":pi,
                "original_patch_instruction":original,"replacement_instruction":replacement,"signature_instructions":decoded}
        out.append(record)
        for d in decoded:
            counts[d["class"]]=counts.get(d["class"],0)+1
        if replacement:counts[replacement["class"]]=counts.get(replacement["class"],0)+1
    return {"schema_version":1,"artifact":"Phoenix PMU ARM64 semantic decode report",
      "provenance":catalog.get("provenance",{}),
      "scope":{"instruction_subset_only":True,"unknown_instructions_preserved":True,"masked_templates_flagged":True,
        "control_flow_reconstructed":False,"hardware_validation":False,"patch_application":False},
      "summary":{"rule_count":len(out),"signature_word_count":sum(len(x["signature_instructions"]) for x in out),
        "mutating_rule_count":sum(x["mutates"] for x in out),
        "unknown_signature_word_count":sum(d["class"]=="unknown" for x in out for d in x["signature_instructions"]),
        "decoded_class_counts":counts},
      "rules":out,
      "limitations":["Only selected AArch64 instruction classes are decoded.","Unknown words are retained without a guessed mnemonic.",
        "Masked signature words are templates; wildcard fields are not concrete instruction operands.",
        "Branch displacements are relative to the instruction address, which is not present in a signature window.",
        "This report does not reconstruct function boundaries, register liveness, flags, memory semantics, or complete control flow.",
        "A decoded replacement does not prove the patch is correct or compatible with another kernel build."]}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("catalog",type=Path)
    p.add_argument("-o","--output",type=Path,default=Path("pmu-arm64-semantic-decode.json"))
    a=p.parse_args()
    try:
        cat=json.loads(a.catalog.read_text(encoding="utf-8"));result=analyze(cat)
        a.output.parent.mkdir(parents=True,exist_ok=True)
        a.output.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
        print("Rules:",result["summary"]["rule_count"])
        print("Signature words:",result["summary"]["signature_word_count"])
        print("Unknown signature words:",result["summary"]["unknown_signature_word_count"])
        print("Decoded classes:",json.dumps(result["summary"]["decoded_class_counts"],sort_keys=True))
        print("JSON:",a.output)
        return 0
    except (OSError,UnicodeError,ValueError,KeyError,TypeError) as e:
        print(f"phoenix-pmu-decode: {e}",file=sys.stderr);return 2
if __name__=="__main__":raise SystemExit(main())
