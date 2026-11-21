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
    # Variable shifts (LSLV, LSRV, ASRV, RORV).
    if (w & 0x7fe0fc00) in (0x1ac02000,0x1ac02400,0x1ac02800,0x1ac02c00):
        sf=(w>>31)&1; base=w&0x7fe0fc00
        names={0x1ac02000:"lslv",0x1ac02400:"lsrv",0x1ac02800:"asrv",0x1ac02c00:"rorv"}
        rd=w&31;rn=(w>>5)&31;rm=(w>>16)&31
        return {"class":"variable-shift","mnemonic":names[base],"operands":[reg(rd,sf),reg(rn,sf),reg(rm,sf)],"meaning":"Variable shift using register amount"}
    # Load/store unsigned immediate (integer scalar).
    # size selects access width; opc selects store/load/sign-extending form.
    if (w & 0x3b000000) == 0x39000000:
        size=(w>>30)&3;opc=(w>>22)&3;imm=(w>>10)&0xfff;rn=(w>>5)&31;rt=w&31
        offset=imm*(1<<size)
        if opc in (0,1):
            is_load=(opc==1)
            names={0:("strb","ldrb"),1:("strh","ldrh"),2:("str","ldr"),3:("str","ldr")}
            mnemonic=names[size][1 if is_load else 0]
            # Byte/halfword/word transfers use W registers; 64-bit uses X.
            sf=1 if size==3 else 0
            return {"class":"load-store","mnemonic":mnemonic,
                    "operands":[reg(rt,sf),f"[{reg(rn,1,True)}, #{offset:#x}]"],
                    "meaning":"Unsigned-immediate load" if is_load else "Unsigned-immediate store",
                    "memory_offset":offset,"access_size_bytes":1<<size}
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
        placeholder=decode(int(rule["replacement_word"],16))
        placeholder.update({"word":rule["replacement_word"],"fully_constrained":True})
        if not rule["change"]:
            placeholder=None
        record={"index":rule["index"],"name":rule["name"],"mutates":rule["change"],"patch_word_index":pi,
                "original_patch_instruction":original,"static_placeholder":placeholder,
                "replacement_instruction":placeholder,"signature_instructions":decoded}
        out.append(record)
        for d in decoded:
            counts[d["class"]]=counts.get(d["class"],0)+1
        if placeholder:counts[placeholder["class"]]=counts.get(placeholder["class"],0)+1
    # The upstream C patcher overwrites four static table placeholders with
    # address-dependent branch instructions in prepare_jumps().
    dynamic={}
    for jump in catalog.get("jumps",[]):
        source=int(jump.get("source_rule",jump.get("source",-1)))
        target=int(jump.get("target_rule",jump.get("target",-1)))
        kind=jump.get("branch_kind")
        if kind is None:
            kind="tbz" if jump.get("test_bit")==1 else "b"
        if source<0 or target<0 or source>=len(out) or target>=len(out):
            raise ValueError("jump redirect references an invalid rule")
        if kind not in ("b","tbz"):
            raise ValueError("unsupported dynamic jump kind")
        target_name=out[target]["name"]
        if kind=="tbz":
            actual={"class":"branch","mnemonic":"tbz","operands":["w8","#0",f"<rule {target}: {target_name}>"],
                    "meaning":"Dynamic test-bit branch; target address is resolved from matched kernel sites",
                    "branch_encoding":"0x36000008 | (imm14 << 5)","tested_register":"w8","tested_bit":0,
                    "target_rule":target,"displacement":"(target_found - source_found) / 4"}
        else:
            actual={"class":"branch","mnemonic":"b","operands":[f"<rule {target}: {target_name}>"],
                    "meaning":"Dynamic unconditional branch; target address is resolved from matched kernel sites",
                    "branch_encoding":"0x14000000 | imm26","target_rule":target,
                    "displacement":"(target_found - source_found) / 4"}
        out[source]["static_placeholder_is_not_final"]=True
        out[source]["replacement_instruction"]=actual
        out[source]["dynamic_redirect"]={"source_rule":source,"target_rule":target,"branch_kind":kind,
            "source_rule_name":out[source]["name"],"target_rule_name":target_name,
            "source_instruction_before_patch":out[source]["original_patch_instruction"],
            "actual_instruction":actual,
            "static_table_placeholder":out[source]["static_placeholder"]}
        dynamic[source]=out[source]["dynamic_redirect"]
    return {"schema_version":1,"artifact":"Phoenix PMU ARM64 semantic decode report",

      "provenance":catalog.get("provenance",{}),
      "scope":{"instruction_subset_only":True,"unknown_instructions_preserved":True,"masked_templates_flagged":True,
        "dynamic_jump_redirects_reconstructed":True,"complete_control_flow_reconstructed":False,"hardware_validation":False,"patch_application":False},
      "summary":{"rule_count":len(out),"signature_word_count":sum(len(x["signature_instructions"]) for x in out),
        "mutating_rule_count":sum(x["mutates"] for x in out),
        "unknown_signature_word_count":sum(d["class"]=="unknown" for x in out for d in x["signature_instructions"]),
        "decoded_class_counts":counts},
      "dynamic_jump_redirects":[out[i]["dynamic_redirect"] for i in sorted(dynamic)],
      "rules":out,
      "limitations":["Only selected AArch64 instruction classes are decoded.","Unknown words are retained without a guessed mnemonic.",
        "Masked signature words are templates; wildcard fields are not concrete instruction operands.",
        "Branch displacements are relative to the instruction address, which is not present in a signature window.",
        "This report does not reconstruct function boundaries, register liveness, flags, memory semantics, or complete control flow.",
        "Dynamic branch destinations depend on the exact matched kernel offsets and are not resolved by the catalog alone.","A decoded replacement does not prove the patch is correct or compatible with another kernel build."]}

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
