#!/usr/bin/env python3
"""Phoenix Kernel Collection Inspector: read-only Mach-O MH_FILESET inventory."""
from __future__ import annotations
import argparse, hashlib, json, struct, sys
from pathlib import Path

MH_FILESET=0xC
LC_FILESET_ENTRY=0x80000035
MAX_COMMANDS=100_000
MAX_ENTRIES=100_000

class FilesetError(ValueError): pass

def u32(data,off,endian,limit):
    if off<0 or off+4>limit: raise FilesetError("32-bit field exceeds binary boundary")
    return struct.unpack_from(endian+"I",data,off)[0]

def u64(data,off,endian,limit):
    if off<0 or off+8>limit: raise FilesetError("64-bit field exceeds binary boundary")
    return struct.unpack_from(endian+"Q",data,off)[0]

def cstr(data,off,limit):
    if off<0 or off>=limit: raise FilesetError("Entry identifier offset outside command")
    end=data.find(b"\x00",off,limit)
    if end<0: raise FilesetError("Unterminated fileset entry identifier")
    return data[off:end].decode("utf-8",errors="replace")

def inspect_embedded(data,off,size):
    end=off+size
    if off<0 or size<32 or end>len(data):
        return {"valid":False,"reason":"embedded slice is truncated"}
    magic=data[off:off+4]
    if magic==bytes.fromhex("cffaedfe"): endian="<"
    elif magic==bytes.fromhex("feedfacf"): endian=">"
    else: return {"valid":False,"reason":"entry does not begin with 64-bit Mach-O magic"}
    _,cpu,sub,filetype,ncmds,sizeofcmds,flags,reserved=struct.unpack_from(endian+"8I",data,off)
    if ncmds>MAX_COMMANDS or off+32+sizeofcmds>end:
        return {"valid":False,"reason":"embedded Mach-O load commands exceed entry bounds"}
    return {"valid":True,"architecture":{"cpu_type":cpu,"cpu_subtype":sub},
            "file_type":filetype,"file_type_name":"MH_FILESET" if filetype==MH_FILESET else "Mach-O",
            "load_command_count":ncmds,"load_command_bytes":sizeofcmds,"flags":"0x%08x"%flags}

def inspect_fileset(data,source="<memory>"):
    if len(data)<32: raise FilesetError("Input is shorter than a 64-bit Mach-O header")
    magic=data[:4]
    if magic==bytes.fromhex("cffaedfe"): endian="<"
    elif magic==bytes.fromhex("feedfacf"): endian=">"
    else: raise FilesetError("Input is not a supported 64-bit Mach-O")
    _,cpu,sub,filetype,ncmds,sizeofcmds,flags,reserved=struct.unpack_from(endian+"8I",data,0)
    if filetype!=MH_FILESET: raise FilesetError("Mach-O file type is not MH_FILESET (0xC)")
    if ncmds>MAX_COMMANDS or 32+sizeofcmds>len(data):
        raise FilesetError("Fileset load command table exceeds input bounds")
    commands_end=32+sizeofcmds
    pos=32
    entries=[]
    inventory=[]
    for index in range(ncmds):
        cmd=u32(data,pos,endian,commands_end)
        cmdsize=u32(data,pos+4,endian,commands_end)
        if cmdsize<8 or pos+cmdsize>commands_end:
            raise FilesetError("Invalid load command size at index %d"%index)
        inventory.append({"cmd":cmd,"size":cmdsize})
        if cmd==LC_FILESET_ENTRY:
            if cmdsize<32: raise FilesetError("LC_FILESET_ENTRY shorter than fixed fields")
            vmaddr=u64(data,pos+8,endian,pos+cmdsize)
            fileoff=u64(data,pos+16,endian,pos+cmdsize)
            idoff=u32(data,pos+24,endian,pos+cmdsize)
            reserved_entry=u32(data,pos+28,endian,pos+cmdsize)
            if idoff>=cmdsize: raise FilesetError("Entry identifier offset exceeds command size")
            identifier=cstr(data,pos+idoff,pos+cmdsize)
            if fileoff>=len(data): raise FilesetError("Fileset entry file offset exceeds input")
            entries.append({"identifier":identifier,"vm_address":"0x%x"%vmaddr,
                            "file_offset":fileoff,"reserved":reserved_entry,
                            "load_command_index":index})
            if len(entries)>MAX_ENTRIES: raise FilesetError("Fileset entry count exceeds safety limit")
        pos+=cmdsize
    if pos!=commands_end: raise FilesetError("Load command byte count does not match sizeofcmds")
    offsets=sorted({e["file_offset"] for e in entries})
    bounds={off:(offsets[i+1] if i+1<len(offsets) else len(data))-off for i,off in enumerate(offsets)}
    for entry in entries:
        span=bounds[entry["file_offset"]]
        entry["available_size"]=span
        entry["embedded_macho"]=inspect_embedded(data,entry["file_offset"],span)
    return {
      "schema_version":1,"tool":"Phoenix Kernel Collection Inspector","source":source,
      "file_size":len(data),"file_sha256":hashlib.sha256(data).hexdigest(),
      "container":{"format":"Mach-O MH_FILESET","architecture":{"cpu_type":cpu,"cpu_subtype":sub},
       "file_type":filetype,"load_command_count":ncmds,"load_command_bytes":sizeofcmds,
       "flags":"0x%08x"%flags,"reserved":reserved},
      "commands":inventory,"entries":entries,
      "summary":{"entry_count":len(entries),
       "valid_embedded_macho_count":sum(e["embedded_macho"]["valid"] for e in entries),
       "invalid_embedded_macho_count":sum(not e["embedded_macho"]["valid"] for e in entries)},
      "limitations":[
       "Inspects the outer 64-bit MH_FILESET header and LC_FILESET_ENTRY records only.",
       "Embedded validation checks Mach-O header and load-command bounds; it does not recursively decode images.",
       "No compression, encryption, code-signature, chained-fixup, symbol or kext dependency decoding.",
       "Successful parsing does not establish iOS version or device compatibility.",
       "Read-only: no firmware patching, signing, execution or restore."]}

def main(argv=None):
    p=argparse.ArgumentParser(description="Read-only Mach-O MH_FILESET inventory")
    p.add_argument("input",type=Path)
    p.add_argument("--out",type=Path,default=Path("phoenix-kc-report.json"))
    a=p.parse_args(argv)
    try:
        report=inspect_fileset(a.input.read_bytes(),a.input.name)
        a.out.parent.mkdir(parents=True,exist_ok=True)
        a.out.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
        print("Container:",report["container"]["format"])
        print("Entries:",report["summary"]["entry_count"])
        print("Valid embedded Mach-O headers:",report["summary"]["valid_embedded_macho_count"])
        print("Report written:",a.out)
        return 0
    except (OSError,FilesetError) as exc:
        print("phoenix-kc: error:",exc,file=sys.stderr)
        return 2

if __name__=="__main__": raise SystemExit(main())
