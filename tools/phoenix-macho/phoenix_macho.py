#!/usr/bin/env python3
"""Phoenix Mach-O Analyzer: bounded, read-only Mach-O 64-bit inspector."""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_UUID = 0x1B
LC_DYSYMTAB = 0xB
LC_BUILD_VERSION = 0x32
MAX_LOAD_COMMANDS = 100_000
MAX_SECTIONS = 500_000
MAX_SYMBOLS = 1_000_000

class MachOError(ValueError):
    pass

def unpack(fmt, data, offset, limit):
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > limit:
        raise MachOError("Structure exceeds binary boundary")
    return struct.unpack_from(fmt, data, offset)

def cstr(data, offset, limit):
    if offset < 0 or offset >= limit:
        raise MachOError("String offset outside binary")
    end = data.find(bytes([0]), offset, limit)
    if end < 0:
        raise MachOError("Unterminated string")
    return data[offset:end].decode("utf-8", errors="replace")

def cpu_name(cpu):
    names = {7:"x86", 0x01000007:"x86_64", 12:"ARM", 0x0100000C:"ARM64"}
    return names.get(cpu, "unknown")

def command_name(cmd):
    names = {
        0x1:"LC_SEGMENT", 0x2:"LC_SYMTAB", 0xB:"LC_DYSYMTAB",
        0xC:"LC_LOAD_DYLIB", 0xD:"LC_ID_DYLIB", 0x19:"LC_SEGMENT_64",
        0x1B:"LC_UUID", 0x20:"LC_CODE_SIGNATURE", 0x21:"LC_SEGMENT_SPLIT_INFO",
        0x22:"LC_REEXPORT_DYLIB", 0x23:"LC_LAZY_LOAD_DYLIB",
        0x24:"LC_ENCRYPTION_INFO_64", 0x25:"LC_DYLD_INFO",
        0x26:"LC_DYLD_INFO_ONLY", 0x2A:"LC_VERSION_MIN_IPHONEOS",
        0x2B:"LC_FUNCTION_STARTS", 0x2E:"LC_MAIN", 0x32:"LC_BUILD_VERSION",
        0x8000001F:"LC_REEXPORT_DYLIB", 0x80000018:"LC_LOAD_WEAK_DYLIB"
    }
    return names.get(cmd, "LC_UNKNOWN_0x%08x" % cmd)

def parse_macho_slice(data, base=0, length=None):
    if length is None:
        length = len(data)-base
    end = base+length
    if base < 0 or length < 32 or end > len(data):
        raise MachOError("Mach-O slice outside input")
    magic_bytes = data[base:base+4]
    if magic_bytes == bytes.fromhex("cffaedfe"):
        endian = "<"
    elif magic_bytes == bytes.fromhex("feedfacf"):
        endian = ">"
    else:
        raise MachOError("Slice is not a supported 64-bit Mach-O")
    (magic,cpu,subtype,filetype,ncmds,sizeofcmds,flags,reserved) = unpack(endian+"8I",data,base,end)
    if magic != MH_MAGIC_64:
        raise MachOError("Invalid 64-bit Mach-O magic")
    if ncmds > MAX_LOAD_COMMANDS:
        raise MachOError("Load command count exceeds safety limit")
    commands_start = base+32
    commands_end = commands_start+sizeofcmds
    if commands_end > end:
        raise MachOError("Load commands exceed slice boundary")
    pos = commands_start
    commands=[]
    segments=[]
    uuid=None
    symtab=None
    section_count=0
    for _ in range(ncmds):
        cmd,cmdsize=unpack(endian+"2I",data,pos,commands_end)
        if cmdsize < 8 or pos+cmdsize > commands_end:
            raise MachOError("Invalid load command size")
        item={"command":command_name(cmd),"cmd":cmd,"size":cmdsize,"offset":pos-base}
        if cmd == LC_SEGMENT_64:
            if cmdsize < 72:
                raise MachOError("LC_SEGMENT_64 shorter than fixed header")
            segname=data[pos+8:pos+24].split(bytes([0]),1)[0].decode("ascii",errors="replace")
            vmaddr,vmsize,fileoff,filesize,maxprot,initprot,nsects,segflags=unpack(endian+"4Q4I",data,pos+24,pos+cmdsize)
            if nsects > MAX_SECTIONS or 72+nsects*80 > cmdsize:
                raise MachOError("Section table exceeds segment command")
            section_count += nsects
            sections=[]
            secpos=pos+72
            for _section in range(nsects):
                sectname=data[secpos:secpos+16].split(bytes([0]),1)[0].decode("ascii",errors="replace")
                ssegname=data[secpos+16:secpos+32].split(bytes([0]),1)[0].decode("ascii",errors="replace")
                addr,secsize=unpack(endian+"2Q",data,secpos+32,pos+cmdsize)
                offset,align,reloff,nreloc,flags1,res1,res2,res3=unpack(endian+"8I",data,secpos+48,pos+cmdsize)
                if secsize and offset and offset+secsize > length:
                    raise MachOError("Section file range exceeds Mach-O slice")
                sections.append({"section":sectname,"segment":ssegname,"address":"0x%x"%addr,
                    "size":secsize,"file_offset":offset,"alignment":align,"relocation_offset":reloff,
                    "relocation_count":nreloc,"flags":"0x%08x"%flags1})
                secpos+=80
            if filesize and fileoff+filesize > length:
                raise MachOError("Segment file range exceeds Mach-O slice")
            segments.append({"name":segname,"vm_address":"0x%x"%vmaddr,"vm_size":vmsize,
                "file_offset":fileoff,"file_size":filesize,"max_protection":maxprot,
                "initial_protection":initprot,"sections":sections})
        elif cmd == LC_UUID:
            if cmdsize < 24:
                raise MachOError("LC_UUID shorter than 24 bytes")
            uuid=data[pos+8:pos+24].hex()
            item["uuid"]=uuid
        elif cmd == LC_SYMTAB:
            if cmdsize < 24:
                raise MachOError("LC_SYMTAB shorter than 24 bytes")
            symoff,nsyms,stroff,strsize=unpack(endian+"4I",data,pos+8,pos+cmdsize)
            if nsyms > MAX_SYMBOLS or symoff+nsyms*16 > length or stroff+strsize > length:
                raise MachOError("Symbol or string table exceeds slice")
            symtab={"symbol_offset":symoff,"symbol_count":nsyms,
                    "string_offset":stroff,"string_size":strsize}
            item["symbol_table"]=symtab
        elif cmd == LC_BUILD_VERSION:
            if cmdsize < 24:
                raise MachOError("LC_BUILD_VERSION shorter than fixed header")
            platform,minos,sdk,ntools=unpack(endian+"4I",data,pos+8,pos+cmdsize)
            if 24+ntools*8 > cmdsize:
                raise MachOError("Build tool table exceeds command")
            item["build_version"]={"platform":platform,"min_os":"%d.%d.%d"%(minos>>16,(minos>>8)&255,minos&255),
                "sdk":"%d.%d.%d"%(sdk>>16,(sdk>>8)&255,sdk&255),"tool_count":ntools}
        commands.append(item)
        pos += cmdsize
    if pos != commands_end:
        raise MachOError("Load command byte count does not match sizeofcmds")
    symbols=[]
    if symtab and symtab["symbol_count"]:
        strings=data[base+symtab["string_offset"]:base+symtab["string_offset"]+symtab["string_size"]]
        for i in range(symtab["symbol_count"]):
            at=base+symtab["symbol_offset"]+i*16
            strx,ntype,sect,desc,value=unpack(endian+"IBBHQ",data,at,end)
            name=cstr(strings,strx,len(strings)) if strx and strx<len(strings) else ""
            if name:
                symbols.append({"name":name,"type":ntype,"section_index":sect,
                                "description":desc,"value":"0x%x"%value})
    return {"architecture":{"cpu_type":cpu,"cpu_subtype":subtype,"name":cpu_name(cpu)},
        "file_type":filetype,"flags":"0x%08x"%flags,"reserved":reserved,
        "header":{"load_command_count":ncmds,"load_command_bytes":sizeofcmds},
        "uuid":uuid,"commands":commands,"segments":segments,
        "summary":{"segment_count":len(segments),"section_count":section_count,
                   "symbol_count":len(symbols),"has_symbol_table":symtab is not None},
        "symbol_table":symtab,"symbols":symbols}

def parse_binary(data, source="<memory>"):
    if len(data)<4:
        raise MachOError("Input is too short")
    magic=data[:4]
    slices=[]
    if magic in (bytes.fromhex("cafebabe"),bytes.fromhex("bebafeca"),
                 bytes.fromhex("cafebabf"),bytes.fromhex("bfbafeca")):
        endian="<" if magic in (bytes.fromhex("bebafeca"),bytes.fromhex("bfbafeca")) else ">"
        is64=magic in (bytes.fromhex("cafebabf"),bytes.fromhex("bfbafeca"))
        _,count=unpack(endian+"2I",data,0,len(data))
        if count==0 or count>128:
            raise MachOError("Invalid universal binary architecture count")
        entry_size=32 if is64 else 20
        table_end=8+count*entry_size
        if table_end>len(data):
            raise MachOError("Universal binary architecture table is truncated")
        for i in range(count):
            at=8+i*entry_size
            if is64:
                cpu,sub,offset,size,align,res=unpack(endian+"IIQQII",data,at,len(data))
            else:
                cpu,sub,offset,size,align=unpack(endian+"IIIII",data,at,len(data))
            if offset<table_end or size<32 or offset+size>len(data):
                raise MachOError("Universal binary slice range is invalid")
            parsed=parse_macho_slice(data,offset,size)
            slices.append({"index":i,"offset":offset,"size":size,"alignment":align,
                           "architecture":parsed["architecture"],"macho":parsed})
        binary_type="universal64" if is64 else "universal32"
    else:
        parsed=parse_macho_slice(data)
        slices=[{"index":0,"offset":0,"size":len(data),"architecture":parsed["architecture"],"macho":parsed}]
        binary_type="thin"
    return {"schema_version":1,"tool":"Phoenix Mach-O Analyzer","source":source,
        "file_size":len(data),"file_sha256":hashlib.sha256(data).hexdigest(),
        "binary_type":binary_type,"slice_count":len(slices),"slices":slices,
        "limitations":["Read-only structural inspection; no code execution, patching or signing.",
          "Symbol names are reported only when a conventional LC_SYMTAB is present.",
          "Chained fixups, exports trie, code signatures and compressed kernel collections are not decoded.",
          "A valid Mach-O parse does not establish device, kernel or OS compatibility."]}

def main(argv=None):
    p=argparse.ArgumentParser(description="Read-only Mach-O 64-bit and universal binary inspector")
    p.add_argument("input",type=Path)
    p.add_argument("--out",type=Path,default=Path("phoenix-macho-report.json"))
    a=p.parse_args(argv)
    try:
        data=a.input.read_bytes()
        report=parse_binary(data,a.input.name)
        a.out.parent.mkdir(parents=True,exist_ok=True)
        a.out.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
        print("Binary type:",report["binary_type"])
        print("Slices:",report["slice_count"])
        print("Report written:",a.out)
        return 0
    except (OSError,MachOError) as exc:
        print("phoenix-macho: error:",exc,file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
