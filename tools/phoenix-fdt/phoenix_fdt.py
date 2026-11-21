#!/usr/bin/env python3
"""Phoenix FDT Analyzer: bounded, read-only Flattened Device Tree parser."""
from __future__ import annotations
import argparse, hashlib, json, struct, sys
from pathlib import Path

FDT_MAGIC=0xD00DFEED
BEGIN_NODE, END_NODE, PROP, NOP, END = 1, 2, 3, 4, 9
HEADER_SIZE=40
MAX_NODES=200_000
MAX_PROPERTIES=1_000_000

class FDTError(ValueError):
    pass

def u32(data, offset, limit):
    if offset < 0 or offset+4 > limit:
        raise FDTError("32-bit field exceeds block boundary")
    return struct.unpack_from(">I", data, offset)[0]

def align4(value):
    return (value+3)&~3

def c_string(data, start, limit):
    if start < 0 or start >= limit:
        raise FDTError("String offset outside block")
    end=data.find(b"\x00", start, limit)
    if end < 0:
        raise FDTError("Unterminated string")
    try:
        value=data[start:end].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FDTError("Invalid UTF-8 string") from exc
    return value, end+1

def decode_property(raw):
    result={"length":len(raw),"raw_hex":raw.hex()}
    if not raw:
        result.update(kind="boolean",value=True)
        return result
    if raw.endswith(b"\x00"):
        try:
            values=[x.decode("utf-8") for x in raw[:-1].split(b"\x00")]
            if all(all(ch.isprintable() for ch in x) for x in values):
                result.update(kind="string_list" if len(values)>1 else "string",
                              value=values if len(values)>1 else values[0])
                return result
        except UnicodeDecodeError:
            pass
    if len(raw)%4==0:
        result["u32_cells"]=[struct.unpack_from(">I",raw,i)[0] for i in range(0,len(raw),4)]
        result["kind"]="u32_cells"
    else:
        result["kind"]="bytes"
    return result

def parse_fdt(data, source="<memory>"):
    if len(data)<HEADER_SIZE:
        raise FDTError("File is shorter than the 40-byte FDT header")
    (magic,total,off_struct,off_strings,off_rsv,version,last_compat,boot_cpuid,
     strings_size,struct_size)=struct.unpack_from(">10I",data,0)
    if magic!=FDT_MAGIC:
        raise FDTError("Bad FDT magic")
    if total<HEADER_SIZE or total>len(data):
        raise FDTError("FDT totalsize outside input file")
    if version<16 or last_compat>version:
        raise FDTError("Unsupported or inconsistent FDT version")
    if min(off_struct,off_strings,off_rsv)<HEADER_SIZE:
        raise FDTError("FDT block offset overlaps header")
    struct_end=off_struct+struct_size
    strings_end=off_strings+strings_size
    if struct_end>total or strings_end>total or off_struct%4:
        raise FDTError("Invalid FDT block bounds or alignment")
    strings=data[off_strings:strings_end]
    pos=off_struct
    stack=[]
    roots=[]
    nodes=props=0
    ended=False
    while pos+4<=struct_end:
        token_at=pos
        token=u32(data,pos,struct_end)
        pos+=4
        if token==BEGIN_NODE:
            name,after=c_string(data,pos,struct_end)
            pos=align4(after)
            if pos>struct_end:
                raise FDTError("Node name alignment exceeds structure block")
            node={"name":name,"properties":{},"children":[]}
            nodes+=1
            if nodes>MAX_NODES:
                raise FDTError("Node count exceeds safety limit")
            if stack: stack[-1]["children"].append(node)
            else: roots.append(node)
            stack.append(node)
        elif token==END_NODE:
            if not stack: raise FDTError("Unmatched END_NODE")
            stack.pop()
        elif token==PROP:
            if not stack or pos+8>struct_end:
                raise FDTError("Property outside node or truncated property header")
            length=u32(data,pos,struct_end)
            nameoff=u32(data,pos+4,struct_end)
            pos+=8
            if nameoff>=len(strings): raise FDTError("Property name offset outside strings block")
            name,_=c_string(strings,nameoff,len(strings))
            value_end=pos+length
            if value_end>struct_end: raise FDTError("Property value exceeds structure block")
            if name in stack[-1]["properties"]: raise FDTError("Duplicate property name")
            stack[-1]["properties"][name]=decode_property(data[pos:value_end])
            pos=align4(value_end)
            if pos>struct_end: raise FDTError("Property alignment exceeds structure block")
            props+=1
            if props>MAX_PROPERTIES: raise FDTError("Property count exceeds safety limit")
        elif token==NOP:
            continue
        elif token==END:
            if stack: raise FDTError("FDT_END before all nodes closed")
            ended=True
            break
        else:
            raise FDTError("Unknown FDT token 0x%08x at offset %d"%(token,token_at))
    if not ended: raise FDTError("Missing FDT_END token")
    if len(roots)!=1: raise FDTError("Expected exactly one root node")
    reservations=[]
    rp=off_rsv
    while rp+16<=total:
        address,size=struct.unpack_from(">QQ",data,rp)
        rp+=16
        if address==0 and size==0: break
        reservations.append({"address":"0x%x"%address,"size":size})
        if len(reservations)>65536: raise FDTError("Reserve map exceeds safety limit")
    else:
        raise FDTError("Unterminated reserve map")
    def flatten(node,parent="/"):
        path=(parent.rstrip("/")+"/"+node["name"]) if parent!="/" else "/"+node["name"]
        yield {"path":path,"name":node["name"],"properties":node["properties"],
               "child_count":len(node["children"])}
        for child in node["children"]:
            yield from flatten(child,path)
    index=list(flatten(roots[0]))
    return {
      "schema_version":1,"tool":"Phoenix FDT Analyzer","source":source,
      "file_size":len(data),"file_sha256":hashlib.sha256(data[:total]).hexdigest(),
      "header":{"totalsize":total,"version":version,"last_compatible_version":last_compat,
       "boot_cpuid_phys":boot_cpuid,"structure_offset":off_struct,"structure_size":struct_size,
       "strings_offset":off_strings,"strings_size":strings_size,"reserve_map_offset":off_rsv},
      "reserve_map":reservations,"root":roots[0],"node_index":index,
      "summary":{"node_count":nodes,"property_count":props,"reserve_entry_count":len(reservations)},
      "limitations":[
       "Raw standard FDT blobs only; compressed and Apple-specific wrappers are not decoded.",
       "Property classification is heuristic; phandles and cell semantics are not resolved.",
       "Parsing does not establish iOS driver compatibility and does not modify firmware."]}

def main(argv=None):
    p=argparse.ArgumentParser(description="Read-only standard FDT/DTB parser")
    p.add_argument("input",type=Path)
    p.add_argument("--out",type=Path,default=Path("phoenix-fdt-report.json"))
    a=p.parse_args(argv)
    try:
        report=parse_fdt(a.input.read_bytes(),a.input.name)
        a.out.parent.mkdir(parents=True,exist_ok=True)
        a.out.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
        print("FDT nodes:",report["summary"]["node_count"])
        print("Properties:",report["summary"]["property_count"])
        print("Report written:",a.out)
        return 0
    except (OSError,FDTError) as exc:
        print("phoenix-fdt: error:",exc,file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
