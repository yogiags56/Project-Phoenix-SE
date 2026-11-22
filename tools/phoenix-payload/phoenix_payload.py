#!/usr/bin/env python3
"""Read-only format triage and optional raw IM4P payload extraction.

No decryption, decompression, signature verification, patching, or device access.
"""
from __future__ import annotations
import argparse, hashlib, json, sys
from pathlib import Path
from typing import Any

# Reuse the project's bounded DER parser; import works both from this directory
# and when invoked as tools/phoenix-payload/phoenix_payload.py.
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
sys.path.insert(0,str(ROOT/"tools"/"phoenix-img4"))
sys.path.insert(0,str(ROOT/"tools"/"phoenix-macho"))
sys.path.insert(0,str(ROOT/"tools"/"phoenix-kc"))
try:
    from phoenix_img4 import read_tlv, children, ia5, DERError
    from phoenix_macho import parse_binary, MachOError
    from phoenix_kc import inspect_fileset, FilesetError
except ImportError:  # pragma: no cover
    read_tlv=children=ia5=None
    DERError=ValueError
    parse_binary=inspect_fileset=None
    MachOError=FilesetError=ValueError

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def classify(data: bytes) -> list[str]:
    """Return signatures only; classification is triage, not full validation."""
    hits=[]
    if data.startswith(b"IMG4"): hits.append("IMG4 ASCII marker (not sufficient alone)")
    if data.startswith(b"\x30"): hits.append("DER SEQUENCE candidate")
    if data.startswith(b"bvx1") or data.startswith(b"bvx2") or data.startswith(b"bvx-"):
        hits.append("Apple LZFSE-family stream marker candidate")
    if data.startswith(b"\x1f\x8b"): hits.append("gzip")
    if data.startswith(b"PK\x03\x04"): hits.append("ZIP local file header")
    if data.startswith(b"\xfd7zXZ\x00"): hits.append("XZ")
    if data.startswith(b"\x04\x22\x4d\x18"): hits.append("LZ4 frame")
    if data.startswith(b"\x28\xb5\x2f\xfd"): hits.append("Zstandard frame")
    if data.startswith(b"bplist00"): hits.append("Apple binary property list")
    if data.startswith(b"\xcf\xfa\xed\xfe") or data.startswith(b"\xfe\xed\xfa\xcf"):
        hits.append("Mach-O 64-bit")
    if data.startswith(b"\xca\xfe\xba\xbe") or data.startswith(b"\xbe\xba\xfe\xca") or data.startswith(b"\xca\xfe\xba\xbf") or data.startswith(b"\xbf\xba\xfe\xca"):
        hits.append("Universal/FAT Mach-O candidate")
    if data.startswith(b"\xd0\x0d\xfe\xed"): hits.append("Flattened Device Tree (FDT)")
    if data.startswith(b"\x7fELF"): hits.append("ELF")
    if not hits: hits.append("Unknown / no recognized leading signature")
    return hits

def find_im4p(data: bytes) -> dict[str,Any] | None:
    if read_tlv is None: return None
    try:
        root=read_tlv(data,0)
        if root["end"]!=len(data) or root["tag"]!=0x30: return None
        top=children(data,root)
        if not top or ia5(data,top[0]) not in ("IMG4","IM4P"): return None
        candidates=[]
        if ia5(data,top[0])=="IM4P":
            candidates.append((0,root))
        else:
            for node in top[1:]:
                if node["tag"]!=0x30: continue
                nested=children(data,node)
                if nested and nested[0]["tag"]==0x16:
                    try: magic=ia5(data,nested[0])
                    except DERError: continue
                    if magic=="IM4P": candidates.append((node["start"],node))
        if len(candidates)!=1: return None
        base,node=candidates[0]
        fields=children(data,node)
        if len(fields)<4: return None
        payload_type=ia5(data,fields[1])
        description=ia5(data,fields[2])
        payload_node=fields[3]
        if payload_node["tag"]!=0x04: return None
        start=payload_node["content_start"]
        end=payload_node["end"]
        raw=data[start:end]
        return {"container_offset":base,"payload_type":payload_type,
                "description":description,"payload_offset":start,
                "payload_size":len(raw),"payload_sha256":sha256(raw),
                "payload_magic":classify(raw[:64]),"_payload":raw}
    except (DERError,ValueError,IndexError,KeyError):
        return None

def analyze_binary(data: bytes, source: str):
    """Structurally inspect recognized Mach-O payloads; never infer compatibility."""
    if parse_binary is None or len(data)<4:
        return None
    magic=data[:4]
    macho_magics={bytes.fromhex(x) for x in ("cffaedfe","feedfacf","cafebabe","bebafeca","cafebabf","bfbafeca")}
    if magic not in macho_magics:
        return None
    report={"format":"Mach-O candidate","source":source}
    try:
        parsed=parse_binary(data,source)
        report["macho"]=parsed
        # MH_FILESET is Mach-O filetype 0xC. Inspect entries only for a thin
        # fileset image; universal slices require selecting a slice explicitly.
        if parsed["binary_type"]=="thin" and parsed["slices"][0]["macho"]["file_type"]==0xC:
            if inspect_fileset is not None:
                report["kernel_collection"]=inspect_fileset(data,source)
        report["validation"]="structural parser accepted input"
    except (MachOError,FilesetError,ValueError,struct.error) as exc:
        report["validation"]="recognized magic, structural parse failed"
        report["error"]=str(exc)
    report["compatibility_conclusion"]="not assessed"
    return report

def inspect(path: Path, extract: Path|None=None):
    if not path.is_file(): raise ValueError(f"input not found: {path}")
    data=path.read_bytes()
    if not data: raise ValueError("empty input")
    head=data[:64]
    report={"schema_version":1,"tool":"Phoenix Payload Inspector",
      "source":{"path":str(path),"size_bytes":len(data),"sha256":sha256(data)},
      "leading_bytes_hex":head[:32].hex(),
      "leading_signature_candidates":classify(head),
      "scope":{"read_only_input":True,"decrypts":False,"decompresses":False,
        "verifies_signatures":False,"patches_firmware":False,"device_accessed":False},
      "interpretation":["Magic-byte matches are triage hints, not proof that the complete file is valid.",
        "An IM4P OCTET STRING extraction is a byte-for-byte container extraction only; it does not decrypt or decompress the payload.",
        "A payload may remain encrypted, compressed, or wrapped after extraction."]}
    im4p=find_im4p(data)
    if im4p:
        raw=im4p.pop("_payload")
        report["im4p"]=im4p
        if extract is not None:
            extract.parent.mkdir(parents=True,exist_ok=True)
            if extract.exists(): raise ValueError(f"refusing to overwrite existing output: {extract}")
            tmp=extract.with_name(extract.name+".phoenix-tmp")
            if tmp.exists(): raise ValueError(f"temporary output already exists: {tmp}")
            try:
                with tmp.open("xb") as f: f.write(raw)
                if tmp.stat().st_size!=len(raw) or sha256(tmp.read_bytes())!=sha256(raw):
                    raise ValueError("extracted payload verification failed")
                tmp.replace(extract)
            except Exception:
                try: tmp.unlink()
                except FileNotFoundError: pass
                raise
            report["im4p"]["extracted_path"]=str(extract)
    elif extract is not None:
        raise ValueError("no unique, structurally valid IM4P payload found; nothing extracted")
    return report

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("input",type=Path)
    p.add_argument("--extract-im4p-payload",type=Path)
    p.add_argument("--out",type=Path)
    a=p.parse_args(argv)
    try:
        report=inspect(a.input,a.extract_im4p_payload)
        rendered=json.dumps(report,indent=2)+"\n"
        if a.out:
            a.out.parent.mkdir(parents=True,exist_ok=True)
            if a.out.exists(): raise ValueError(f"refusing to overwrite report: {a.out}")
            a.out.write_text(rendered,encoding="utf-8")
            print(f"Report written: {a.out}")
        else: print(rendered,end="")
        return 0
    except (OSError,ValueError) as exc:
        print(f"phoenix-payload: error: {exc}",file=sys.stderr);return 2
if __name__=="__main__": raise SystemExit(main())
