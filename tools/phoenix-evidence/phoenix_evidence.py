#!/usr/bin/env python3
"""Read-only IPSW evidence inspector for local Phoenix research.

Inventories BuildManifest identity and a named kernelcache ZIP member. It does
not decrypt, decompress, patch, sign, restore, or execute firmware.
"""
from __future__ import annotations
import argparse, hashlib, json, plistlib, sys, zipfile
from pathlib import Path, PurePosixPath

DEFAULT_KERNEL="kernelcache.release.ipad6f"
CHUNK=1024*1024

def sha256_file(path: Path):
    h=hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda:f.read(CHUNK),b""): h.update(block)
    return h.hexdigest()

def sha256_stream(stream):
    h=hashlib.sha256(); size=0
    while True:
        block=stream.read(CHUNK)
        if not block: break
        size+=len(block);h.update(block)
    return h.hexdigest(),size

def safe_member(name: str):
    p=PurePosixPath(name)
    return not p.is_absolute() and ".." not in p.parts and "\\" not in name

def manifest_identity(data: bytes):
    obj=plistlib.loads(data)
    if not isinstance(obj,dict): raise ValueError("BuildManifest.plist root must be a dictionary")
    products=obj.get("SupportedProductTypes",[])
    if not isinstance(products,list): products=[]
    return {
      "product_build_version":obj.get("ProductBuildVersion"),
      "product_version":obj.get("ProductVersion"),
      "supported_product_types":sorted(set(x for x in products if isinstance(x,str))),
      "build_manifest_keys":sorted(str(k) for k in obj.keys())
    }

def inspect_ipsw(ipsw: Path, kernel_name: str, extract: Path|None=None):
    if not ipsw.is_file(): raise ValueError(f"IPSW not found: {ipsw}")
    with zipfile.ZipFile(ipsw,"r") as z:
        names=z.namelist()
        manifests=[n for n in names if n=="BuildManifest.plist"]
        if len(manifests)!=1: raise ValueError(f"expected exactly one root BuildManifest.plist, found {len(manifests)}")
        manifest_info=z.getinfo(manifests[0])
        if manifest_info.file_size>64*1024*1024: raise ValueError("BuildManifest exceeds 64 MiB safety limit")
        identity=manifest_identity(z.read(manifests[0]))
        candidates=[n for n in names if PurePosixPath(n).name==PurePosixPath(kernel_name).name]
        if len(candidates)!=1: raise ValueError(f"expected exactly one ZIP member named {kernel_name}, found {len(candidates)}")
        member=candidates[0]
        if not safe_member(member): raise ValueError("unsafe kernelcache member path")
        info=z.getinfo(member)
        if info.file_size<=0: raise ValueError("kernelcache ZIP member is empty")
        if info.file_size>8*1024*1024*1024: raise ValueError("kernelcache exceeds 8 GiB safety limit")
        with z.open(info,"r") as stream:
            digest,size=sha256_stream(stream)
        extracted=None
        if extract is not None:
            extract.parent.mkdir(parents=True,exist_ok=True)
            # Stream to a user-selected local path; never overwrite an existing file.
            if extract.exists(): raise ValueError(f"refusing to overwrite existing output: {extract}")
            tmp=extract.with_name(extract.name+".phoenix-tmp")
            if tmp.exists(): raise ValueError(f"temporary output already exists: {tmp}")
            try:
                with z.open(info,"r") as src,tmp.open("xb") as dst:
                    while True:
                        block=src.read(CHUNK)
                        if not block: break
                        dst.write(block)
                if tmp.stat().st_size!=size or sha256_file(tmp)!=digest:
                    raise ValueError("extracted kernelcache hash/size mismatch")
                tmp.replace(extract)
            except Exception:
                try: tmp.unlink()
                except FileNotFoundError: pass
                raise
            extracted={"path":str(extract),"sha256":digest,"size_bytes":size}
        return {
          "schema_version":1,"tool":"Phoenix IPSW Evidence Inspector",
          "scope":{"read_only_source":True,"ipsw_modified":False,"decrypts":False,
            "decompresses":False,"firmware_patched":False,"device_accessed":False},
          "ipsw":{"path":str(ipsw),"size_bytes":ipsw.stat().st_size,"sha256":sha256_file(ipsw)},
          "build_manifest":{"archive_path":manifests[0],"size_bytes":manifest_info.file_size,**identity},
          "kernelcache":{"requested_basename":kernel_name,"archive_path":member,
            "compressed_size_bytes":info.compress_size,"uncompressed_size_bytes":size,
            "zip_compression_method":info.compress_type,"crc32_zip_metadata":f"{info.CRC:08x}",
            "sha256_uncompressed_member":digest,"extracted":extracted},
          "interpretation":["BuildManifest product types identify supported restore products; they do not by themselves prove the kernelcache is decrypted or directly disassemblable.",
            "The kernelcache member hash is computed over bytes decompressed by Python's ZIP reader, not over any later IMG4 payload transformation.",
            "Further IMG4, compression, encryption, Mach-O, or kernel-collection inspection is a separate documented step."]
        }

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("ipsw",type=Path)
    p.add_argument("--kernelcache",default=DEFAULT_KERNEL)
    p.add_argument("--extract-kernelcache",type=Path,help="optional local output path; existing files are never overwritten")
    p.add_argument("--out",type=Path,help="optional JSON report path; stdout if omitted")
    a=p.parse_args(argv)
    try:
        report=inspect_ipsw(a.ipsw,a.kernelcache,a.extract_kernelcache)
        rendered=json.dumps(report,indent=2)+"\n"
        if a.out:
            a.out.parent.mkdir(parents=True,exist_ok=True)
            a.out.write_text(rendered,encoding="utf-8")
            print(f"JSON report: {a.out}")
        else: print(rendered,end="")
        return 0
    except (OSError,zipfile.BadZipFile,KeyError,ValueError,plistlib.InvalidFileException) as e:
        print(f"phoenix-evidence: {e}",file=sys.stderr);return 2
if __name__=="__main__": raise SystemExit(main())
