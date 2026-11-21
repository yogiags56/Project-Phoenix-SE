#!/usr/bin/env python3
"""Phoenix IMG4 Parser: bounded, read-only ASN.1 DER inspection."""
from __future__ import annotations
import argparse, hashlib, json, sys
from pathlib import Path

class DERError(ValueError):
    pass

def read_tlv(data: bytes, offset: int, limit: int | None = None):
    if limit is None:
        limit = len(data)
    if offset < 0 or offset >= limit or limit > len(data):
        raise DERError("TLV offset out of bounds")
    start = offset
    tag = data[offset]
    offset += 1
    if tag & 0x1f == 0x1f:
        raise DERError("High-tag-number form is not supported")
    if offset >= limit:
        raise DERError("Missing DER length")
    first = data[offset]
    offset += 1
    if first == 0x80:
        raise DERError("Indefinite length is BER, not DER")
    if first < 0x80:
        length = first
    else:
        count = first & 0x7f
        if count == 0 or count > 8 or offset + count > limit:
            raise DERError("Invalid or truncated DER length")
        raw = data[offset:offset + count]
        if raw[0] == 0:
            raise DERError("Non-minimal DER length")
        length = int.from_bytes(raw, "big")
        if length < 128 or (count > 1 and length < (1 << (8 * (count - 1)))):
            raise DERError("Non-minimal DER length")
        offset += count
    end = offset + length
    if end > limit:
        raise DERError("DER value exceeds enclosing boundary")
    return {"tag": tag, "start": start, "header": offset - start,
            "content_start": offset, "length": length, "end": end}

def children(data, node):
    if not node["tag"] & 0x20:
        raise DERError("Expected constructed DER value")
    out, pos = [], node["content_start"]
    while pos < node["end"]:
        item = read_tlv(data, pos, node["end"])
        out.append(item)
        pos = item["end"]
    if pos != node["end"]:
        raise DERError("Invalid child boundary")
    return out

def ia5(data, node):
    if node["tag"] != 0x16:
        raise DERError("Expected IA5String")
    try:
        value = data[node["content_start"]:node["end"]].decode("ascii")
    except UnicodeDecodeError as exc:
        raise DERError("Non-ASCII IA5String") from exc
    if any(ord(c) < 32 or ord(c) > 126 for c in value):
        raise DERError("Non-printable IA5String")
    return value

def summary(node):
    return {"tag": "0x%02x" % node["tag"], "offset": node["start"],
            "header_length": node["header"], "content_offset": node["content_start"],
            "content_length": node["length"], "end_offset": node["end"]}

def parse_bytes(data: bytes, source="<memory>", hash_payload=False):
    if not data:
        raise DERError("Empty input")
    root = read_tlv(data, 0)
    if root["end"] != len(data):
        raise DERError("Trailing bytes after top-level DER object")
    if root["tag"] != 0x30:
        raise DERError("Expected top-level SEQUENCE")
    top = children(data, root)
    if not top:
        raise DERError("Empty top-level SEQUENCE")
    magic = ia5(data, top[0])
    if magic not in ("IMG4", "IM4P", "IM4M", "IM4R"):
        raise DERError("Unknown container magic: " + repr(magic))
    report = {"schema_version": 1, "tool": "Phoenix IMG4 Parser",
              "source": source, "file_size": len(data), "container_type": magic,
              "top_level": summary(root), "children": [summary(x) for x in top],
              "limitations": [
                  "Structural DER parsing only; no cryptographic validation.",
                  "No payload decryption or extraction.",
                  "Container metadata does not prove device compatibility."]}
    if magic == "IM4P":
        if len(top) < 3:
            raise DERError("IM4P requires magic, payload type and description")
        payload_type, description = ia5(data, top[1]), ia5(data, top[2])
        payload_node = top[3] if len(top) > 3 else None
        if payload_node is not None and payload_node["tag"] != 0x04:
            raise DERError("Expected IM4P OCTET STRING payload")
        payload = None
        if payload_node is not None:
            raw = data[payload_node["content_start"]:payload_node["end"]]
            payload = summary(payload_node)
            payload["sha256"] = hashlib.sha256(raw).hexdigest() if hash_payload else None
        report["payload"] = {"type": payload_type, "description": description,
                             "octet_string": payload,
                             "additional_fields": [summary(x) for x in top[4:]]}
    elif magic == "IMG4":
        embedded = []
        for child in top[1:]:
            if child["tag"] == 0x30:
                nested = children(data, child)
                if nested and nested[0]["tag"] == 0x16:
                    name = ia5(data, nested[0])
                    if name in ("IM4P", "IM4M", "IM4R"):
                        embedded.append({"container_type": name, "offset": child["start"],
                                         "length": child["end"] - child["start"],
                                         "child_count": len(nested)})
        report["embedded_containers"] = embedded
    else:
        report["fields"] = [summary(x) for x in top[1:]]
        report["note"] = "Fields are not semantically decoded or authenticated."
    return report

def inspect(path: Path, hash_payload=False):
    data = path.read_bytes()
    report = parse_bytes(data, path.name, hash_payload)
    report["file_sha256"] = hashlib.sha256(data).hexdigest()
    return report

def main(argv=None):
    parser = argparse.ArgumentParser(description="Read-only IMG4-family DER structure inspector")
    parser.add_argument("input", type=Path)
    parser.add_argument("--out", type=Path, default=Path("phoenix-img4-report.json"))
    parser.add_argument("--hash-payload", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = inspect(args.input, args.hash_payload)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print("Container:", report["container_type"])
        print("Report written:", args.out)
        return 0
    except (OSError, DERError) as exc:
        print("phoenix-img4: error:", exc, file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
