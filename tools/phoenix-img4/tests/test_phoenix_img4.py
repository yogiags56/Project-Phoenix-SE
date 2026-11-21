import hashlib
import unittest
from phoenix_img4 import DERError, parse_bytes, read_tlv

def der(tag, payload):
    n = len(payload)
    if n < 128:
        length = bytes([n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + length + payload

def ia5(s):
    return der(0x16, s.encode("ascii"))

def seq(*items):
    return der(0x30, b"".join(items))

class ParserTests(unittest.TestCase):
    def test_im4p_payload_hash(self):
        payload = b"firmware-payload"
        raw = seq(ia5("IM4P"), ia5("krnl"), ia5("Kernel"), der(0x04, payload))
        report = parse_bytes(raw, hash_payload=True)
        self.assertEqual(report["payload"]["type"], "krnl")
        self.assertEqual(report["payload"]["octet_string"]["sha256"],
                         hashlib.sha256(payload).hexdigest())

    def test_img4_embedded_containers(self):
        p = seq(ia5("IM4P"), ia5("krnl"), ia5("Kernel"), der(0x04, b"x"))
        m = seq(ia5("IM4M"), der(0x04, b"manifest"))
        report = parse_bytes(seq(ia5("IMG4"), p, m))
        self.assertEqual([x["container_type"] for x in report["embedded_containers"]],
                         ["IM4P", "IM4M"])

    def test_reject_indefinite_length(self):
        with self.assertRaises(DERError):
            read_tlv(b"\x30\x80\x00\x00", 0)

    def test_reject_trailing_bytes(self):
        with self.assertRaises(DERError):
            parse_bytes(seq(ia5("IM4M")) + b"\x00")

    def test_reject_nonminimal_length(self):
        with self.assertRaises(DERError):
            read_tlv(b"\x04\x81\x01x", 0)

    def test_reject_truncated_value(self):
        with self.assertRaises(DERError):
            read_tlv(b"\x04\x05xx", 0)

if __name__ == "__main__":
    unittest.main()
