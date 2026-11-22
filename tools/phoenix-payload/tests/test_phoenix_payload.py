import tempfile,unittest
from pathlib import Path
from phoenix_payload import classify,inspect

def tlv(tag,payload):
 n=len(payload)
 if n<128: length=bytes([n])
 else:
  raw=n.to_bytes((n.bit_length()+7)//8,"big");length=bytes([0x80|len(raw)])+raw
 return bytes([tag])+length+payload
def ia5(s):return tlv(0x16,s.encode("ascii"))
def seq(*items):return tlv(0x30,b"".join(items))

class TestPayloadInspector(unittest.TestCase):
 def test_magic_triage(self):
  self.assertIn("gzip",classify(b"\x1f\x8b"+b"x"*20))
  self.assertIn("Apple LZFSE-family stream marker candidate",classify(b"bvx2"+b"x"*20))
  self.assertIn("Mach-O 64-bit",classify(bytes.fromhex("cffaedfe")+b"x"*20))
 def test_im4p_extract_exact_bytes(self):
  payload=b"\xcf\xfa\xed\xfe"+b"synthetic-kernel-payload"
  im4p=seq(ia5("IM4P"),ia5("krnl"),ia5("test-kernel"),tlv(0x04,payload))
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);src=root/"kernel.im4p";out=root/"out"/"payload.bin"
   src.write_bytes(im4p)
   r=inspect(src,out)
   self.assertEqual(out.read_bytes(),payload)
   self.assertEqual(r["im4p"]["payload_size"],len(payload))
   self.assertEqual(r["im4p"]["payload_sha256"],r["source"]["sha256"] if False else __import__("hashlib").sha256(payload).hexdigest())
   self.assertIn("Mach-O 64-bit",r["im4p"]["payload_magic"])
 def test_refuse_overwrite(self):
  payload=b"raw"
  im4p=seq(ia5("IM4P"),ia5("krnl"),ia5("kernel"),tlv(0x04,payload))
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);src=root/"a.im4p";out=root/"payload"
   src.write_bytes(im4p);out.write_bytes(b"keep")
   with self.assertRaisesRegex(ValueError,"refusing to overwrite"):inspect(src,out)
 def test_non_im4p_does_not_extract(self):
  with tempfile.TemporaryDirectory() as d:
   src=Path(d)/"unknown.bin";src.write_bytes(b"\x00\x01\x02")
   with self.assertRaisesRegex(ValueError,"no unique"):inspect(src,Path(d)/"out")
if __name__=="__main__":unittest.main()
