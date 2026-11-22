import struct,unittest,json,tempfile
from pathlib import Path
from phoenix_pmu_discovery import discover,DiscoveryError,load_catalog

def macho_fileset(entry_blob):
 entry_offset=80
 command=bytearray(40)
 struct.pack_into("<IIQQII",command,0,0x80000035,40,0xFFFFFFF007004000,entry_offset,32,0)
 command[32:36]=bytes([112,109,117,0])
 header=struct.pack("<8I",0xFEEDFACF,0x0100000C,0,0xC,1,len(command),0,0)
 return header+bytes(command)+bytes(entry_offset-(32+len(command)))+entry_blob

class DiscoveryTests(unittest.TestCase):
 def catalog(self):
  return [{"index":7,"name":"fixture PMU pattern","signature_id":7,
           "words":[(0xD2800015,0xffffffff),(0x7100811f,0xffffffff)]}]
 def test_finds_masked_signature_and_keeps_file_offset(self):
  body=b"\x00"*8+struct.pack("<II",0xD2800015,0x7100811f)+b"\x00"*12
  raw=macho_fileset(body)
  r=discover(raw,self.catalog(),"fixture.kc")
  e=r["entries"][0]
  self.assertEqual(e["identifier"],"pmu")
  self.assertTrue(e["name_hint_only"])
  self.assertEqual(e["signature_match_count"],1)
  self.assertEqual(e["matches"][0]["file_offset"],88)
  self.assertNotIn("virtual_address",e["matches"][0])
  self.assertFalse(r["scope"]["compatibility_assessed"])
 def test_masked_wildcard_bits(self):
  cat=[{"index":1,"name":"masked","signature_id":1,
        "words":[(0x54000000,0xff000000)]}]
  body=b"\x00"*4+struct.pack("<I",0x54000121)
  r=discover(macho_fileset(body),cat)
  self.assertEqual(r["entries"][0]["signature_match_count"],1)
 def test_rejects_non_fileset(self):
  with self.assertRaises(DiscoveryError): discover(b"not a fileset",self.catalog())
 def test_rejects_invalid_catalog_word(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/"bad.json"
   p.write_text(json.dumps({"rules":[{"index":0,"signature":[{"value":"nothex","mask":"ffffffff"}]}]}))
   with self.assertRaises(DiscoveryError): load_catalog(p)
if __name__=="__main__":unittest.main()
