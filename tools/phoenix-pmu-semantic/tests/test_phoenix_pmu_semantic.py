import unittest
from phoenix_pmu_semantic import decode,analyze
class DecoderTests(unittest.TestCase):
 def test_nop(self): self.assertEqual(decode(0xd503201f)["mnemonic"],"nop")
 def test_cmp_immediate(self):
  d=decode(0x7101801f);self.assertEqual(d["mnemonic"],"cmp");self.assertEqual(d["immediate"],0x60)
 def test_movz(self):
  d=decode(0x52812ce1);self.assertEqual(d["mnemonic"],"movz");self.assertEqual(d["operands"][0],"w1")
 def test_conditional_branch(self):
  d=decode(0x54000001);self.assertEqual(d["mnemonic"],"b.ne")
 def test_bl(self): self.assertEqual(decode(0x94000000)["mnemonic"],"bl")
 def test_tbz(self):
  d=decode(0x36000017);self.assertEqual(d["mnemonic"],"tbz");self.assertEqual(d["tested_bit"],0)
 def test_adrp(self):
  d=decode(0x9000000a);self.assertEqual(d["mnemonic"],"adrp");self.assertEqual(d["operands"][0],"x10")
 def test_unsigned_immediate_load_widths(self):
  cases=[(0x39400000,"ldrb","w0",1),(0x79400000,"ldrh","w0",2),(0xb9400000,"ldr","w0",4),(0xf9400000,"ldr","x0",8)]
  for word,mnemonic,dest,width in cases:
   with self.subTest(word=hex(word)):
    d=decode(word);self.assertEqual(d["mnemonic"],mnemonic);self.assertEqual(d["operands"][0],dest);self.assertEqual(d["access_size_bytes"],width)
 def test_unsigned_immediate_store_widths(self):
  cases=[(0x39000000,"strb","w0",1),(0x79000000,"strh","w0",2),(0xb9000000,"str","w0",4),(0xf9000000,"str","x0",8)]
  for word,mnemonic,src,width in cases:
   with self.subTest(word=hex(word)):
    d=decode(word);self.assertEqual(d["mnemonic"],mnemonic);self.assertEqual(d["operands"][0],src);self.assertEqual(d["access_size_bytes"],width)
 def test_scaled_load_store_offset(self):
  d=decode(0xf94002c8);self.assertEqual(d["mnemonic"],"ldr");self.assertEqual(d["operands"],["x8","[x22, #0x0]"])
  d=decode(0xf9405108);self.assertEqual(d["operands"][1],"[x8, #0xa0]")
 def test_lsrv(self):
  d=decode(0x9ada2508);self.assertEqual(d["mnemonic"],"lsrv");self.assertEqual(d["operands"],["x8","x8","x26"])
 def test_dynamic_redirect_overrides_static_nop_placeholder(self):
  cat={"provenance":{},"jumps":[{"source_rule":0,"target_rule":1,"branch_kind":"b"}],
   "rules":[
    {"index":0,"name":"dynamic source","change":True,"patch_word_index":0,"replacement_word":"0xd503201f","signature":[{"value":"0x34000008","mask":"0xff00001f"}]},
    {"index":1,"name":"target anchor","change":False,"patch_word_index":0,"replacement_word":"0x00000000","signature":[{"value":"0x52805858","mask":"0xffffffff"}]}
   ]}
  r=analyze(cat);self.assertEqual(r["rules"][0]["replacement_instruction"]["mnemonic"],"b")
  self.assertTrue(r["rules"][0]["static_placeholder_is_not_final"])
  self.assertEqual(r["rules"][0]["dynamic_redirect"]["target_rule"],1)
 def test_unknown_is_explicit(self): self.assertEqual(decode(0x00000000)["class"],"unknown")
 def test_masked_template_flag(self):
  cat={"provenance":{},"rules":[{"index":0,"name":"x","change":True,"patch_word_index":0,
    "replacement_word":"0xd503201f","signature":[{"value":"0x54000001","mask":"0xff00001f"}]}]}
  r=analyze(cat);self.assertFalse(r["rules"][0]["signature_instructions"][0]["fully_constrained"])
  self.assertIn("masked template",r["rules"][0]["signature_instructions"][0]["meaning"])
if __name__=="__main__":unittest.main()
