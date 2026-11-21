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
 def test_unknown_is_explicit(self): self.assertEqual(decode(0x00000000)["class"],"unknown")
 def test_masked_template_flag(self):
  cat={"provenance":{},"rules":[{"index":0,"name":"x","change":True,"patch_word_index":0,
    "replacement_word":"0xd503201f","signature":[{"value":"0x54000001","mask":"0xff00001f"}]}]}
  r=analyze(cat);self.assertFalse(r["rules"][0]["signature_instructions"][0]["fully_constrained"])
  self.assertIn("masked template",r["rules"][0]["signature_instructions"][0]["meaning"])
if __name__=="__main__":unittest.main()
