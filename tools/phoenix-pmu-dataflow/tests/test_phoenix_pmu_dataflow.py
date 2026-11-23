import json,unittest
from pathlib import Path
from phoenix_pmu_dataflow import analyze,decode_extended,effects

class LDODataflowTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  root=Path(__file__).resolve().parents[3]
  cls.catalog=json.loads((root/"research"/"PMU-SIGNATURE-CATALOG.json").read_text())
  cls.report=analyze(cls.catalog)
 def test_full_ldo_range(self):
  s=self.report["summary"]
  self.assertEqual(s["rule_count"],16)
  self.assertEqual(s["instruction_word_count"],144)
  self.assertEqual(s["dynamic_redirects"],4)
  self.assertFalse(self.report["scope"]["runtime_register_values_known"])
 def test_lsrv_reads_source_and_shift_register(self):
  d=decode_extended(0x9ada2508)
  self.assertEqual(d["mnemonic"],"lsrv")
  reads,writes,*_=effects(d)
  self.assertEqual(reads,["r8","r26"])
  self.assertEqual(writes,["r8"])
 def test_umaddl_decoding(self):
  d=decode_extended(0x9ba82abc)
  self.assertEqual(d["mnemonic"],"umaddl")
  self.assertEqual(d["operands"],["x28","w21","w8","x10"])
 def test_pair_store(self):
  d=decode_extended(0xa901abe9)
  self.assertEqual(d["mnemonic"],"stp")
  reads,writes,*_=effects(d)
  self.assertIn("r9",reads);self.assertIn("r10",reads)
  self.assertEqual(writes,[])
 def test_masked_words_remain_marked(self):
  r=next(x for x in self.report["rules"] if x["rule_index"]==61)
  self.assertFalse(r["instructions"][2]["fully_constrained"])
 def test_dynamic_redirects_not_resolved(self):
  self.assertTrue(all("not resolved" in j["interpretation"] for j in self.report["dynamic_redirects"]))
if __name__=="__main__":unittest.main()
