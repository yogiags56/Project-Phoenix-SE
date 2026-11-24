import json,unittest
from pathlib import Path
from phoenix_pmu_cf_delta import build,ControlDeltaError

class ControlDeltaTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  root=Path(__file__).resolve().parents[3]
  cls.catalog=json.loads((root/"research"/"PMU-SIGNATURE-CATALOG.json").read_text())
  cls.report=build(cls.catalog)
 def row(self,n):return next(x for x in self.report["redirects"] if x["source_rule"]==n)
 def test_four_source_declared_redirects(self):
  self.assertEqual(self.report["summary"]["dynamic_redirects"],4)
  self.assertEqual([x["source_rule"] for x in self.report["redirects"]],[59,61,62,65])
 def test_rule59_cbz_becomes_unconditional(self):
  x=self.row(59)
  self.assertEqual(x["original"]["mnemonic"],"cbz")
  self.assertEqual(x["original"]["condition"]["expression"],"w8 == 0")
  self.assertEqual(x["patched"]["condition"]["expression"],"always")
  self.assertFalse(x["original"]["displacement_known"])
 def test_rule61_mov_becomes_tbz(self):
  x=self.row(61)
  self.assertEqual(x["original"]["mnemonic"],"mov")
  self.assertEqual(x["original"]["register_effects"]["writes"],["w9"])
  self.assertEqual(x["patched"]["condition"]["expression"],"W8[0] == 0")
  self.assertEqual(x["patched"]["writes"],[])
 def test_rule62_mov_becomes_unconditional_branch(self):
  x=self.row(62)
  self.assertEqual(x["original"]["mnemonic"],"mov")
  self.assertEqual(x["original"]["register_effects"]["writes"],["w10"])
  self.assertEqual(x["patched"]["mnemonic"],"b")
 def test_rule65_bne_condition_removed(self):
  x=self.row(65)
  self.assertEqual(x["original"]["mnemonic"],"b.ne")
  self.assertEqual(x["original"]["condition"]["expression"],"Z == 0")
  self.assertEqual(x["patched"]["condition"]["expression"],"always")
 def test_static_nop_rule57(self):
  self.assertEqual(self.report["static_nop_contrast"]["rule"],57)
  self.assertFalse(self.report["static_nop_contrast"]["dynamic_redirect"])
 def test_wrong_jump_rejected(self):
  c=json.loads(json.dumps(self.catalog))
  c["jumps"][0]["target_rule"]=67
  with self.assertRaises(ControlDeltaError):build(c)
if __name__=="__main__":unittest.main()
