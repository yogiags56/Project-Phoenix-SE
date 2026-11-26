import json,unittest
from pathlib import Path
from phoenix_pmu_patch_liveness import build,LivenessError

class PatchLivenessTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  root=Path(__file__).resolve().parents[3]
  cls.catalog=json.loads((root/"research"/"PMU-SIGNATURE-CATALOG.json").read_text())
  cls.report=build(cls.catalog)
 def site(self,n):return next(x for x in self.report["sites"] if x["rule"]==n)
 def test_four_dynamic_sites(self):
  self.assertEqual([x["rule"] for x in self.report["sites"]],[59,61,62,65])
 def test_rule59_branch_operand_has_local_load_producer(self):
  x=self.site(59)
  self.assertEqual(x["original"]["mnemonic"],"cbz")
  self.assertIsNotNone(x["prelude"]["original_operand_producers"]["r8"])
 def test_rule61_tbz_uses_locally_defined_w8(self):
  x=self.site(61)
  self.assertEqual(x["patched"]["kind"],"tbz")
  self.assertIsNotNone(x["prelude"]["patched_operand_producers"]["r8"])
  self.assertEqual(x["patched"]["reads"],["r8"])
 def test_rule65_bne_has_local_cmp_flag_producer(self):
  x=self.site(65)
  self.assertTrue(x["flag_delta"]["original_reads_NZCV"])
  self.assertEqual(x["flag_delta"]["nearest_local_NZCV_definition"]["mnemonic"],"cmp")
  self.assertFalse(x["flag_delta"]["patched_reads_NZCV"])
 def test_rule61_removed_w9_definition_is_reported(self):
  x=self.site(61)
  self.assertIn("r9",x["removed_register_definitions"])
 def test_rule62_removed_w10_definition_is_reported(self):
  x=self.site(62)
  self.assertIn("r10",x["removed_register_definitions"])
 def test_no_claim_of_whole_function_liveness(self):
  self.assertFalse(self.report["scope"]["whole_function_liveness"])
 def test_bad_redirect_rejected(self):
  c=json.loads(json.dumps(self.catalog));c["jumps"][0]["target_rule"]=67
  with self.assertRaises(LivenessError):build(c)
if __name__=="__main__":unittest.main()
