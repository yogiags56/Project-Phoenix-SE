import json,unittest
from pathlib import Path
from phoenix_pmu_delta import audit,DeltaError

class DeltaAuditTests(unittest.TestCase):
 def test_full_reference_catalog_without_donor(self):
  root=Path(__file__).resolve().parents[3]
  cat=json.loads((root/"research"/"PMU-SIGNATURE-CATALOG.json").read_text())
  r=audit(cat);s=r["summary"]
  self.assertEqual(s["rule_count"],70)
  self.assertEqual(s["mutating_rules"],66)
  self.assertEqual(s["anchors"],4)
  self.assertEqual(s["dynamic_redirects"],4)
  self.assertFalse(r["scope"]["binary_signature_matches_verified"])
  self.assertFalse(r["scope"]["hardware_validation"])
 def test_dynamic_redirect_is_effective_instruction(self):
  cat={"rules":[
   {"index":0,"name":"source","signature_id":0,"change":True,"patch_word_index":0,"replacement_word":"0xd503201f","signature":[{"value":"0x34000008","mask":"0xffffffff"}]},
   {"index":1,"name":"target","signature_id":1,"change":False,"patch_word_index":0,"replacement_word":"0x00000000","signature":[{"value":"0x52805858","mask":"0xffffffff"}]}],
   "jumps":[{"source_rule":0,"target_rule":1,"branch_kind":"tbz"}]}
  row=audit(cat)["rules"][0]
  self.assertEqual(row["effective_replacement"]["mnemonic"],"tbz")
  self.assertEqual(row["dynamic_redirect"]["target_rule"],1)
  self.assertFalse(row["instruction_class_changed"])
  self.assertTrue(row["mnemonic_changed"])
 def test_masked_original_is_not_concrete(self):
  cat={"rules":[{"index":0,"name":"masked","change":True,"patch_word_index":0,"replacement_word":"0xd503201f","signature":[{"value":"0x54000001","mask":"0xff00001f"}]}]}
  row=audit(cat)["rules"][0]
  self.assertFalse(row["original_word_fully_constrained"])
  self.assertTrue(row["original_is_masked_template"])
 def test_rejects_invalid_jump(self):
  cat={"rules":[{"index":0,"name":"x","change":True,"patch_word_index":0,"replacement_word":"0xd503201f","signature":[{"value":"0xd503201f","mask":"0xffffffff"}]}],
       "jumps":[{"source_rule":0,"target_rule":8,"branch_kind":"b"}]}
  with self.assertRaises(DeltaError):audit(cat)
if __name__=="__main__":unittest.main()
