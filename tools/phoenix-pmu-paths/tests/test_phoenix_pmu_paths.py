import json, unittest
from pathlib import Path
from phoenix_pmu_paths import build, PathModelError

class SymbolicPathTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  root=Path(__file__).resolve().parents[3]
  cls.catalog=json.loads((root/"research"/"PMU-SIGNATURE-CATALOG.json").read_text())
  cls.report=build(cls.catalog)
 def test_expected_edges_and_paths(self):
  s=self.report["summary"]
  self.assertEqual(s["ldo_rules"],16)
  self.assertEqual(s["dynamic_redirect_edges"],4)
  self.assertEqual(s["conditional_fallthrough_edges"],1)
  self.assertEqual(s["total_edges"],5)
  self.assertEqual(s["documented_path_summaries"],3)
 def test_tbz_two_outcomes(self):
  edges=[e for e in self.report["edges"] if e["from"]==61]
  self.assertEqual({(e["to"],e["condition"]) for e in edges},
   {(67,"W8[0] == 0"),(62,"W8[0] == 1 (branch not taken)")})
 def test_option_path_preserves_branch_condition(self):
  p=next(x for x in self.report["path_summaries"] if x["id"]=="alternate-enable-option")
  self.assertEqual(p["steps"],[65,60,61,62,68])
  self.assertIn("bit 0 is set",p["condition"])
 def test_no_complete_cfg_claim(self):
  self.assertFalse(self.report["scope"]["complete_cfg_reconstructed"])
  self.assertFalse(self.report["scope"]["all_predecessors_known"])
 def test_missing_redirect_rejected(self):
  c=json.loads(json.dumps(self.catalog))
  c["jumps"]=[j for j in c["jumps"] if j.get("source_rule")!=61]
  with self.assertRaises(PathModelError): build(c)
if __name__=="__main__": unittest.main()
