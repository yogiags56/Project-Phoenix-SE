import json,unittest
from pathlib import Path
from phoenix_pmu_ldo import analyze,LDOError,overlaps

class LDOOverlapTests(unittest.TestCase):
 def catalog(self):
  root=Path(__file__).resolve().parents[3]
  return json.loads((root/"research"/"PMU-SIGNATURE-CATALOG.json").read_text())
 def test_real_catalog_overlap_edges(self):
  r=analyze(self.catalog());s=r["summary"]
  self.assertEqual(s["rule_count"],16)
  self.assertEqual(s["overlap_edge_count"],25)
  self.assertEqual(s["overlap_edges_ge_6_words"],17)
  self.assertEqual(s["dynamic_redirect_count"],4)
  self.assertFalse(r["scope"]["binary_offsets_resolved"])
 def test_known_overlap_54_to_69(self):
  r=analyze(self.catalog())
  e=next(x for x in r["overlap_edges"] if x["from_rule"]==54 and x["to_rule"]==69)
  self.assertEqual(e["overlap_words"],6)
  self.assertFalse(e["fully_constrained"])
 def test_nested_window_59_to_60(self):
  r=analyze(self.catalog())
  e=next(x for x in r["overlap_edges"] if x["from_rule"]==59 and x["to_rule"]==60)
  self.assertEqual(e["overlap_words"],8)
 def test_mask_mismatch_is_not_overlap(self):
  a={"signature":[{"value":1,"mask":0xffffffff},{"value":2,"mask":0xff}]}
  b={"signature":[{"value":2,"mask":0xffffffff}]}
  self.assertEqual(overlaps(a,b),0)
 def test_dynamic_branch_not_static_nop(self):
  r=analyze(self.catalog())
  p=next(x for x in r["patch_sites"] if x["rule_index"]==61)
  self.assertEqual(p["effective_behavior"],"dynamic_branch_redirect")
  self.assertEqual(p["dynamic_redirect"]["branch_kind"],"tbz")
if __name__=="__main__":unittest.main()
