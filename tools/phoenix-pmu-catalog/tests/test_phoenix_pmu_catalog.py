import unittest
from phoenix_pmu_catalog import parse
FIXTURE = r'''
static const Word sig0[] = {
 {0x7101501fu, 0xffffffffu},
 {0x54000008u, 0xff00001fu},
};
static const Word sig1[] = {
 {0x52800001u, 0xffffffffu},
};
static Rule rules[] = {
 {"GPIO geometry / transfer", sig0, COUNT(sig0), 1, 0x7100001fu, 1, 0},
 {"LDO anchor", sig1, COUNT(sig1), 0, 0xd503201fu, 0, 0},
};
static const Jump jumps[] = {
 {0, 1, 0},
 {1, 0, 1},
 {0, 1, 0},
 {1, 0, 1},
};
static const unsigned char ldo_before[] = {0x01,0x02,0x03};
static const unsigned char ldo_after[] = {0x01,0x09,0x03};
'''
class CatalogTests(unittest.TestCase):
 def test_rejects_non_reference_rule_count(self):
  with self.assertRaisesRegex(ValueError,"expected 70"):
   parse(FIXTURE)
 def test_accepts_exact_shape(self):
  declarations=[]
  rule_rows=[]
  for i in range(70):
   declarations.append(f"static const Word sig{i}[] = {{{{0x7101501fu, 0xffffffffu}}}};")
   rule_rows.append(f'{{"group", sig{i}, COUNT(sig{i}), 0, 0x7100001fu, {1 if i<66 else 0}, 0}}')
  src="\n".join(declarations)+"\nstatic Rule rules[] = {\n"+",\n".join(rule_rows)+"\n};\n"
  src+="static const Jump jumps[] = {{0, 1, 0},{1, 2, 1},{2, 3, 0},{3, 4, 1}};\n"
  src+="static const unsigned char ldo_before[] = {0x01,0x02};\nstatic const unsigned char ldo_after[] = {0x01,0x03};\n"
  result=parse(src,"fixture")
  self.assertEqual(result["summary"]["rule_count"],70)
  self.assertEqual(result["summary"]["mutating_rule_count"],66)
  self.assertEqual(result["summary"]["anchor_rule_count"],4)
  self.assertEqual(result["summary"]["ldo_changed_byte_count"],1)
  self.assertEqual(result["jumps"][1]["branch_kind"],"tbz")
if __name__=="__main__": unittest.main()
