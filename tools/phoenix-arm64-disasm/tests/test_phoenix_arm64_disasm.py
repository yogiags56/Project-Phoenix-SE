import tempfile,unittest
from pathlib import Path
from phoenix_arm64_disasm import analyze,diff,number,parse_instruction
class TestDisassembly(unittest.TestCase):
 def parse(self,s):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d,"listing.txt");p.write_text(s);return analyze(p,"fixture")
 def test_branches(self):
  r=self.parse("1000: bl 0x1100\n1004: b.eq 0x1020\n1008: ret\n")
  self.assertEqual(r["summary"]["instruction_count"],3)
  self.assertEqual(r["instructions"][0]["control_flow"]["target"],0x1100)
  self.assertTrue(r["instructions"][1]["control_flow"]["conditional"])
  self.assertEqual(r["instructions"][2]["control_flow"]["kind"],"return")
 def test_adrp_add(self):
  r=self.parse("1000: adrp x8, 0x2000\n1004: add x8, x8, #0x138\n")
  self.assertEqual(r["instructions"][0]["address_materialization"]["resolved_with_add"]["address"],0x2138)
 def test_raw_words(self):
  r=self.parse("1000: 90000008 adrp x8, 0x2000\n1004: 9104e108 add x8, x8, #0x138\n")
  self.assertEqual(r["summary"]["instruction_count"],2)
 def test_diff(self):
  a=self.parse("1000: mov x0, #1\n1004: ret\n")
  b=self.parse("1000: mov x0, #2\n1008: ret\n")
  self.assertEqual([x["status"] for x in diff(a,b)],["changed","removed","added"])
 def test_non_code_lines_and_cmp(self):
  r=self.parse("file format mach-o arm64\n1000: cmp x0, #0\n")
  self.assertEqual(r["summary"]["instruction_count"],1);self.assertEqual(r["summary"]["compare_count"],1)
 def test_number(self):
  self.assertEqual(number("#0x10"),16);self.assertEqual(number("#12"),12);self.assertIsNone(number("symbol"))
 def test_nested_operand_commas(self):
  _,ops=parse_instruction("ldr x0, [x1, #0x10]")
  self.assertEqual(ops,["x0","[x1, #0x10]"])
if __name__=="__main__":unittest.main()
