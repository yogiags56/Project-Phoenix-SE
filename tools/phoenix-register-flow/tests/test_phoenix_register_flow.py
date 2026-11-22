import tempfile,unittest
from pathlib import Path
from phoenix_register_flow import analyze

class TestRegisterFlow(unittest.TestCase):
 def run_listing(self,text):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d,"sample.s");p.write_text(text)
   return analyze(p,"fixture")
 def test_register_alias_and_movk_read_modify_write(self):
  r=self.run_listing("1000: movz x8, #0x12\n1004: movk x8, #0x34, lsl #16\n1008: lsr x9, x8, #2\n")
  self.assertEqual(r["instructions"][1]["reads"],["r8"])
  self.assertEqual(r["instructions"][1]["writes"],["r8"])
  self.assertEqual(r["def_use_links"][0]["register"],"r8")
  self.assertEqual(r["def_use_links"][0]["definition_index"],0)
 def test_memory_address_registers(self):
  r=self.run_listing("1000: add x8, x22, #0x20\n1004: ldr x9, [x8, #0x10]\n1008: str x9, [x22]\n")
  self.assertEqual(r["instructions"][1]["reads"],["r8"])
  self.assertEqual(r["instructions"][1]["writes"],["r9"])
  self.assertEqual(r["instructions"][2]["reads"],["r22","r9"])
 def test_unknown_instruction_is_barrier(self):
  r=self.run_listing("1000: mov x8, #1\n1004: mystery x8, x9\n1008: add x10, x8, #1\n")
  self.assertEqual(len(r["unknown_effect_barriers"]),1)
  self.assertEqual(r["def_use_links"],[])
 def test_flags(self):
  r=self.run_listing("1000: cmp x8, #1\n1004: b.ne 0x1010\n")
  self.assertTrue(r["instructions"][0]["flags_written"])
  self.assertTrue(r["instructions"][1]["flags_read"])
 def test_branch_register_reads(self):
  r=self.run_listing("1000: cbz w8, 0x1010\n1004: br x9\n")
  self.assertEqual(r["instructions"][0]["reads"],["r8"])
  self.assertEqual(r["instructions"][1]["reads"],["r9"])
if __name__=="__main__":unittest.main()
