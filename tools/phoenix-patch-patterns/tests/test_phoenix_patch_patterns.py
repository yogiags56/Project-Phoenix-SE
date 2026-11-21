import tempfile,unittest
from pathlib import Path
from phoenix_patch_patterns import analyze,parse_input,markdown

class TestPatterns(unittest.TestCase):
 def test_word_masks_and_comment(self):
  src="""/* PMU compare signature */
static const Word cmp_sig[] = {
 {0x7101801fu, 0xffffffffu},
 {0x54000001u, 0xff00001fu},
};
static void patch(void) { match(cmp_sig); edit(4, 0); }
"""
  with tempfile.TemporaryDirectory() as d:
   p=Path(d,"x.c");p.write_text(src);r=analyze("pmu",p)
  a=r["arrays"][0]
  self.assertEqual(a["count"],2)
  self.assertEqual(a["exact_mask_words"],1)
  self.assertEqual(a["comment"],"PMU compare signature")
  self.assertTrue(a["use_lines"])

 def test_payload(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d,"x.c");p.write_text("static const uint32_t payload[] = {0x1u, 2u, 0x3u};")
   self.assertEqual(analyze("p",p)["arrays"][0]["count"],3)

 def test_ignore_comments_strings(self):
  src="""// static const Word fake[] = {{1,2}};
const char *s="edit(";
"""
  with tempfile.TemporaryDirectory() as d:
   p=Path(d,"x.c");p.write_text(src);r=analyze("x",p)
  self.assertEqual(r["arrays"],[])
  self.assertEqual(r["summary"]["mutation_calls"],0)

 def test_markdown_caveat(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d,"x.c");p.write_text("static const Word p[]={{1,0xffffffff}};");r=analyze("demo",p)
  self.assertIn(r["sha256"],markdown({"generated_utc":"now","sources":[r]}))

 def test_bad_input(self):
  with self.assertRaises(Exception):parse_input("bad")

if __name__=="__main__":unittest.main()
