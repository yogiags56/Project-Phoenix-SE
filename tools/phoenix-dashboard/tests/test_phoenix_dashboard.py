import json
import tempfile
import unittest
from pathlib import Path
from phoenix_dashboard import DashboardError, build_manifest, load_inputs, render_html

class DashboardTests(unittest.TestCase):
    def test_loads_reports_and_hashes_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp,"report.json")
            p.write_text(json.dumps({"tool":"Phoenix A9 Platform Profiler","subsystem_count":19}))
            reports=load_inputs([("profile",p)])
            self.assertEqual(len(reports),1)
            self.assertEqual(len(reports[0]["sha256"]),64)

    def test_rejects_duplicate_labels(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp,"r.json"); p.write_text("{}")
            with self.assertRaises(DashboardError):
                load_inputs([("same",p),("same",p)])

    def test_rejects_non_object_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp,"r.json"); p.write_text("[]")
            with self.assertRaises(DashboardError):
                load_inputs([("x",p)])

    def test_manifest_does_not_infer_aggregate_verdict(self):
        reports=[{"label":"mapper","path":"x.json","sha256":"a"*64,
          "data":{"tool":"Phoenix Firmware Compatibility Mapper","status":"Potential","comparison":{}}}]
        m=build_manifest(reports)
        self.assertFalse(m["interpretation"]["aggregate_verdict"])
        self.assertEqual(m["reports"][0]["status"],"Potential")

    def test_html_escapes_untrusted_report_values(self):
        reports=[{"label":"<script>alert(1)</script>","path":"x","sha256":"a"*64,
          "data":{"tool":"<img src=x>","status":"Unknown","limitations":["<script>bad()</script>"]}}]
        page=render_html(build_manifest(reports))
        self.assertNotIn("<script>alert(1)</script>",page)
        self.assertIn("&lt;script&gt;",page)

    def test_dashboard_includes_hash_and_warning(self):
        m=build_manifest([{"label":"A9","path":"p","sha256":"b"*64,
          "data":{"tool":"Phoenix A9 Platform Profiler","device_tested_subsystem_count":0}}])
        page=render_html(m)
        self.assertIn("SHA-256",page)
        self.assertIn("No aggregate compatibility verdict",page)

if __name__=="__main__":
    unittest.main()
