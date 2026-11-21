import json
import tempfile
import unittest
from pathlib import Path
from phoenix_kernel_compat import KernelAnalysisError, compare, read_report

def macho(cpu=0x0100000c,sub=0):
    return {"tool":"Phoenix Mach-O Analyzer","slices":[{"architecture":{"cpu_type":cpu,"cpu_subtype":sub}}]}
def kc(cpu=0x0100000c,sub=0):
    return {"tool":"Phoenix Kernel Collection Inspector","container":{"architecture":{"cpu_type":cpu,"cpu_subtype":sub}},"entries":[]}
def kext(ids):
    return {"tool":"Phoenix Kext Dependency Analyzer",
            "bundles":[{"bundle_id":x,"valid":True} for x in ids],
            "dependencies":[{"consumer":x,"dependency":"com.apple.kernel","required_version":"1","resolved":True} for x in ids]}
def bundle(m,k,x):
    return {"macho":{"path":"m","sha256":"a","data":m},
            "kc":{"path":"k","sha256":"b","data":k},
            "kext":{"path":"x","sha256":"c","data":x}}

class KernelCompatibilityTests(unittest.TestCase):
    def test_overlap_is_potential_not_compatibility(self):
        r=compare(bundle(macho(),kc(),kext(["com.example.a"])),
                  bundle(macho(),kc(),kext(["com.example.a"])))
        self.assertEqual(r["indication"],"Potential")
        self.assertEqual(r["summary"]["shared_kext_bundle_id_count"],1)

    def test_disjoint_macho_architecture_is_incompatible(self):
        r=compare(bundle(macho(0x0100000c),kc(),kext([])),
                  bundle(macho(0x01000007),kc(),kext([])))
        self.assertEqual(r["indication"],"Incompatible")

    def test_disjoint_kernel_collection_architecture_is_incompatible(self):
        r=compare(bundle(macho(),kc(0x0100000c),kext([])),
                  bundle(macho(),kc(0x01000007),kext([])))
        self.assertEqual(r["indication"],"Incompatible")

    def test_empty_evidence_is_unknown(self):
        r=compare(bundle(macho(None),kc(None),kext([])),
                  bundle(macho(None),kc(None),kext([])))
        self.assertEqual(r["indication"],"Unknown")

    def test_kext_sets_are_reported(self):
        r=compare(bundle(macho(),kc(),kext(["a","b"])),
                  bundle(macho(),kc(),kext(["b","c"])))
        self.assertEqual(r["kext_comparison"]["shared_bundle_ids"],["b"])
        self.assertEqual(r["kext_comparison"]["target_only_bundle_ids"],["a"])
        self.assertEqual(r["kext_comparison"]["donor_only_bundle_ids"],["c"])

    def test_rejects_wrong_report_tool(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp,"bad.json")
            p.write_text(json.dumps({"tool":"wrong"}))
            with self.assertRaises(KernelAnalysisError):
                read_report(p,"Phoenix Mach-O Analyzer")

if __name__=="__main__":
    unittest.main()
