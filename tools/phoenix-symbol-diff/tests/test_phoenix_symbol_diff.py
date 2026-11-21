import json
import tempfile
import unittest
from pathlib import Path
from phoenix_symbol_diff import SymbolDiffError, compare, load_report

def report(symbols,cpu=0x0100000c,sub=0):
    return {"tool":"Phoenix Mach-O Analyzer","binary_type":"thin","file_sha256":"abc",
      "slices":[{"architecture":{"cpu_type":cpu,"cpu_subtype":sub,"name":"ARM64"},
        "macho":{"summary":{"has_symbol_table":True},"symbols":symbols}}]}
def sym(name,kind=0x0f):
    return {"name":name,"type":kind,"section_index":1,"description":0,"value":"0x1000"}
def wrap(obj,name):
    return {"path":name,"sha256":"report-hash","source_sha256":obj["file_sha256"],
      "binary_type":obj["binary_type"],"slices":{
        (obj["slices"][0]["architecture"]["cpu_type"],obj["slices"][0]["architecture"]["cpu_subtype"]):
        {"architecture":obj["slices"][0]["architecture"],"symbols":obj["slices"][0]["macho"]["symbols"],
         "has_symbol_table":obj["slices"][0]["macho"]["summary"]["has_symbol_table"]}}}

class SymbolDiffTests(unittest.TestCase):
    def test_compares_defined_and_undefined_symbols(self):
        t=wrap(report([sym("_common"),sym("_target"),sym("_missing",0)]),"t")
        d=wrap(report([sym("_common"),sym("_donor"),sym("_other",0)]),"d")
        r=compare(t,d)["slice_comparisons"][0]
        self.assertEqual(r["summary"]["shared_symbol_name_count"],1)
        self.assertEqual(r["target_only_defined_symbols"]["names"],["_target"])
        self.assertEqual(r["donor_only_undefined_symbols"]["names"],["_other"])

    def test_architecture_mismatch_is_not_cross_compared(self):
        t=wrap(report([sym("_x")],0x0100000c),"t")
        d=wrap(report([sym("_x")],0x01000007),"d")
        r=compare(t,d)
        self.assertEqual(r["architecture_summary"]["shared_architecture_count"],0)
        self.assertEqual(r["slice_comparisons"],[])

    def test_missing_symbol_table_is_allowed_as_empty_evidence(self):
        obj=report([])
        obj["slices"][0]["macho"]["summary"]["has_symbol_table"]=False
        t=wrap(obj,"t"); d=wrap(obj,"d")
        r=compare(t,d)["slice_comparisons"][0]
        self.assertFalse(r["symbol_table_present"]["target"])
        self.assertEqual(r["summary"]["shared_symbol_name_count"],0)

    def test_debug_symbols_are_counted(self):
        t=wrap(report([sym("_debug",0xe0)]),"t")
        d=wrap(report([]),"d")
        r=compare(t,d)["slice_comparisons"][0]
        self.assertEqual(r["summary"]["target_debug_symbol_records"],1)

    def test_rejects_wrong_tool(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp,"bad.json"); p.write_text(json.dumps({"tool":"wrong"}))
            with self.assertRaises(SymbolDiffError): load_report(p)

    def test_rejects_missing_symbol_list(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp,"bad.json")
            p.write_text(json.dumps({"tool":"Phoenix Mach-O Analyzer","slices":[
              {"architecture":{"cpu_type":1,"cpu_subtype":0},"macho":{}}]}))
            with self.assertRaises(SymbolDiffError): load_report(p)

if __name__=="__main__":
    unittest.main()
