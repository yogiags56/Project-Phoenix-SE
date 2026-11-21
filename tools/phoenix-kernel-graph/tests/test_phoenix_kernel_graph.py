import unittest
from phoenix_kernel_graph import GraphError, build_graph, render_mermaid

def kext_report():
    return {"tool":"Phoenix Kext Dependency Analyzer","bundles":[
      {"bundle_id":"com.apple.driver.A","path":"A.kext","valid":True,"required":"Root","version":"1"},
      {"bundle_id":"com.apple.driver.B","path":"B.kext","valid":True,"required":"Safe Boot","version":"2"},
      {"bundle_id":None,"path":"Broken.kext","valid":False}],
      "dependencies":[
       {"consumer":"com.apple.driver.A","dependency":"com.apple.driver.B","required_version":"1","resolved":True},
       {"consumer":"com.apple.driver.A","dependency":"com.apple.kernel","required_version":"1","resolved":False}]}
def kc_report():
    return {"tool":"Phoenix Kernel Collection Inspector","entries":[
      {"identifier":"com.apple.driver.A","file_offset":128,"embedded_macho":{"valid":True,"architecture":{"cpu_type":1}}}]}

class KernelGraphTests(unittest.TestCase):
    def test_dependency_edges_and_unresolved_external_node(self):
        g=build_graph(kext_report(),"abc")
        self.assertEqual(g["summary"]["unresolved_dependency_edge_count"],1)
        self.assertTrue(any(n["type"]=="external-dependency" for n in g["nodes"]))
        self.assertTrue(any(e["status"]=="provider-present" for e in g["edges"]))

    def test_boot_critical_is_only_candidate(self):
        g=build_graph(kext_report(),"abc")
        self.assertEqual(g["summary"]["boot_critical_candidate_count"],1)
        self.assertTrue(g["boot_critical_candidate_node_ids"][0].startswith("kext:"))

    def test_kernel_collection_exact_identifier_correlation(self):
        g=build_graph(kext_report(),"abc",kc_report(),"def")
        self.assertEqual(g["summary"]["kernel_collection_entries_correlated"],1)
        self.assertTrue(any(e["kind"]=="identifier-correlation" for e in g["edges"]))

    def test_symbol_edges_require_explicit_mapping(self):
        g=build_graph(kext_report(),"abc",symbol_map={"providers":[
          {"symbol":"_example","consumer_bundle_id":"com.apple.driver.A",
           "provider_bundle_id":"com.apple.driver.B"}]})
        self.assertEqual(g["summary"]["explicit_symbol_mapping_edge_count"],2)

    def test_duplicate_bundle_ids_preserve_ambiguous_providers(self):
        r=kext_report()
        r["bundles"].append({"bundle_id":"com.apple.driver.B","path":"B2.kext","valid":True})
        g=build_graph(r,"abc")
        provider_edges=[e for e in g["edges"] if e["kind"]=="kext-library-dependency" and e["status"]=="provider-present"]
        self.assertEqual(len(provider_edges),2)

    def test_mermaid_export(self):
        g=build_graph(kext_report(),"abc")
        self.assertIn("flowchart LR",render_mermaid(g))

if __name__=="__main__":
    unittest.main()
