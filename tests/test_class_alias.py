"""Ten lop theo docs/taxonomy.yml (INSECURE_AUTHENTICATION) duoc quy ve ten noi bo truoc khi so sanh."""
import csv
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("sast_alias", ROOT / "03_run_sast.py")
sast = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sast)


class ClassAliasTests(unittest.TestCase):
    def test_taxonomy_name_maps_to_internal_class(self):
        self.assertEqual(sast.canonical_class("INSECURE_AUTHENTICATION"), "AUTHENTICATION_WEAKNESS")
        self.assertEqual(sast.canonical_class("AUTHENTICATION_WEAKNESS"), "AUTHENTICATION_WEAKNESS")
        self.assertEqual(sast.canonical_class(" XSS "), "XSS")
        self.assertEqual(sast.canonical_class("SAFE"), "SAFE")          # nhan la khong bi doi thanh lop hop le
        self.assertIsNone(sast.canonical_class(None))

    def test_rule_metadata_with_new_name_counts_as_auth(self):
        self.assertEqual(sast.finding_classes(["287"], {"vuln_class": "INSECURE_AUTHENTICATION"}),
                         ["AUTHENTICATION_WEAKNESS"])
        self.assertEqual(sast.finding_classes(["916"], {"vuln_class": "INSECURE_AUTHENTICATION"}),
                         ["AUTHENTICATION_WEAKNESS"])
        self.assertEqual(sast.finding_classes(["89"], {"vuln_class": "SQL_INJECTION"}), ["SQL_INJECTION"])

    def test_dataset_label_with_new_name_is_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "train.csv"
            with p.open("w", newline="", encoding="utf-8") as fh:
                w = csv.DictWriter(fh, fieldnames=["id", "code", "cls_gt", "programming_language"])
                w.writeheader()
                w.writerow({"id": "1", "code": "x = 1", "cls_gt": "INSECURE_AUTHENTICATION", "programming_language": "python"})
                w.writerow({"id": "2", "code": "y = 2", "cls_gt": "XSS", "programming_language": "Python"})
            rows = sast.read_test_rows(p, ("Python",))
        self.assertEqual([r["cls_gt"] for r in rows], ["AUTHENTICATION_WEAKNESS", "XSS"])
        self.assertEqual(rows[0]["cls_gt_original"], "INSECURE_AUTHENTICATION")

    def test_unknown_label_still_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "train.csv"
            p.write_text("id,code,cls_gt,programming_language\n1,x,SAFE,Python\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                sast.read_test_rows(p, ("Python",))


if __name__ == "__main__":
    unittest.main()
