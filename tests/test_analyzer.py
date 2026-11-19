from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
import pandas as pd
from fg_log_analyzer import FGLogAnalyzer


class TestAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = FGLogAnalyzer()
        self.sample = Path(__file__).resolve().parents[1] / "data" / "sample_log.csv"
        self.analyzer.load_csv(self.sample)

    def test_statistics_and_detect(self):
        stats = self.analyzer.statistics()
        self.assertGreater(stats["total"], 30)
        self.assertGreater(stats["failed"], 0)
        detections = self.analyzer.fg_detect_bruteforce()
        self.assertIn("203.0.113.42", [item.source_ip for item in detections])

    def test_filter_and_export(self):
        filtered = self.analyzer.filtered("203.0.113.42", "FAILED")
        self.assertTrue(all(filtered["status"].eq("FAILED")))
        self.assertTrue(all(filtered["source_ip"].eq("203.0.113.42")))
        with TemporaryDirectory() as location:
            target = Path(location) / "out.csv"
            count = self.analyzer.export_csv(target, "203.0.113.42", "FAILED")
            self.assertEqual(count, len(pd.read_csv(target)))

    def test_invalid_columns_do_not_replace_loaded_data(self):
        before = len(self.analyzer.data)
        with TemporaryDirectory() as location:
            target = Path(location) / "bad.csv"
            target.write_text("foo,bar\n1,2\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                self.analyzer.load_csv(target)
        self.assertEqual(before, len(self.analyzer.data))


if __name__ == "__main__":
    unittest.main()
