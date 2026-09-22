import json
import unittest
from datetime import date
from pathlib import Path

from app.parser import LogParseError, parse_log_file, parse_timestamp

SAMPLES = Path(__file__).resolve().parents[2] / "data" / "sample_logs"
D = date(2026, 9, 14)


class TimestampTests(unittest.TestCase):
    def test_time_only_uses_default_date(self):
        dt, assumed = parse_timestamp("12:01", D)
        self.assertEqual(dt.isoformat(), "2026-09-14T12:01:00")
        self.assertTrue(assumed)

    def test_iso_and_space_separated(self):
        self.assertEqual(parse_timestamp("2026-09-14T08:00:05", D)[0].second, 5)
        self.assertEqual(parse_timestamp("2026-09-14 08:00:05", D)[0].hour, 8)

    def test_timezone_converted_to_utc(self):
        dt, _ = parse_timestamp("2026-09-14T10:00:00+02:00", D)
        self.assertEqual(dt.hour, 8)

    def test_epoch_seconds(self):
        dt, _ = parse_timestamp("1789000000", D)
        self.assertEqual(dt.year, 2026)

    def test_garbage_returns_none(self):
        self.assertIsNone(parse_timestamp("not a time", D)[0])
        self.assertIsNone(parse_timestamp("25:99", D)[0])


class CsvTests(unittest.TestCase):
    def test_headerless_brief_format(self):
        data = (SAMPLES / "spec_example_no_header.csv").read_bytes()
        r = parse_log_file(data, "x.csv", default_date=D)
        self.assertEqual(len(r.events), 5)
        self.assertEqual(r.events[0]["username"], "admin")
        self.assertEqual(r.events[0]["status"], "FAILED")
        self.assertEqual(r.events[0]["timestamp"], "2026-09-14T12:01:00")
        self.assertTrue(any("No header row" in w for w in r.warnings))

    def test_column_aliases_and_status_normalization(self):
        csv_text = "time,user,src_ip,dst_ip,type,result,host\n2026-09-14 09:00:00,bob,1.2.3.4,5.6.7.8,login,fail,PC1\n"
        r = parse_log_file(csv_text.encode(), "a.csv")
        e = r.events[0]
        self.assertEqual((e["username"], e["source_ip"], e["destination_ip"]), ("bob", "1.2.3.4", "5.6.7.8"))
        self.assertEqual((e["event_type"], e["status"], e["hostname"]), ("LOGIN", "FAILED", "PC1"))

    def test_bad_timestamp_row_skipped_with_warning(self):
        csv_text = "timestamp,user\n2026-09-14 09:00:00,a\nbanana,b\n2026-09-14 09:05:00,c\n"
        r = parse_log_file(csv_text.encode(), "a.csv")
        self.assertEqual((len(r.events), r.skipped_rows, r.total_rows), (2, 1, 3))
        self.assertTrue(any("Row 2" in w for w in r.warnings))

    def test_events_sorted_and_ids_keep_original_row(self):
        csv_text = "timestamp,user\n2026-09-14 10:00:00,late\n2026-09-14 09:00:00,early\n"
        r = parse_log_file(csv_text.encode(), "a.csv")
        self.assertEqual([e["username"] for e in r.events], ["early", "late"])
        self.assertEqual(r.events[0]["event_id"], "EVT-000002")
        self.assertEqual(r.events[0]["raw"]["user"], "early")

    def test_missing_timestamp_column_is_error(self):
        with self.assertRaises(LogParseError):
            parse_log_file(b"user,action\nbob,login\n", "a.csv")

    def test_empty_and_unsupported(self):
        with self.assertRaises(LogParseError):
            parse_log_file(b"   \n", "a.csv")
        with self.assertRaises(LogParseError):
            parse_log_file(b"whatever", "a.exe")


class JsonTests(unittest.TestCase):
    def test_list_object_and_wrapped(self):
        rec = {"timestamp": "2026-09-14T09:00:00", "user": "bob", "destination_port": "443"}
        for payload in ([rec], {"events": [rec]}):
            r = parse_log_file(json.dumps(payload).encode(), "a.json")
            self.assertEqual(r.events[0]["username"], "bob")
            self.assertEqual(r.events[0]["destination_port"], 443)

    def test_jsonl_skips_bad_lines(self):
        text = '{"timestamp":"2026-09-14T09:00:00","user":"a"}\nnot json\n{"timestamp":"2026-09-14T09:01:00","user":"b"}\n'
        r = parse_log_file(text.encode(), "a.jsonl")
        self.assertEqual((len(r.events), r.skipped_rows), (2, 1))

    def test_invalid_json_is_error(self):
        with self.assertRaises(LogParseError):
            parse_log_file(b"{oops", "a.json")


class SampleDatasetTests(unittest.TestCase):
    def test_every_sample_file_parses_cleanly(self):
        names = [p for p in SAMPLES.iterdir()
                 if p.suffix in (".csv", ".json") and p.name != "manifest.json"]
        self.assertGreaterEqual(len(names), 7)
        for path in names:
            with self.subTest(file=path.name):
                r = parse_log_file(path.read_bytes(), path.name, default_date=D)
                self.assertEqual(r.skipped_rows, 0)
                self.assertGreater(len(r.events), 0)

    def test_csv_and_json_combined_datasets_match(self):
        a = parse_log_file((SAMPLES / "security_logs.csv").read_bytes(), "a.csv")
        b = parse_log_file((SAMPLES / "security_logs.json").read_bytes(), "a.json")
        self.assertEqual(len(a.events), len(b.events))

    def test_attack_chain_contains_25_admin_failures(self):
        r = parse_log_file((SAMPLES / "attack_chain.csv").read_bytes(), "a.csv")
        fails = [e for e in r.events if e["status"] == "FAILED"
                 and e["source_ip"] == "192.168.1.50" and e["username"] == "admin"]
        self.assertEqual(len(fails), 25)


if __name__ == "__main__":
    unittest.main()
