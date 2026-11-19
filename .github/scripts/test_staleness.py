import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "generate_index", ROOT / ".github/scripts/generate_index.py")
index = importlib.util.module_from_spec(spec)
spec.loader.exec_module(index)


def image(name, current, latest):
    return {
        "image": name + ":old",
        "image_name": name,
        "current_tag": "old",
        "latest_tag": "new",
        "latest_image": name + ":new",
        "status": "NEEDS_UPDATE",
        "findings_current": current,
        "findings_latest": latest,
    }


class CardTests(unittest.TestCase):
    def card(self, images, affected=66):
        return index.render_card("scan-20261118-1", {
            "affected": affected, "targets": 33, "vexed": 0, "worst": "HIGH",
            "stale_needs_update": len(images),
            # Old summaries may contain bogus deltas from failed rescans.
            "stale_affected_current": 58, "stale_affected_latest": 8,
            "stale_images": index._stale_image_details(images),
        })

    def test_complete_comparison_includes_zero_and_instance_totals(self):
        card = self.card([
            image("a", {"HIGH": 10}, {"HIGH": 4}),
            image("b", {"HIGH": 10}, {}),
        ])
        self.assertIn("20 \u2192 4 affected CVE instances (16 fewer)", card)
        self.assertIn("Fleet with these updates: 66 \u2192 50", card)
        self.assertNotIn("Partial comparison", card)
        self.assertIn("10 &#8594; 0 affected (10 fewer)", card)

    def test_partial_comparison_keeps_unavailable_images_unchanged(self):
        card = self.card([
            image("a", {"HIGH": 10}, {}),
            image("b", {"HIGH": 20}, None),
            image("c", None, {}),
        ])
        self.assertIn("66 \u2192 56", card)
        self.assertIn("Partial comparison (1/3 updated images compared)", card)
        self.assertIn("CVE comparison unavailable", card)

    def test_missing_counts_do_not_claim_reduction(self):
        card = self.card([image("a", {"HIGH": 50}, None)])
        self.assertIn("Updated-image CVE counts unavailable", card)
        self.assertNotIn("fewer", card)
        self.assertNotIn("fixed by updating", card)

    def test_increase_and_no_change_are_distinct(self):
        card = self.card([image("a", {}, {"HIGH": 2})])
        self.assertIn("(2 more)", card)
        self.assertIn("66 \u2192 68", card)
        card = self.card([image("a", {}, {})])
        self.assertIn("no net change", card)
        self.assertIn("66 \u2192 66", card)


class RescanTests(unittest.TestCase):
    def run_rescan(self, payload):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            entries = [image("a", None, None), image("b", None, None)]
            (path / "tags.json").write_text(json.dumps(entries))
            finding = {"status": "linked", "severity": "HIGH", "fixed_version": "2"}
            main = {"results": [
                {"target": "a:old", "findings": [finding]},
                {"target": "b:old", "findings": [finding, finding]},
            ]}
            (path / "scan.json").write_text(json.dumps(main))
            (path / "fleet.txt").write_text("a:old roots=/bin/a\nb:old\n")
            (path / "payload.json").write_text(payload)
            checker = path / "check-latest-tags"
            checker.write_text('#!/bin/sh\ncat tags.json\n')
            checker.chmod(0o755)
            scanner = path / "vexscan"
            scanner.write_text(
                '#!/bin/sh\nprintf "%s\\n" "$@" > args.txt\n'
                'cp stale-images.txt rescan-input.txt\n'
                'cat payload.json\necho "b: manifest unknown" >&2\nexit 1\n')
            scanner.chmod(0o755)
            script = (ROOT / "scan.sh").read_text()
            block = script[script.index('if [[ "$staleness_check" == "true" ]]'):]
            setup = (
                'set -euo pipefail\nstaleness_check=true\nimages_source=./fleet.txt\n'
                'use_prime_ingress=false\nscript_dir=.\nsource_vexhub=source-vex\n'
                'vexhub=https://example.test/vex\nprefer_vendor=suse\n'
                'severity_filter=HIGH\nfixed_only=true\noutput_file=scan.json\n')
            env = dict(os.environ, PATH=directory + os.pathsep + os.environ["PATH"])
            result = subprocess.run(
                ["bash", "-c", setup + block], cwd=directory, env=env,
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("retaining successful results", result.stderr)
            self.assertNotIn("source-vex", (path / "args.txt").read_text())
            self.assertEqual((path / "rescan-input.txt").read_text(),
                             "a:new roots=/bin/a\nb:new\n")
            return json.loads((path / "scan.json").read_text()), result.stderr

    def test_partial_nonzero_batch_retains_success_and_applies_filter(self):
        doc, _ = self.run_rescan(json.dumps({
            "results": [{"target": "a:new", "findings": [
                {"status": "linked", "severity": "HIGH"},  # no published fix
            ]}],
            "failures": [{"target": "b:new", "error": "manifest unknown"}],
        }))
        stale = doc["staleness"]
        self.assertEqual(stale["summary"]["rescanned"], 1)
        self.assertEqual(stale["summary"]["affected_current"], 1)
        self.assertEqual(stale["summary"]["affected_latest"], 0)
        self.assertEqual(stale["images"][0]["findings_latest"], {})
        self.assertIsNone(stale["images"][1]["findings_latest"])
        self.assertEqual(len(doc["results"][1]["findings"]), 2)

    def test_invalid_output_leaves_latest_counts_unknown(self):
        doc, stderr = self.run_rescan("not JSON")
        self.assertIn("latest-tag CVE counts unavailable", stderr)
        self.assertEqual(doc["staleness"]["summary"]["rescanned"], 0)
        self.assertTrue(all(img["findings_latest"] is None
                            for img in doc["staleness"]["images"]))


if __name__ == "__main__":
    unittest.main()
