"""Run with: python3 -m unittest discover -s tests -p test_mutation_fuzzer.py."""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mutation_fuzzer import BundleMutationFuzzer, get_mutations_for_bundle


class HarnessChecks(unittest.TestCase):
    def test_baseline_trust_root_and_failure_classification(self):
        fuzzer = BundleMutationFuzzer(verifier_command=[sys.executable])
        bundle, artifact, root = map(Path, ["bundle.json", "artifact", "root.json"])
        command = fuzzer._build_verify_command(bundle, artifact, root)
        self.assertEqual(command[command.index("--trusted-root") + 1], str(root))
        for code, output, expected in [
            (0, "Verification: SUCCESS", True),
            (1, "Verification error: invalid signature", False),
            (1, "Error parsing bundle: invalid JSON", False),
            (1, "could not load trust root", None),
            (1, "", None),
            (2, "usage error", None),
            (101, "panicked at", None),
            (-11, "", None),
        ]:
            with self.subTest(code=code, output=output), patch("mutation_fuzzer.subprocess.run", return_value=subprocess.CompletedProcess(command, code, output, "")):
                if expected is None:
                    with self.assertRaises(RuntimeError):
                        fuzzer.verify_bundle(bundle, artifact, root)
                else:
                    self.assertEqual(fuzzer.verify_bundle(bundle, artifact, root)[0], expected)
        with patch.object(fuzzer, "verify_bundle", return_value=(False, "invalid signature")):
            with self.assertRaisesRegex(RuntimeError, "baseline"):
                fuzzer.fuzz_bundle(bundle, artifact, root)
        with patch("mutation_fuzzer.subprocess.run", side_effect=subprocess.TimeoutExpired(command, 30)):
            with self.assertRaisesRegex(RuntimeError, "timed out"):
                fuzzer.verify_bundle(bundle, artifact, root)

    def test_rekor_v2_mutates_authenticated_checkpoint_not_unsigned_hints(self):
        bundle = {"verificationMaterial": {"tlogEntries": [{"kindVersion": {"kind": "hashedrekord", "version": "0.0.2"}}]}}
        names = {mutation.name for mutation in get_mutations_for_bundle(bundle)}
        self.assertIn("checkpoint_wrong_root_hash", names)
        self.assertNotIn("inclusion_proof_wrong_root_hash", names)
        self.assertNotIn("integrated_time_future", names)
        bundle["verificationMaterial"]["tlogEntries"][0]["kindVersion"]["version"] = "0.0.1"
        names = {mutation.name for mutation in get_mutations_for_bundle(bundle)}
        self.assertIn("inclusion_proof_wrong_root_hash", names)
        self.assertIn("integrated_time_future", names)

    def test_always_rejecting_executable_cannot_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "reject.py"
            script.write_text("print('Verification error: fake rejection')\nraise SystemExit(1)\n")
            fuzzer = BundleMutationFuzzer(verifier_command=[sys.executable, str(script)])
            with self.assertRaisesRegex(RuntimeError, "baseline"):
                fuzzer.fuzz_bundle(Path("unused-bundle"), Path("unused-artifact"))


if __name__ == "__main__":
    unittest.main()
