#!/usr/bin/env python3
"""Unit tests for pivscan.

  python3 -m unittest test_pivscan

Fixtures are generated at run time by tests/make_fixtures.py -- see that file
for why nothing credential-shaped is committed.

One test here (test_known_gap_*) asserts a FALSE NEGATIVE rather than correct
behaviour. That is deliberate: the gap is real, it is documented in the README,
and pinning it means the day someone fixes it the test fails and says so.
"""

import os
import shutil
import tempfile
import unittest

import pivscan
from tests import make_fixtures


class FixtureCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix="pivscan-test-")
        make_fixtures.write(cls.dir)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir, ignore_errors=True)

    def fx(self, name):
        return os.path.join(self.dir, name)


class TestStringExtraction(FixtureCase):
    def test_ascii_strings_found(self):
        data = pivscan.read_file(self.fx("text.piv"))
        texts = [t for _, enc, t in pivscan.extract_strings(data) if enc == "ascii"]
        self.assertTrue(any("HostName=" in t for t in texts))

    def test_utf16_strings_found(self):
        # The whole reason a Windows config file looks "empty" to naive tools.
        data = pivscan.read_file(self.fx("binary.piv"))
        utf16 = [t for _, enc, t in pivscan.extract_strings(data) if enc == "utf-16le"]
        self.assertTrue(utf16, "no UTF-16LE strings recovered from the binary fixture")
        self.assertTrue(any("HostName=" in t for t in utf16))

    def test_offsets_are_sorted(self):
        data = pivscan.read_file(self.fx("text.piv"))
        offs = [o for o, _, _ in pivscan.extract_strings(data)]
        self.assertEqual(offs, sorted(offs))

    def test_min_len_respected(self):
        data = b"ab\x00\x00abcdefghij\x00"
        short = pivscan.extract_strings(data, 4)
        self.assertTrue(all(len(t) >= 4 for _, _, t in short))


class TestKeyValue(FixtureCase):
    def test_pairs_extracted(self):
        data = pivscan.read_file(self.fx("text.piv"))
        kv = pivscan.extract_kv(pivscan.extract_strings(data))
        keys = {p["key"] for p in kv}
        for expected in ("HostName", "Port", "SessionType", "DebugTrace"):
            self.assertIn(expected, keys)

    def test_colon_separator(self):
        kv = pivscan.extract_kv([(0, "ascii", "HostName: server01")])
        self.assertEqual(kv[0]["value"], "server01")


class TestCamelNormalisation(unittest.TestCase):
    def test_camel_case_split(self):
        self.assertEqual(
            pivscan.normalise_for_match("RememberUsernameAndPassword=1"),
            "Remember Username And Password=1",
        )

    def test_acronym_boundary(self):
        self.assertEqual(pivscan.normalise_for_match("ActivateURIFlag"),
                         "Activate URI Flag")

    def test_underscores_become_spaces(self):
        self.assertIn("prompt for security",
                      pivscan.normalise_for_match("prompt_for_security").lower())

    def test_camel_key_matches_a_rule(self):
        # Without normalisation, \b(password)\b never matches
        # RememberUsernameAndPassword and the file reads as clean.
        rule = next(r for r, _ in pivscan.COMPILED if r["id"] == "PIV-CRED-002")
        rx = next(x for r, x in pivscan.COMPILED if r["id"] == "PIV-CRED-002")
        raw = "RememberUsernameAndPassword=1"
        self.assertTrue(rx.search(pivscan.normalise_for_match(raw)),
                        "%s misses the CamelCase form" % rule["id"])


class TestRules(FixtureCase):
    def setUp(self):
        self.rep = pivscan.scan(self.fx("text.piv"))
        self.ids = {f["id"] for f in self.rep["findings"]}

    def test_stored_credential_detected(self):
        self.assertIn("PIV-CRED-001", self.ids)

    def test_credential_persistence_detected(self):
        self.assertIn("PIV-CRED-002", self.ids)

    def test_prompt_for_security_detected(self):
        self.assertIn("PIV-CRED-003", self.ids)

    def test_lockdown_detected(self):
        self.assertIn("PIV-AUTH-004", self.ids)

    def test_telnet_detected(self):
        self.assertIn("PIV-NET-005", self.ids)

    def test_unc_path_detected(self):
        self.assertIn("PIV-PATH-008", self.ids)

    def test_xfer_in_detected(self):
        self.assertIn("PIV-PARAM-009", self.ids)

    def test_debug_detected(self):
        self.assertIn("PIV-DEBUG-013", self.ids)

    def test_connection_string_detected(self):
        self.assertIn("PIV-DB-014", self.ids)

    def test_every_finding_carries_guidance(self):
        # A finding with no verification step is a finding the tester cannot
        # act on, and the recommendation is what goes in the client report.
        for f in self.rep["findings"]:
            self.assertTrue(f["verify"], "%s has no verify text" % f["id"])
            self.assertTrue(f["recommendation"], "%s has no recommendation" % f["id"])
            self.assertTrue(f["refs"], "%s has no references" % f["id"])

    def test_findings_sorted_by_severity(self):
        order = [pivscan.SEV_ORDER[f["severity"]] for f in self.rep["findings"]]
        self.assertEqual(order, sorted(order))

    def test_evidence_is_capped(self):
        for f in self.rep["findings"]:
            self.assertLessEqual(len(f["evidence"]), 12)

    def test_clean_file_produces_no_findings(self):
        rep = pivscan.scan(self.fx("empty.piv"))
        self.assertEqual(rep["findings"], [])
        self.assertEqual(rep["credential_candidates"], [])

    def test_all_rule_ids_unique(self):
        ids = [r["id"] for r in pivscan.RULES]
        self.assertEqual(len(ids), len(set(ids)))

    def test_all_rule_severities_are_known(self):
        for r in pivscan.RULES:
            self.assertIn(r["severity"], pivscan.SEV_ORDER)


class TestSeverityContext(FixtureCase):
    def test_internal_downgrades_marked_rules(self):
        rep = pivscan.scan(self.fx("text.piv"), context="internal")
        cred = next(f for f in rep["findings"] if f["id"] == "PIV-CRED-001")
        self.assertEqual(cred["base_severity"], "CRITICAL")
        self.assertEqual(cred["severity"], "HIGH")
        self.assertTrue(cred["adjusted"])

    def test_raw_context_leaves_severity_alone(self):
        rep = pivscan.scan(self.fx("text.piv"), context="raw")
        cred = next(f for f in rep["findings"] if f["id"] == "PIV-CRED-001")
        self.assertEqual(cred["severity"], "CRITICAL")
        self.assertFalse(cred["adjusted"])

    def test_rules_marked_do_not_downgrade_stay_put(self):
        # PIV-PATH-008 is internal_adjust: 0 on purpose -- NTLM relay is an
        # internal attack, so an internal position makes it worse, not better.
        rep = pivscan.scan(self.fx("text.piv"), context="internal")
        path = next(f for f in rep["findings"] if f["id"] == "PIV-PATH-008")
        self.assertEqual(path["severity"], "HIGH")
        self.assertFalse(path["adjusted"])

    def test_adjustment_clamps_at_both_ends(self):
        self.assertEqual(pivscan.adjust_severity("CRITICAL", 5), "CRITICAL")
        self.assertEqual(pivscan.adjust_severity("INFO", -5), "INFO")
        self.assertEqual(pivscan.adjust_severity("CRITICAL", -1), "HIGH")


class TestCredentialAssessment(FixtureCase):
    def setUp(self):
        self.rep = pivscan.scan(self.fx("text.piv"))
        self.by_key = {c["key"]: c for c in self.rep["credential_candidates"]}

    def test_plaintext_called_plaintext(self):
        self.assertTrue(
            self.by_key["ProivPassword"]["assessment"].startswith("STORED IN PLAINTEXT"))

    def test_unix_password_also_flagged(self):
        self.assertIn("UnixPassword", self.by_key)

    def test_boolean_not_treated_as_secret(self):
        a = self.by_key["RememberUsernameAndPassword"]["assessment"]
        self.assertTrue(a.startswith("boolean flag"))

    def test_plaintext_does_not_get_brute_force_noise(self):
        # Printing 8 xor candidates for a value you can already read is the
        # fastest way to make the report look unreliable.
        rendered = pivscan.render(self.rep)
        self.assertIn("STORED IN PLAINTEXT", rendered)
        block = rendered.split("CREDENTIAL-SHAPED")[1]
        self.assertNotIn("xor:0x", block.split("ProivPassword")[1][:400])

    def test_md5_shape_recognised(self):
        kv = [(0, "ascii", "Password=" + "a" * 32)]
        rep_secrets = pivscan.extract_kv(kv)
        self.assertEqual(len(rep_secrets), 1)
        self.assertTrue(pivscan.SECRET_KEY_RE.search(rep_secrets[0]["key"]))


class TestReversals(unittest.TestCase):
    def test_base64_recovered(self):
        self.assertEqual(pivscan.try_base64("cGFzc3dvcmQxMjM0"), "password1234")

    def test_base64_rejects_binary_result(self):
        self.assertIsNone(pivscan.try_base64("//////////8="))

    def test_base64_rejects_wrong_padding(self):
        self.assertIsNone(pivscan.try_base64("abc"))

    def test_hex_recovered(self):
        self.assertEqual(pivscan.try_hex("70617373776f7264"), "password")

    def test_single_byte_xor_recovers_a_low_key(self):
        secret = "Operator"
        blob = bytes(ord(c) ^ 0x01 for c in secret)
        hits = pivscan.try_single_byte_xor(blob)
        self.assertIn(secret, [plain for _, plain in hits])

    def test_additive_shift_recovers_plaintext(self):
        secret = "Operator"
        blob = bytes((ord(c) - 3) & 0xFF for c in secret)
        hits = pivscan.try_rot_add(blob)
        self.assertIn(secret, [plain for _, plain in hits])

    def test_candidates_are_deduped_and_capped(self):
        out = pivscan.analyse_secret_value("cGFzc3dvcmQxMjM0")
        self.assertLessEqual(len(out), 8)
        self.assertEqual(len({p for _, p in out}), len(out))


class TestKnownGaps(FixtureCase):
    """Pinned false negatives. These document real limits of a string-based
    scanner; see the README's Limits section."""

    def test_known_gap_binary_obfuscated_secret_is_missed(self):
        # binary.piv holds a single-byte-XOR password right after the ASCII
        # key name "ProivPassword=". extract_kv only sees printable runs, so
        # the key is recovered with an EMPTY value and the pair is dropped
        # before analyse_secret_value ever runs. The obfuscated secret -- the
        # exact thing this tool exists to catch -- is invisible in the binary
        # format. Use 'carve' + the diff workflow for binary PIVs.
        rep = pivscan.scan(self.fx("binary.piv"))
        keys = {p["key"] for p in rep["key_value_pairs"]}
        self.assertIn("ProivPassword", keys, "the key name should still be seen")
        self.assertEqual(
            rep["credential_candidates"], [],
            "if this now finds the XOR'd secret, the gap is fixed -- "
            "delete this test and update the README's Limits section")

    def test_known_gap_xor_cap_can_hide_the_right_key(self):
        # try_single_byte_xor walks keys 1..255 in order and returns hits[:5].
        # Any key that is printable-looking produces a "hit", so for a high
        # key the five lowest keys fill the list and the correct plaintext is
        # never shown. The key IS found by the search -- it is the cap, applied
        # before ranking, that discards it.
        secret = "Winter2024"
        blob = bytes(ord(c) ^ 0x5A for c in secret)
        shown = [plain for _, plain in pivscan.try_single_byte_xor(blob)]
        self.assertNotIn(secret, shown,
                         "if the right key now surfaces, the cap was fixed -- "
                         "delete this test and update the README's Limits section")

        # Proof that the search itself works: unbounded, 0x5A is in there.
        every = [(k, bytes(c ^ k for c in blob)) for k in range(1, 256)]
        self.assertIn(secret, [v.decode("latin-1") for _, v in every])

    def test_rule_keywords_still_fire_on_the_binary(self):
        # The gap is in value analysis, not rule matching: the settings are
        # still reported, so the file does not read as clean.
        rep = pivscan.scan(self.fx("binary.piv"))
        ids = {f["id"] for f in rep["findings"]}
        self.assertIn("PIV-CRED-001", ids)
        self.assertIn("PIV-AUTH-004", ids)


class TestFormatCharacterisation(FixtureCase):
    def test_text_piv_identified_as_text(self):
        self.assertIn("text", pivscan.scan(self.fx("text.piv"))["format_guess"])

    def test_binary_piv_identified_as_mixed(self):
        self.assertIn("mixed", pivscan.scan(self.fx("binary.piv"))["format_guess"])

    def test_opaque_piv_identified_as_opaque(self):
        self.assertIn("opaque", pivscan.scan(self.fx("empty.piv"))["format_guess"])

    def test_no_integrity_hint_in_fixtures(self):
        # None of the fixtures carries a signature field, which is the point:
        # the report must say so rather than staying silent.
        self.assertFalse(pivscan.scan(self.fx("text.piv"))["integrity_field_hint"])

    def test_integrity_hint_detected_when_present(self):
        p = self.fx("signed.piv")
        with open(p, "wb") as fh:
            fh.write(b"[Session]\r\nHostName=a\r\nSignature=deadbeef\r\n")
        self.assertTrue(pivscan.scan(p)["integrity_field_hint"])


class TestEntropy(unittest.TestCase):
    def test_empty_input(self):
        self.assertEqual(pivscan.shannon_entropy(b""), 0.0)

    def test_uniform_input_is_zero(self):
        self.assertEqual(pivscan.shannon_entropy(b"\x00" * 100), 0.0)

    def test_random_input_is_high(self):
        self.assertGreater(pivscan.shannon_entropy(bytes(range(256))), 7.9)

    def test_entropy_map_keeps_a_usable_tail(self):
        # The cutoff is 32 bytes, not "a full window": a 44-byte tail is still
        # measured, a 20-byte one is not.
        self.assertEqual(len(pivscan.entropy_map(b"\x00" * 300, window=256)), 2)
        self.assertEqual(len(pivscan.entropy_map(b"\x00" * 276, window=256)), 1)


class TestDiff(FixtureCase):
    def test_single_byte_change_is_reported_as_one_run(self):
        out = pivscan.diff(self.fx("before.piv"), self.fx("after.piv"))
        self.assertIn("Differing byte positions", out)
        self.assertIn("(1 byte)", out)

    def test_interpretation_guide_present(self):
        out = pivscan.diff(self.fx("before.piv"), self.fx("after.piv"))
        self.assertIn("XOR/substitution", out)

    def test_identical_files_report_no_changes(self):
        out = pivscan.diff(self.fx("text.piv"), self.fx("text.piv"))
        self.assertIn("compared): 0", out)
        self.assertNotIn("Changed runs", out)

    def test_length_difference_is_called_out(self):
        out = pivscan.diff(self.fx("empty.piv"), self.fx("text.piv"))
        self.assertIn("Size differs by", out)

    def test_string_level_diff(self):
        out = pivscan.diff(self.fx("empty.piv"), self.fx("text.piv"))
        self.assertIn("Strings only in B", out)


class TestCarve(FixtureCase):
    def test_pem_block_carved(self):
        p = self.fx("withpem.piv")
        with open(p, "wb") as fh:
            fh.write(b"[Session]\r\n-----BEGIN CERTIFICATE-----\r\nQUJD\r\n"
                     b"-----END CERTIFICATE-----\r\n")
        out = tempfile.mkdtemp(prefix="pivscan-carve-")
        try:
            msg = pivscan.carve(p, out)
            self.assertIn("Carved", msg)
            self.assertTrue(any(f.endswith(".pem") for f in os.listdir(out)))
        finally:
            shutil.rmtree(out, ignore_errors=True)

    def test_nothing_to_carve(self):
        out = tempfile.mkdtemp(prefix="pivscan-carve-")
        try:
            self.assertEqual(pivscan.carve(self.fx("empty.piv"), out),
                             "No carvable regions found.")
        finally:
            shutil.rmtree(out, ignore_errors=True)

    def test_carve_does_not_modify_the_input(self):
        before = pivscan.read_file(self.fx("text.piv"))
        out = tempfile.mkdtemp(prefix="pivscan-carve-")
        try:
            pivscan.carve(self.fx("text.piv"), out)
        finally:
            shutil.rmtree(out, ignore_errors=True)
        self.assertEqual(before, pivscan.read_file(self.fx("text.piv")))


class TestBlobSignatures(FixtureCase):
    def test_pem_signature_found(self):
        p = self.fx("blob.piv")
        with open(p, "wb") as fh:
            fh.write(b"xx-----BEGIN PRIVATE KEY-----yy")
        rep = pivscan.scan(p)
        self.assertTrue(any(b["type"] == "PEM block" for b in rep["embedded_blobs"]))

    def test_key_material_rule_fires(self):
        p = self.fx("blob2.piv")
        with open(p, "wb") as fh:
            fh.write(b"[Session]\r\n-----BEGIN RSA PRIVATE KEY-----\r\n")
        ids = {f["id"] for f in pivscan.scan(p)["findings"]}
        self.assertIn("PIV-CRYPT-011", ids)


class TestRender(FixtureCase):
    def test_render_is_plain_text_and_complete(self):
        out = pivscan.render(pivscan.scan(self.fx("text.piv")))
        for section in ("NEXT STEPS", "CAVEATS", "CREDENTIAL-SHAPED",
                        "Integrity field", "RECOMMENDATION:"):
            self.assertIn(section, out)

    def test_render_handles_no_findings(self):
        out = pivscan.render(pivscan.scan(self.fx("empty.piv")))
        self.assertIn("none matched", out)

    def test_adjusted_findings_show_their_original_severity(self):
        out = pivscan.render(pivscan.scan(self.fx("text.piv"), context="internal"))
        self.assertIn("adjusted from CRITICAL", out)

    def test_wrap_respects_width(self):
        text = " ".join(["word"] * 60)
        for line in pivscan.wrap(text, 40, "  ").split("\n"):
            self.assertLessEqual(len(line.strip()), 44)

    def test_report_is_json_serialisable(self):
        import json
        json.dumps(pivscan.scan(self.fx("text.piv")))


class TestReadOnly(FixtureCase):
    def test_scan_does_not_modify_the_input(self):
        before = pivscan.read_file(self.fx("text.piv"))
        mtime = os.path.getmtime(self.fx("text.piv"))
        pivscan.scan(self.fx("text.piv"))
        self.assertEqual(before, pivscan.read_file(self.fx("text.piv")))
        self.assertEqual(mtime, os.path.getmtime(self.fx("text.piv")))


if __name__ == "__main__":
    unittest.main(verbosity=2)
