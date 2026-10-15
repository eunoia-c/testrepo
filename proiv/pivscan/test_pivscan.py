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


class TestTunnelArchitecture(FixtureCase):
    """The SSH-local-forward deployment: the PIV carries SSH credentials and the
    application protocol then runs over loopback into the forwarder."""

    def setUp(self):
        self.rep = pivscan.scan(self.fx("ssh_tunnel.piv"))
        self.ids = {f["id"] for f in self.rep["findings"]}

    def test_ssh_credentials_detected(self):
        self.assertIn("PIV-CRED-018", self.ids)

    def test_missing_transport_encryption_detected(self):
        self.assertIn("PIV-NET-017", self.ids)

    def test_ssh_credentials_outrank_an_application_password(self):
        # SSH credentials are OS access, so the rule must not be scored below
        # the application-credential rule -- and the login page that appears
        # after the tunnel comes up is not a mitigation for it.
        ssh = next(f for f in self.rep["findings"] if f["id"] == "PIV-CRED-018")
        self.assertEqual(ssh["base_severity"], "CRITICAL")
        self.assertFalse(ssh["adjusted"], "SSH credentials must not be downgraded "
                                          "for internal context")

    def test_transport_encryption_is_not_downgraded_by_the_tunnel(self):
        net = next(f for f in self.rep["findings"] if f["id"] == "PIV-NET-017")
        self.assertFalse(net["adjusted"])
        self.assertIn("tunnel", net["impact"].lower())

    def test_verification_asks_the_question_that_sets_severity(self):
        ssh = next(f for f in self.rep["findings"] if f["id"] == "PIV-CRED-018")
        for probe in ("shell", "forward", "shared"):
            self.assertIn(probe, ssh["verify"].lower())

    def test_passphrase_and_key_path_both_surface(self):
        plain = pivscan.render_plaintext(self.fx("ssh_tunnel.piv"))
        self.assertIn("PrivateKeyFile=", plain)
        self.assertIn("Passphrase=", plain)

    def test_socks_recommendation_names_the_server_side_control(self):
        f = next(x for x in self.rep["findings"] if x["id"] == "PIV-NET-019")
        low = f["recommendation"].lower()
        self.assertIn("allowtcpforwarding", low)
        self.assertIn("permitopen", low)
        self.assertIn("-l ", low)

    def test_strict_host_key_checking_off_is_visible(self):
        self.assertIn("StrictHostKeyChecking=0",
                      pivscan.render_plaintext(self.fx("ssh_tunnel.piv")))

    def test_dynamic_socks_forwarding_detected(self):
        self.assertIn("PIV-NET-019", self.ids)

    def test_socks_finding_is_not_downgraded(self):
        # An internal position is what makes a pivot useful, not what blunts it.
        f = next(x for x in self.rep["findings"] if x["id"] == "PIV-NET-019")
        self.assertEqual(f["severity"], "CRITICAL")
        self.assertFalse(f["adjusted"])

    def test_socks_impact_distinguishes_D_from_L(self):
        f = next(x for x in self.rep["findings"] if x["id"] == "PIV-NET-019")
        self.assertIn("-D", f["impact"])
        self.assertIn("-L", f["impact"])
        self.assertIn("unauthenticated", f["impact"].lower())

    def test_socks_rule_matches_the_bare_flag(self):
        rx = next(x for r, x in pivscan.COMPILED if r["id"] == "PIV-NET-019")
        for hit in ("-D 1080", "socks5", "DynamicForward 1080", "ProxyPort=1080"):
            self.assertTrue(rx.search(hit), hit)
        # -D must not match inside ordinary words, or every PIV gets the finding.
        for miss in ("MODE-DEBUG", "x-Dy", "DEBUG", "nothing here"):
            self.assertFalse(rx.search(miss), miss)

    def test_failed_ssh_login_does_not_clear_the_credential_finding(self):
        # "permission denied" has several innocent-looking explanations and none
        # of them mean the exposed credential is harmless.
        f = next(x for x in self.rep["findings"] if x["id"] == "PIV-CRED-018")
        low = f["verify"].lower()
        self.assertIn("permission denied", low)
        self.assertIn("key only", low)
        self.assertIn("unresolved, not disproven", low)

    def test_recommendation_names_the_real_controls(self):
        net = next(f for f in self.rep["findings"] if f["id"] == "PIV-NET-017")
        low = net["recommendation"].lower()
        self.assertIn("secure socket", low)
        self.assertIn("https", low)
        ssh = next(f for f in self.rep["findings"] if f["id"] == "PIV-CRED-018")
        self.assertIn("permitopen", ssh["recommendation"].lower())


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

    def test_single_byte_xor_surfaces_a_high_key(self):
        # Regression: these used to return the first five printable results in
        # key order, so a high key lost to low-numbered garbage and never
        # appeared. Candidates are ranked by plaintext likeness before capping.
        secret = "Winter2024"
        blob = bytes(ord(c) ^ 0x5A for c in secret)
        hits = pivscan.try_single_byte_xor(blob)
        self.assertEqual(hits[0][1], secret, "correct key should rank first")
        self.assertEqual(hits[0][0], 0x5A)

    def test_single_byte_xor_recovers_a_low_key(self):
        secret = "Operator"
        blob = bytes(ord(c) ^ 0x01 for c in secret)
        hits = pivscan.try_single_byte_xor(blob)
        self.assertIn(secret, [plain for _, plain in hits])

    def test_bigram_scoring_separates_words_from_noise(self):
        self.assertGreater(pivscan.plaintext_likeness(b"Winter2024"),
                           pivscan.plaintext_likeness(b"Uklvgp0206"))

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

    def test_rule_keywords_still_fire_on_the_binary(self):
        # The gap is in value analysis, not rule matching: the settings are
        # still reported, so the file does not read as clean.
        rep = pivscan.scan(self.fx("binary.piv"))
        ids = {f["id"] for f in rep["findings"]}
        self.assertIn("PIV-CRED-001", ids)
        self.assertIn("PIV-AUTH-004", ids)


class TestDeobfuscation(FixtureCase):
    """The case that made the scanner report a clean file: UTF-16LE property
    text XOR'd with one byte, behind a plaintext magic."""

    def test_header_skip_finds_the_magic_only(self):
        raw = pivscan.read_file(self.fx("obfuscated.piv"))
        self.assertEqual(raw[:pivscan.header_skip(raw)], b"PRO4VS")

    def test_header_skip_does_not_run_into_the_body(self):
        # XOR'd UTF-16LE is printable too, so "advance while printable" walks
        # past the magic and poisons key recovery.
        raw = pivscan.read_file(self.fx("obfuscated.piv"))
        self.assertLess(pivscan.header_skip(raw), 10)

    def test_header_skip_zero_on_a_text_piv(self):
        raw = pivscan.read_file(self.fx("text.piv"))
        self.assertEqual(pivscan.header_skip(raw), 0)

    def test_single_byte_key_recovered(self):
        raw = pivscan.read_file(self.fx("obfuscated.piv"))
        body = raw[pivscan.header_skip(raw):]
        self.assertEqual(pivscan.recover_xor_key_modal(body, 1), b"\x3b")
        self.assertEqual(pivscan.recover_xor_key_columns(body, 1), b"\x3b")

    def test_multibyte_key_recovered(self):
        # The modal trick alone cannot do this: with an even key length every
        # UTF-16 null lands in one column and the others hold no nulls at all.
        raw = pivscan.read_file(self.fx("obfuscated_multibyte.piv"))
        body = raw[pivscan.header_skip(raw):]
        best = pivscan.deobfuscate_candidates(raw, skip=pivscan.header_skip(raw))[0]
        self.assertEqual(best["transform"], "xor:3b2f")

    def test_best_candidate_is_the_right_transform(self):
        raw = pivscan.read_file(self.fx("obfuscated.piv"))
        cands = pivscan.deobfuscate_candidates(raw, skip=pivscan.header_skip(raw))
        self.assertEqual(cands[0]["transform"], "xor:3b")
        self.assertGreaterEqual(len(cands[0]["keyword_hits"]), 10)

    def test_repeated_keys_are_collapsed(self):
        self.assertEqual(pivscan.smallest_period(b"\x3b\x3b\x3b"), b"\x3b")
        self.assertEqual(pivscan.smallest_period(b"\x3b\x2f\x3b\x2f"), b"\x3b\x2f")
        self.assertEqual(pivscan.smallest_period(b"\x01\x02\x03"), b"\x01\x02\x03")

    def test_scan_auto_decodes_and_says_so(self):
        rep = pivscan.scan(self.fx("obfuscated.piv"))
        self.assertTrue(rep["obfuscation"]["detected"])
        self.assertEqual(rep["obfuscation"]["transform"], "xor:3b")
        self.assertEqual(rep["obfuscation"]["source"], "auto-detected")
        self.assertIn("DEFEATED", pivscan.render(rep))

    def test_rules_fire_after_decoding(self):
        # Before this, the same file produced zero findings.
        ids = {f["id"] for f in pivscan.scan(self.fx("obfuscated.piv"))["findings"]}
        for expected in ("PIV-CRED-001", "PIV-CRED-002", "PIV-AUTH-004",
                         "PIV-NET-005", "PIV-PATH-008", "PIV-DEBUG-013"):
            self.assertIn(expected, ids)

    def test_credential_recovered_from_the_obfuscated_file(self):
        rep = pivscan.scan(self.fx("obfuscated.piv"))
        keys = {c["key"] for c in rep["credential_candidates"]}
        self.assertIn("ProivPassword", keys)
        cred = next(c for c in rep["credential_candidates"]
                    if c["key"] == "ProivPassword")
        self.assertTrue(cred["assessment"].startswith("STORED IN PLAINTEXT"))

    def test_offsets_still_address_the_original_file(self):
        # A byte-wise transform preserves length, so a reported offset must
        # point at the right place in the file on disk -- that is what makes
        # the output usable in a hex editor.
        rep = pivscan.scan(self.fx("obfuscated.piv"))
        raw = pivscan.read_file(self.fx("obfuscated.piv"))
        cred = next(c for c in rep["credential_candidates"]
                    if c["key"] == "ProivPassword")
        decoded = raw[:6] + pivscan.xor_bytes(raw[6:], b"\x3b")
        at_offset = decoded[cred["offset"]:cred["offset"] + 40]
        # The decoded field is UTF-16LE, so the ASCII name is interleaved with
        # nulls -- decode before comparing.
        self.assertTrue(at_offset.decode("utf-16-le", "replace")
                        .startswith("ProivPassword="))

    def test_size_and_entropy_describe_the_file_on_disk(self):
        rep = pivscan.scan(self.fx("obfuscated.piv"))
        self.assertEqual(rep["size"], len(pivscan.read_file(self.fx("obfuscated.piv"))))

    def test_no_false_decode_on_a_plaintext_piv(self):
        # The expensive failure mode: "decoding" a file that was never encoded.
        for name in ("text.piv", "binary.piv", "empty.piv"):
            rep = pivscan.scan(self.fx(name))
            self.assertFalse(rep["obfuscation"]["detected"],
                             "%s was wrongly decoded" % name)

    def test_auto_decode_can_be_turned_off(self):
        rep = pivscan.scan(self.fx("obfuscated.piv"), auto_decode=False)
        self.assertFalse(rep["obfuscation"]["detected"])
        self.assertEqual(rep["findings"], [])     # back to the silent-pass behaviour

    def test_explicit_spec_is_applied(self):
        rep = pivscan.scan(self.fx("obfuscated.piv"), spec="xor:3b")
        self.assertEqual(rep["obfuscation"]["source"], "user-specified")
        self.assertIn("PIV-CRED-001", {f["id"] for f in rep["findings"]})

    def test_spec_parsing(self):
        self.assertEqual(pivscan.parse_spec("xor:3b"), ("xor", b"\x3b"))
        self.assertEqual(pivscan.parse_spec("xor:3b2f"), ("xor", b"\x3b\x2f"))
        self.assertEqual(pivscan.parse_spec("add:05"), ("add", b"\x05"))
        self.assertEqual(pivscan.parse_spec("none"), ("none", b""))
        with self.assertRaises(ValueError):
            pivscan.parse_spec("rot13:5")

    def test_add_transform_round_trips(self):
        plain = b"HostName=server01"
        cipher = pivscan.add_bytes(plain, 0x05)
        self.assertEqual(pivscan.apply_transform(cipher, "add", b"\x05"), plain)

    def test_xor_transform_round_trips(self):
        plain = b"HostName=server01"
        cipher = pivscan.xor_bytes(plain, b"\x3b\x2f")
        self.assertEqual(pivscan.apply_transform(cipher, "xor", b"\x3b\x2f"), plain)

    def test_decode_report_lists_candidates(self):
        out = pivscan.decode_report(self.fx("obfuscated.piv"))
        self.assertIn("xor:3b", out)
        self.assertIn("hostname", out)

    def test_decode_report_writes_the_decoded_file(self):
        out_path = os.path.join(self.dir, "decoded.bin")
        pivscan.decode_report(self.fx("obfuscated.piv"), out=out_path)
        self.assertTrue(os.path.exists(out_path))
        data = pivscan.read_file(out_path)
        self.assertTrue(data.startswith(b"PRO4VS"))
        self.assertIn(b"H\x00o\x00s\x00t\x00N\x00a\x00m\x00e\x00", data)

    def test_decode_report_admits_defeat_on_an_opaque_file(self):
        out = pivscan.decode_report(self.fx("empty.piv"))
        self.assertIn("No candidate recovered", out)

    def test_nothing_matched_output_points_at_decode(self):
        out = pivscan.render(pivscan.scan(self.fx("empty.piv")))
        self.assertIn("pivscan decode", out)

    def _big_obfuscated(self, key, repeats=30):
        """~100 KB of UTF-16LE properties under `key`. Size matters here: the
        scoring bugs this guards against only appear at scale."""
        props = [
            "HostName=proiv-app01.corp.internal", "ProivUserName=operator",
            "ProivPassword=" + make_fixtures.PLAIN_PW, "SessionType=Telnet",
            "RememberUsernameAndPassword=1", "PromptForSecurity=0",
            "ActivateUserRuntimeInterface=1", "DebugTrace=1",
            "ApplicationDefinitions=\\\\fs01\\proiv$\\appdef.ini",
            "XferIn=MENU=ADMIN", "UploadMax=1048576", "CustomToolBar=1",
        ]
        body = b""
        for _ in range(repeats):
            for f in props:
                body += f.encode("utf-16-le") + b"\x01\x00"
        path = os.path.join(self.dir, "big_%s.piv" % key.hex())
        with open(path, "wb") as fh:
            fh.write(b"PRO4VS" + pivscan.xor_bytes(body, key))
        return path

    def test_score_prefers_correct_utf16_over_printable_garbage(self):
        # The regression that mattered most. A UTF-16 character is two bytes
        # but one extracted character, so counting characters scored printable
        # garbage at ~2x a correct decode: on a 100 KB file the right key
        # scored 51,930 and a wrong one 101,789. Coverage is counted in bytes.
        path = self._big_obfuscated(b"\x3b")
        raw = pivscan.read_file(path)
        body = raw[pivscan.header_skip(raw):]
        right = pivscan.text_score(pivscan.xor_bytes(body, b"\x3b"))
        wrong = pivscan.text_score(pivscan.xor_bytes(body, b"\x32"))
        self.assertGreater(len(right["keyword_hits"]), 5)
        self.assertEqual(wrong["keyword_hits"], [])
        self.assertGreater(right["score"], wrong["score"])

    def test_coverage_counts_utf16_as_two_bytes(self):
        utf16 = pivscan.text_score("HostName=server01".encode("utf-16-le"))
        ascii_ = pivscan.text_score(b"HostName=server01")
        # Both account for essentially the whole input.
        self.assertGreater(utf16["coverage"], 0.8)
        self.assertGreater(ascii_["coverage"], 0.8)

    def test_detection_works_at_scale(self):
        for key in (b"\x3b", b"\x3b\x2f"):
            rep = pivscan.scan(self._big_obfuscated(key))
            self.assertTrue(rep["obfuscation"]["detected"],
                            "100 KB file with key %s not detected" % key.hex())
            self.assertEqual(rep["obfuscation"]["transform"],
                             "xor:" + key.hex())
            self.assertIn("PIV-CRED-001", {f["id"] for f in rep["findings"]})

    def test_recovery_does_not_scale_with_file_size(self):
        # Key recovery used to run over the whole body -- 256 trial decodes per
        # column -- which cost 19 seconds on a 100 KB file. It runs on an 8 KB
        # sample now; column alignment is identical because the sample starts
        # at offset 0. Asserted as a loose ceiling rather than a benchmark.
        import time
        path = self._big_obfuscated(b"\x3b", repeats=60)
        start = time.time()
        rep = pivscan.scan(path)
        elapsed = time.time() - start
        self.assertTrue(rep["obfuscation"]["detected"])
        self.assertLess(elapsed, 15, "deobfuscation is pathologically slow again")

    def test_decode_surfaces_a_candidate_auto_detect_declines(self):
        # Auto-decode needs two distinct property names; `decode` has no such
        # gate, which is the point of having both.
        path = os.path.join(self.dir, "thin.piv")
        body = b""
        for _ in range(50):
            body += "HostName=a".encode("utf-16-le") + b"\x01\x00"
        with open(path, "wb") as fh:
            fh.write(b"PRO4VS" + pivscan.xor_bytes(body, b"\x3b"))

        self.assertFalse(pivscan.scan(path)["obfuscation"]["detected"])
        cands = pivscan.deobfuscate_candidates(
            pivscan.read_file(path), skip=pivscan.header_skip(pivscan.read_file(path)))
        self.assertEqual(cands[0]["transform"], "xor:3b")

    def test_text_score_rewards_property_names(self):
        plain = pivscan.text_score(b"HostName=a\r\nProivPassword=b\r\nDebugTrace=1\r\n")
        noise = pivscan.text_score(b"qqqqqqqqqq wwwwwwwwww eeeeeeeeee")
        self.assertGreater(len(plain["keyword_hits"]), 2)
        self.assertEqual(noise["keyword_hits"], [])
        self.assertGreater(plain["score"], noise["score"])


class TestPlaintextOutput(FixtureCase):
    def test_every_field_is_listed(self):
        out = pivscan.render_plaintext(self.fx("obfuscated.piv"))
        for field in ("CustomToolBar", "HostName=proiv-app03.corp.internal",
                      "SessionType=Telnet", "ProivPassword=",
                      "ActivateUserRuntimeInterface=1", "DebugTrace=1"):
            self.assertIn(field, out)

    def test_magic_is_shown_as_such(self):
        out = pivscan.render_plaintext(self.fx("obfuscated.piv"))
        self.assertIn("PRO4VS", out)
        self.assertIn("magic", out)

    def test_transform_is_named(self):
        out = pivscan.render_plaintext(self.fx("obfuscated.piv"))
        self.assertIn("xor:3b", out)
        self.assertIn("auto-detected", out)

    def test_offsets_match_the_original_file(self):
        _raw, data, skip, _obf = pivscan.load_decoded(self.fx("obfuscated.piv"))
        rows = pivscan.plaintext_lines(data, skip)
        raw = pivscan.read_file(self.fx("obfuscated.piv"))
        decoded = raw[:6] + pivscan.xor_bytes(raw[6:], b"\x3b")
        for r in rows:
            if r["encoding"] != "utf-16le":
                continue
            at = decoded[r["offset"]:r["offset"] + len(r["text"]) * 2]
            self.assertEqual(at.decode("utf-16-le", "replace"), r["text"])

    def test_field_boundaries_are_preserved(self):
        # Gluing adjacent runs together would lose the field structure, which
        # is the only structure a string-level view has.
        _raw, data, skip, _obf = pivscan.load_decoded(self.fx("obfuscated.piv"))
        rows = [r for r in pivscan.plaintext_lines(data, skip)
                if r["encoding"] == "utf-16le"]
        self.assertGreater(len(rows), 10)
        self.assertNotIn("CustomToolBarDefaultWallpaper",
                         " ".join(r["text"] for r in rows))

    def test_hex_mode_renders_a_dump(self):
        out = pivscan.render_plaintext(self.fx("obfuscated.piv"), as_hex=True)
        self.assertIn("|PRO4VSC.u.s.t.o.|", out)

    def test_plain_file_says_no_transform_applied(self):
        out = pivscan.render_plaintext(self.fx("text.piv"))
        self.assertIn("none applied", out)
        self.assertIn("HostName=", out)

    def test_scan_can_embed_the_plaintext(self):
        rep = pivscan.scan(self.fx("obfuscated.piv"), show_plaintext=True)
        self.assertIn("plaintext", rep)
        rendered = pivscan.render(rep)
        self.assertIn("DEOBFUSCATED CONTENTS", rendered)
        self.assertIn("SessionType=Telnet", rendered)

    def test_scan_omits_the_plaintext_by_default(self):
        self.assertNotIn("plaintext", pivscan.scan(self.fx("obfuscated.piv")))

    def test_load_decoded_is_consistent_with_scan(self):
        raw, data, skip, obf = pivscan.load_decoded(self.fx("obfuscated.piv"))
        self.assertEqual(len(raw), len(data))        # length-preserving
        self.assertEqual(obf["transform"], "xor:3b")
        self.assertEqual(skip, 6)


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
