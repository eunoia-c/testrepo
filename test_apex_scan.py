#!/usr/bin/env python3
"""Unit tests for apex_scan.py.

Run: python3 -m unittest -v test_apex_scan
     python3 test_apex_scan.py

The emphasis is on the properties that make the tool safe to report from:
comments and literals cannot produce hits, redaction never leaks a value,
fingerprints survive line movement, and a malformed file cannot abort the run.
"""

import csv
import io
import json
import os
import shutil
import tempfile
import unittest

import apex_scan as A


def unit(src: str, name: str = "T.cls") -> A.ApexUnit:
    return A.ApexUnit(A.SourceFile(name, src, relpath=name))


def scan(src: str, name: str = "T.cls") -> list[A.Finding]:
    findings, _entries, err = A.Scanner().scan_text(src, name)
    assert not err, err
    return findings


def ids(findings) -> set[str]:
    return {f.rule_id for f in findings}


# --------------------------------------------------------------------------
class TestPreprocessing(unittest.TestCase):

    def test_masking_preserves_offsets_and_lines(self):
        src = "line1\n// comment here\nString s = 'abc';\n"
        sf = A.SourceFile("T.cls", src)
        self.assertEqual(len(sf.masked), len(src))
        self.assertEqual(sf.masked.count("\n"), src.count("\n"))
        self.assertEqual(sf.line_of(src.index("String")), 3)

    def test_line_comment_blanked(self):
        sf = A.SourceFile("T.cls", "// Database.query(evil)\nInteger x = 1;")
        self.assertNotIn("Database.query", sf.masked)

    def test_block_comment_blanked_across_lines(self):
        sf = A.SourceFile("T.cls", "/* Database.query(\n  evil\n) */\nInteger x = 1;")
        self.assertNotIn("Database.query", sf.masked)
        self.assertEqual(sf.masked.count("\n"), 3)

    def test_string_interior_blanked_but_quotes_kept(self):
        sf = A.SourceFile("T.cls", "String s = 'Database.query(x)';")
        self.assertNotIn("Database.query", sf.masked)
        self.assertEqual(sf.masked.count("'"), 2)

    def test_literal_value_recorded(self):
        sf = A.SourceFile("T.cls", "String s = 'hello world';")
        self.assertEqual([l.value for l in sf.literals], ["hello world"])

    def test_escaped_quote_inside_literal(self):
        sf = A.SourceFile("T.cls", r"String s = 'it\'s fine'; Integer y = 2;")
        self.assertEqual(sf.literals[0].value, "it's fine")
        self.assertIn("Integer y", sf.masked)

    def test_unterminated_literal_does_not_swallow_file(self):
        src = "String s = 'oops\nInteger y = 2;\n"
        sf = A.SourceFile("T.cls", src)
        self.assertIn("Integer y", sf.masked)

    def test_markup_masks_html_comments_and_double_quotes(self):
        sf = A.SourceFile("P.page", '<!-- secret -->\n<a href="http://x">t</a>')
        self.assertNotIn("secret", sf.masked)
        self.assertIn("http://x", [l.value for l in sf.literals])


# --------------------------------------------------------------------------
class TestParsing(unittest.TestCase):

    def test_class_sharing_variants(self):
        for decl, expect in (("with sharing", "with sharing"),
                             ("without sharing", "without sharing"),
                             ("inherited sharing", "inherited sharing"),
                             ("", "")):
            u = unit("public %s class C { }" % decl)
            self.assertEqual(u.classes[0].sharing, expect, decl)

    def test_method_and_params(self):
        u = unit("public class C { @AuraEnabled public static String f(String a, Integer b) { return a; } }")
        m = u.method_by_name("f")
        self.assertIsNotNone(m)
        self.assertEqual([p.name for p in m.params], ["a", "b"])
        self.assertTrue(m.is_entry_point)
        self.assertEqual(m.entry_kind, "@AuraEnabled")

    def test_generic_param_types_not_split_on_inner_comma(self):
        u = unit("public class C { public static void f(Map<String, Object> m, String s) { } }")
        self.assertEqual([p.name for p in u.method_by_name("f").params], ["m", "s"])

    def test_non_entry_point_private_method(self):
        u = unit("public class C { private static void helper(String s) { } }")
        self.assertFalse(u.method_by_name("helper").is_entry_point)

    def test_webservice_and_global_are_entry_points(self):
        u = unit("global class C { webservice static void a(String s) { } global static void b(String s) { } }")
        self.assertTrue(u.method_by_name("a").is_entry_point)
        self.assertTrue(u.method_by_name("b").is_entry_point)


# --------------------------------------------------------------------------
class TestSoqlTaint(unittest.TestCase):

    def test_direct_injection_high_confidence(self):
        f = [x for x in scan("""
public class C {
    @AuraEnabled
    public static List<Account> f(String n) {
        String q = 'SELECT Id FROM Account WHERE Name = ' + n;
        return Database.query(q);
    }
}""") if x.rule_id == "APEX-SOQL-001"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].confidence, "HIGH")
        self.assertEqual(f[0].parameter, "n")
        self.assertGreaterEqual(len(f[0].chain), 3)
        self.assertEqual(f[0].chain[0]["kind"], "source")
        self.assertEqual(f[0].chain[-1]["kind"], "sink")

    def test_escape_single_quotes_clears_taint(self):
        self.assertNotIn("APEX-SOQL-001", ids(scan("""
public class C {
    @AuraEnabled
    public static List<Account> f(String n) {
        String q = 'SELECT Id FROM Account WHERE Name = ' + String.escapeSingleQuotes(n);
        return Database.query(q);
    }
}""")))

    def test_bind_variable_is_not_injection(self):
        self.assertNotIn("APEX-SOQL-001", ids(scan("""
public class C {
    @AuraEnabled
    public static List<Account> f(String n) {
        return Database.query('SELECT Id FROM Account WHERE Name = :n');
    }
}""")))

    def test_cast_clears_taint(self):
        self.assertNotIn("APEX-SOQL-001", ids(scan("""
public class C {
    @AuraEnabled
    public static List<Account> f(String raw) {
        Id safe = Id.valueOf(raw);
        return Database.query('SELECT Id FROM Account WHERE Id = \\'' + safe + '\\'');
    }
}""")))

    def test_allowlist_contains_clears_taint(self):
        self.assertNotIn("APEX-SOQL-001", ids(scan("""
public class C {
    private static final Set<String> ALLOWED = new Set<String>{'Name','Id'};
    @AuraEnabled
    public static List<Account> f(String fld) {
        if (!ALLOWED.contains(fld)) { return null; }
        return Database.query('SELECT ' + fld + ' FROM Account');
    }
}""")))

    def test_helper_propagation_medium_confidence(self):
        f = [x for x in scan("""
public class C {
    @AuraEnabled
    public static List<Account> f(String n) { return h(n); }
    private static List<Account> h(String t) {
        return Database.query('SELECT Id FROM Account WHERE Name = ' + t);
    }
}""") if x.rule_id == "APEX-SOQL-001"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].confidence, "MEDIUM")
        self.assertTrue(any(s["kind"] == "call" for s in f[0].chain))

    def test_page_parameter_is_a_source(self):
        self.assertIn("APEX-SOQL-001", ids(scan("""
public class C {
    public static List<Account> f() {
        String n = ApexPages.currentPage().getParameters().get('q');
        return Database.query('SELECT Id FROM Account WHERE Name = ' + n);
    }
}""")))

    def test_commented_out_sink_never_fires(self):
        self.assertFalse(ids(scan("""
public with sharing class C {
    @AuraEnabled
    public static void f(String n) {
        // return Database.query('SELECT Id FROM Account WHERE Name = ' + n);
        /* Database.query('SELECT Id FROM Contact WHERE X = ' + n); */
    }
}""")) & {"APEX-SOQL-001", "APEX-SOQL-002"})

    def test_multiple_sources_all_reported_in_parameter(self):
        f = [x for x in scan("""
public class C {
    @AuraEnabled
    public static List<Account> f(String a, String b) {
        String q = 'SELECT Id FROM Account WHERE N = ' + a;
        q += ' ORDER BY ' + b;
        return Database.query(q);
    }
}""") if x.rule_id == "APEX-SOQL-001"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].parameter, "a, b")

    def test_static_query_only_is_not_reported(self):
        self.assertFalse(ids(scan("""
public with sharing class C {
    @AuraEnabled
    public static List<Account> f() {
        return Database.query('SELECT Id FROM Account LIMIT 10');
    }
}""")) & {"APEX-SOQL-001", "APEX-SOQL-002"})

    def test_all_sink_functions_recognised(self):
        for sink in ("Database.query", "Database.countQuery", "Database.getQueryLocator",
                     "Search.query"):
            src = """
public class C {
    @AuraEnabled
    public static Object f(String n) {
        return %s('SELECT Id FROM Account WHERE N = ' + n);
    }
}""" % sink
            self.assertIn("APEX-SOQL-001", ids(scan(src)), sink)


# --------------------------------------------------------------------------
class TestSecrets(unittest.TestCase):

    SECRET = "kR8mQ2vN" + "7pL4xW9z" + "T6yB3dF5"

    def test_keyword_assignment_detected_with_underscore_name(self):
        f = [x for x in scan("public class C { String SVC_TOKEN = '%s'; }" % self.SECRET)
             if x.rule_id == "APEX-SECRET-001"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].confidence, "MEDIUM")

    def test_value_never_appears_in_any_output_field(self):
        f = [x for x in scan("public class C { String apiKey = '%s'; }" % self.SECRET)
             if x.rule_id == "APEX-SECRET-001"][0]
        blob = json.dumps(f.to_dict())
        self.assertNotIn(self.SECRET, blob)
        self.assertIn("kR8m", blob)          # first four only
        self.assertIn(str(len(self.SECRET)), blob)

    def test_known_format_is_critical(self):
        key = "AKIA" + "QZ7T4N2VJ" + "R8KWLMD"   # AKIA + exactly 16 chars
        f = [x for x in scan("public class C { String k = '%s'; }" % key)
             if x.rule_id == "APEX-SECRET-001"][0]
        self.assertEqual(f.severity, "CRITICAL")
        self.assertEqual(f.confidence, "HIGH")

    def test_placeholders_suppressed(self):
        src = ("public class C { String apiKey = 'YOUR_API_KEY_HERE';"
               " String t = 'changeme'; String e = ''; String x = 'test1234'; }")
        self.assertNotIn("APEX-SECRET-001", ids(scan(src)))

    def test_prose_and_urls_not_flagged_by_entropy(self):
        src = ("public class C { String msg = 'The quick brown fox jumps over it';"
               " String u = 'https://example.com/a/b/c/d/e/f/g'; }")
        self.assertNotIn("APEX-SECRET-001", ids(scan(src)))

    def test_entropy_helper(self):
        self.assertGreater(A.shannon_entropy("aB3$xY9!zQ2@wE7#"), 3.5)
        self.assertLess(A.shannon_entropy("aaaaaaaaaaaa"), 0.5)

    def test_redact_format(self):
        self.assertEqual(A.redact("abcdefgh"), "abcd… (8 chars)")
        self.assertEqual(A.redact(""), "(empty)")


# --------------------------------------------------------------------------
class TestSharing(unittest.TestCase):

    AURA = "@AuraEnabled public static List<Contact> a() { return [SELECT Id FROM Contact]; }"

    def test_with_sharing_not_flagged(self):
        self.assertNotIn("APEX-SHARE-001",
                         ids(scan("public with sharing class C { %s }" % self.AURA)))

    def test_without_sharing_flagged(self):
        self.assertIn("APEX-SHARE-001",
                      ids(scan("public without sharing class C { %s }" % self.AURA)))

    def test_no_declaration_flagged_lower(self):
        f = [x for x in scan("public class C { }") if x.rule_id == "APEX-SHARE-001"][0]
        self.assertEqual(f.severity, "LOW")

    def test_escalated_when_remote_entry_and_no_crud_checks(self):
        f = [x for x in scan("public without sharing class C { %s }" % self.AURA)
             if x.rule_id == "APEX-SHARE-001"][0]
        self.assertEqual(f.severity, "HIGH")
        self.assertEqual(f.confidence, "HIGH")
        self.assertFalse(f.extra["has_crud_fls_checks"])

    def test_not_escalated_when_crud_checks_present(self):
        src = ("public without sharing class C { @AuraEnabled public static void a() {"
               " if (Schema.sObjectType.Contact.isAccessible()) { } } }")
        f = [x for x in scan(src) if x.rule_id == "APEX-SHARE-001"][0]
        self.assertEqual(f.severity, "MEDIUM")
        self.assertTrue(f.extra["has_crud_fls_checks"])

    def test_inherited_sharing_not_flagged(self):
        self.assertNotIn("APEX-SHARE-001",
                         ids(scan("public inherited sharing class C { %s }" % self.AURA)))


# --------------------------------------------------------------------------
class TestCryptoAndCallouts(unittest.TestCase):

    def test_weak_digest_flagged(self):
        for algo in ("MD5", "SHA1", "SHA-1"):
            self.assertIn("APEX-CRYPTO-001", ids(scan(
                "public class C { Blob b = Crypto.generateDigest('%s', x); }" % algo)), algo)

    def test_strong_digest_not_flagged(self):
        self.assertNotIn("APEX-CRYPTO-001", ids(scan(
            "public class C { Blob b = Crypto.generateDigest('SHA-256', x); }")))

    def test_math_random_for_token_flagged(self):
        self.assertIn("APEX-CRYPTO-003", ids(scan(
            "public class C { String token = String.valueOf(Math.random()); }")))

    def test_math_random_unrelated_not_flagged(self):
        self.assertNotIn("APEX-CRYPTO-003", ids(scan(
            "public class C { Double jitter = Math.random() * 10; }")))

    def test_http_endpoint_flagged(self):
        self.assertIn("APEX-CALLOUT-002", ids(scan(
            "public class C { void f() { r.setEndpoint('http://a.example.com/x'); } }")))

    def test_named_credential_not_flagged(self):
        got = ids(scan("public class C { void f() { r.setEndpoint('callout:My_NC/x'); } }"))
        self.assertFalse(got & {"APEX-CALLOUT-002", "APEX-CALLOUT-003"})

    def test_external_https_host_listed(self):
        f = [x for x in scan("public class C { void f() { r.setEndpoint('https://api.vendor.com/x'); } }")
             if x.rule_id == "APEX-CALLOUT-003"][0]
        self.assertEqual(f.extra["host"], "api.vendor.com")

    def test_salesforce_host_not_listed_as_external(self):
        self.assertNotIn("APEX-CALLOUT-003", ids(scan(
            "public class C { void f() { r.setEndpoint('https://na1.salesforce.com/x'); } }")))

    def test_tainted_endpoint_is_ssrf_candidate(self):
        self.assertIn("APEX-CALLOUT-004", ids(scan("""
public class C {
    @AuraEnabled
    public static void f(String target) { r.setEndpoint(target); }
}""")))

    def test_hardcoded_authorization_header_redacted(self):
        f = [x for x in scan(
            "public class C { void f() { r.setHeader('Authorization', 'Basic QWxhZGRpbjpvcGVu'); } }")
            if x.rule_id == "APEX-CALLOUT-005"][0]
        self.assertNotIn("QWxhZGRpbjpvcGVu", json.dumps(f.to_dict()))


# --------------------------------------------------------------------------
class TestMiscRules(unittest.TestCase):

    def test_read_modify_write_without_for_update(self):
        self.assertIn("APEX-MISC-001", ids(scan("""
public class C {
    public static void f(Id i) {
        Account a = [SELECT Id FROM Account WHERE Id = :i];
        update a;
    }
}""")))

    def test_for_update_suppresses(self):
        self.assertNotIn("APEX-MISC-001", ids(scan("""
public class C {
    public static void f(Id i) {
        Account a = [SELECT Id FROM Account WHERE Id = :i FOR UPDATE];
        update a;
    }
}""")))

    def test_debug_of_sensitive_variable(self):
        self.assertIn("APEX-MISC-002", ids(scan(
            "public class C { void f(String userPassword) { System.debug(userPassword); } }")))

    def test_debug_of_ordinary_variable_not_flagged(self):
        self.assertNotIn("APEX-MISC-002", ids(scan(
            "public class C { void f(String name) { System.debug(name); } }")))

    def test_hardcoded_salesforce_id(self):
        f = [x for x in scan("public class C { String o = '0058d000004k2VbAAI'; }")
             if x.rule_id == "APEX-MISC-003"]
        self.assertEqual(len(f), 1)

    def test_dml_in_loop_is_informational_only(self):
        f = [x for x in scan(
            "public class C { void f(List<Account> l) { for (Account a : l) { update a; } } }")
            if x.rule_id == "APEX-MISC-004"][0]
        self.assertEqual(f.severity, "INFO")


# --------------------------------------------------------------------------
class TestRobustness(unittest.TestCase):

    def test_malformed_file_does_not_raise(self):
        bad = "public class Broken { void f( {\n  String q = 'unclosed\n  if (x"
        findings, entries, err = A.Scanner().scan_text(bad, "Broken.cls")
        self.assertIsInstance(findings, list)
        self.assertIsInstance(entries, list)

    def test_binary_ish_content_does_not_raise(self):
        findings, _e, _err = A.Scanner().scan_text("\x00\x01\x02 garbage �", "X.cls")
        self.assertIsInstance(findings, list)

    def test_empty_input(self):
        findings, entries, err = A.Scanner().scan_text("", "E.cls")
        self.assertEqual(findings, [])
        self.assertEqual(entries, [])

    def test_deeply_nested_does_not_hang(self):
        src = "public class C { void f() { " + "if (x) { " * 60 + "}" * 60 + " } }"
        findings, _e, _err = A.Scanner().scan_text(src, "N.cls")
        self.assertIsInstance(findings, list)


# --------------------------------------------------------------------------
class TestFindingIdentity(unittest.TestCase):

    SRC = """
public class C {
    @AuraEnabled
    public static List<Account> f(String n) {
        return Database.query('SELECT Id FROM Account WHERE N = ' + n);
    }
}"""

    def test_fingerprint_stable_across_runs(self):
        a = [f.compute_fingerprint() for f in scan(self.SRC)]
        b = [f.compute_fingerprint() for f in scan(self.SRC)]
        self.assertEqual(a, b)

    def test_fingerprint_survives_line_shift(self):
        """Prepending lines must not churn every fingerprint, or diffing runs
        is useless after any unrelated edit."""
        base = {f.rule_id: f.compute_fingerprint() for f in scan(self.SRC)}
        shifted = {f.rule_id: f.compute_fingerprint()
                   for f in scan("// added\n// added\n" + self.SRC)}
        self.assertEqual(base, shifted)

    def test_ordering_is_deterministic(self):
        f = scan(self.SRC)
        self.assertEqual([x.rule_id for x in sorted(f, key=A.sort_key)],
                         [x.rule_id for x in sorted(list(reversed(f)), key=A.sort_key)])

    def test_severity_ordering(self):
        f = sorted(scan(self.SRC), key=A.sort_key)
        ranks = [A.SEVERITY_RANK[x.severity] for x in f]
        self.assertEqual(ranks, sorted(ranks))


# --------------------------------------------------------------------------
class TestFilters(unittest.TestCase):

    def _findings(self):
        return scan("""
public without sharing class C {
    @AuraEnabled
    public static List<Account> f(String n) {
        return Database.query('SELECT Id FROM Account WHERE N = ' + n);
    }
}""")

    def test_min_confidence_high_drops_lower(self):
        kept = A.filter_findings(self._findings(), "HIGH", None)
        self.assertTrue(all(f.confidence == "HIGH" for f in kept))

    def test_rule_filter_exact(self):
        kept = A.filter_findings(self._findings(), "LOW", {"APEX-SOQL-001"})
        self.assertEqual({f.rule_id for f in kept}, {"APEX-SOQL-001"})

    def test_rule_filter_prefix_expansion(self):
        self.assertEqual(A.expand_rule_filter("APEX-SOQL"), {"APEX-SOQL-001", "APEX-SOQL-002"})

    def test_unknown_rule_filter_rejected(self):
        with self.assertRaises(SystemExit):
            A.expand_rule_filter("NOPE-123")


# --------------------------------------------------------------------------
class TestEndToEnd(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.src = os.path.join(self.tmp, "dump")
        self.out = os.path.join(self.tmp, "out")
        os.makedirs(self.src)
        with open(os.path.join(self.src, "Vuln.cls"), "w") as fh:
            fh.write("""
public without sharing class Vuln {
    @AuraEnabled
    public static List<Account> f(String n) {
        return Database.query('SELECT Id FROM Account WHERE N = ' + n);
    }
}""")
        with open(os.path.join(self.src, "Managed.cls"), "w") as fh:
            fh.write("(hidden)")
        with open(os.path.join(self.src, "Empty.cls"), "w") as fh:
            fh.write("")
        with open(os.path.join(self.src, "Broken.cls"), "w") as fh:
            fh.write("public class Broken { void f( { 'unclosed")
        with open(os.path.join(self.src, "notes.txt"), "w") as fh:
            fh.write("ignored, wrong extension")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_hidden_and_empty_counted_separately(self):
        _f, _e, stats = A.Scanner().scan_dir(self.src)
        self.assertEqual(stats.files_hidden, 1)
        self.assertEqual(stats.files_empty, 1)
        self.assertEqual(stats.hidden_files, ["Managed.cls"])
        self.assertEqual(stats.files_seen, 4)          # notes.txt excluded

    def test_cli_writes_all_three_formats(self):
        rc = A.main(["--input", self.src, "--out", self.out,
                     "--format", "json,csv,md", "--quiet"])
        self.assertEqual(rc, 0)
        for name in ("results.json", "results.csv", "report.md"):
            self.assertTrue(os.path.exists(os.path.join(self.out, name)), name)

    def test_json_is_valid_and_reports_coverage(self):
        A.main(["--input", self.src, "--out", self.out, "--format", "json", "--quiet"])
        with open(os.path.join(self.out, "results.json")) as fh:
            d = json.load(fh)
        self.assertEqual(d["coverage"]["files_hidden"], 1)
        self.assertIn("entry_points", d)
        self.assertTrue(all("fingerprint" in f for f in d["findings"]))

    def test_csv_has_expected_header_and_parses(self):
        A.main(["--input", self.src, "--out", self.out, "--format", "csv", "--quiet"])
        with open(os.path.join(self.out, "results.csv"), newline="") as fh:
            rows = list(csv.reader(fh))
        self.assertEqual(rows[0], A.CSV_COLUMNS)
        self.assertTrue(all(len(r) == len(A.CSV_COLUMNS) for r in rows))

    def test_markdown_contains_required_sections(self):
        A.main(["--input", self.src, "--out", self.out, "--format", "md", "--quiet"])
        md = open(os.path.join(self.out, "report.md")).read()
        for heading in ("## Summary", "## Coverage", "## Checker validation",
                        "## Attack surface inventory", "## Findings"):
            self.assertIn(heading, md, heading)

    def test_entry_point_inventory_lists_regardless_of_findings(self):
        _f, entries, _s = A.Scanner().scan_dir(self.src)
        self.assertTrue(any(e.method == "f" and e.kind == "@AuraEnabled" for e in entries))

    def test_missing_input_returns_error_code(self):
        self.assertEqual(A.main(["--input", os.path.join(self.tmp, "nope"),
                                 "--out", self.out, "--quiet"]), 2)


# --------------------------------------------------------------------------
class TestRedactionAcrossOutputs(unittest.TestCase):
    """The markdown report prints three lines of context either side of every
    finding. A credential on one of those lines leaked into the report even
    though the secret rule redacted its own snippet -- so redaction is applied
    to every string that leaves the tool, not per-rule. These guard that."""

    SECRET = "kR8mQ2vN" + "7pL4xW9z" + "T6yB3dF5"
    AUTHVAL = "Basic QWxh" + "ZGRpbjpvcGVu"

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.src = os.path.join(self.tmp, "dump")
        self.out = os.path.join(self.tmp, "out")
        os.makedirs(self.src)
        # The secret sits two lines above an unrelated finding, so it lands in
        # that finding's context window.
        with open(os.path.join(self.src, "Leaky.cls"), "w") as fh:
            fh.write("""
public without sharing class Leaky {
    private static final String apiKey = '%s';
    public static void f() {
        HttpRequest r = new HttpRequest();
        r.setEndpoint('http://plain.example.com/x');
        r.setHeader('Authorization', '%s');
    }
}""" % (self.SECRET, self.AUTHVAL))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _outputs(self) -> str:
        A.main(["--input", self.src, "--out", self.out,
                "--format", "json,csv,md", "--quiet"])
        blob = []
        for name in ("results.json", "results.csv", "report.md"):
            with open(os.path.join(self.out, name), encoding="utf-8") as fh:
                blob.append(fh.read())
        return "\n".join(blob)

    def test_secret_never_appears_in_any_output(self):
        self.assertNotIn(self.SECRET, self._outputs())

    def test_authorization_value_never_appears_in_any_output(self):
        self.assertNotIn(self.AUTHVAL, self._outputs())

    def test_redacted_prefix_is_present_so_finding_is_still_actionable(self):
        blob = self._outputs()
        self.assertIn(self.SECRET[:4], blob)
        self.assertIn("%d chars" % len(self.SECRET), blob)

    def test_markdown_context_window_is_scrubbed(self):
        A.main(["--input", self.src, "--out", self.out, "--format", "md", "--quiet"])
        md = open(os.path.join(self.out, "report.md"), encoding="utf-8").read()
        self.assertIn("```apex", md)          # context blocks were rendered
        self.assertNotIn(self.SECRET, md)     # and scrubbed

    def test_scrub_helper(self):
        self.assertEqual(A.scrub("x=%s;" % self.SECRET, [self.SECRET]),
                         "x=%s;" % A.redact(self.SECRET))
        self.assertEqual(A.scrub("nothing here", [self.SECRET]), "nothing here")


# --------------------------------------------------------------------------
class TestSelfTest(unittest.TestCase):

    def test_built_in_self_test_passes(self):
        r = A.run_self_test()
        self.assertTrue(r["passed"], "\n".join(r["failures"]))
        self.assertGreater(r["assertions"], 15)

    def test_self_test_covers_both_polarities(self):
        self.assertGreater(A.run_self_test()["vulnerable"], 0)
        self.assertGreater(A.run_self_test()["safe"], 0)

    def test_cli_self_test_exit_code(self):
        self.assertEqual(A.main(["--self-test", "--quiet"]), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
