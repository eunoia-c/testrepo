#!/usr/bin/env python3
"""Tests for snowpick.py.

Assertions on request format, status classification and hint basis are taken
from the Go implementation's own test suite, so a divergence between the port
and the original fails here rather than in a client report.

Run: python3 -m unittest -v test_snowpick
"""

import json
import os
import shutil
import tempfile
import threading
import time
import unittest

import snowpick as S


# --------------------------------------------------------------------------
# Test doubles
# --------------------------------------------------------------------------

def response(status: int, body: str = "", headers: dict | None = None,
             cookies: list | None = None) -> S.Response:
    return S.Response(status=status,
                      headers={k.lower(): v for k, v in (headers or {}).items()},
                      body=body.encode("utf-8"),
                      set_cookies=cookies or [])


class FakeClient:
    """Records requests and replays canned responses."""

    def __init__(self, handler=None):
        self.handler = handler or (lambda **kw: response(200, "{}"))
        self.requests: list[dict] = []

    def request(self, method, url, headers=None, body="", max_body=S.MAX_BODY):
        call = {"method": method, "url": url, "headers": headers or {}, "body": body}
        self.requests.append(call)
        result = self.handler(**call)
        if isinstance(result, Exception):
            raise result
        return result


def session(target="TARGET_HOST", token="token123",
            cookies=(("JSESSIONID", "session123"),)) -> S.Session:
    return S.Session(target=target, token=token, cookies=list(cookies))


EXPOSED_WIDGET_BODY = json.dumps({
    "result": {"data": {"results": {
        "meta": {"count": 2, "returned_results": 1, "has_more_results": True},
        "results": [{"title": "Visible record", "sys_id": {"display_value": "ABC123"}}],
    }}}
})


# --------------------------------------------------------------------------
class TestSessionBootstrap(unittest.TestCase):

    def test_extracts_gck_token_and_cookies(self):
        page = "<html><script>var g_ck = 'deadbeefcafe1234';</script></html>"
        client = FakeClient(lambda **kw: response(
            200, page, cookies=[("JSESSIONID", "abc"), ("glide_user_route", "xyz")]))
        sess = S.bootstrap("host.example", client)
        self.assertEqual(sess.token, "deadbeefcafe1234")
        self.assertEqual(sess.cookies, [("JSESSIONID", "abc"), ("glide_user_route", "xyz")])
        self.assertEqual(client.requests[0]["url"], "https://host.example/login.do")

    def test_non_200_raises(self):
        client = FakeClient(lambda **kw: response(503, "nope"))
        with self.assertRaises(S.HttpError) as ctx:
            S.bootstrap("host.example", client)
        self.assertIn("503", str(ctx.exception))

    def test_missing_token_raises_with_body_size(self):
        client = FakeClient(lambda **kw: response(200, "no token here"))
        with self.assertRaises(S.HttpError) as ctx:
            S.bootstrap("host.example", client)
        self.assertIn("g_ck token not found", str(ctx.exception))

    def test_token_must_be_hex(self):
        client = FakeClient(lambda **kw: response(200, "g_ck = 'NOT-HEX-!!'"))
        with self.assertRaises(S.HttpError):
            S.bootstrap("host.example", client)

    def test_cookie_header_joins_pairs(self):
        sess = session(cookies=[("A", "1"), ("B", "2")])
        self.assertEqual(sess.cookie_header(), "A=1; B=2")

    def test_vendor_header_sent_when_set(self):
        S.VENDOR_HEADER = "engagement-42"
        try:
            self.assertEqual(S.base_headers().get("X-Vendor"), "engagement-42")
        finally:
            S.VENDOR_HEADER = ""

    def test_vendor_header_absent_by_default(self):
        self.assertNotIn("X-Vendor", S.base_headers())


# --------------------------------------------------------------------------
class TestWidgetProbe(unittest.TestCase):
    """Mirrors TestProbeWidgetExposedIncludesReproduction from the Go suite."""

    def test_exposed_includes_reproduction(self):
        seen = {}

        def handler(method, url, headers, body):
            seen.update(method=method, url=url, headers=headers, body=body)
            return response(201, EXPOSED_WIDGET_BODY)

        result = S.probe_widget(session(), S.Widget("widget123", "test-widget"),
                                FakeClient(handler))
        self.assertEqual(result.status, S.STATUS_EXPOSED, result.error)
        self.assertEqual(result.record_count, 2)
        self.assertEqual(seen["headers"]["X-UserToken"], "token123")
        self.assertEqual(seen["url"], "https://TARGET_HOST/api/now/sp/widget/widget123")

        repro = result.reproduction
        self.assertIsNotNone(repro)
        self.assertEqual(repro.method, "POST")
        self.assertEqual(repro.url, "https://TARGET_HOST/api/now/sp/widget/widget123")
        self.assertEqual(repro.headers["X-UserToken"], "token123")
        self.assertEqual(repro.headers["Cookie"], "JSESSIONID=session123")
        self.assertEqual(repro.body, '{"payload":{"start":0,"end":1}}')
        self.assertEqual(repro.status_code, 201)
        self.assertIn("JSESSIONID=session123", repro.curl)

    def test_evidence_fields_include_nested_display_value(self):
        result = S.probe_widget(session(), S.Widget("w", "n"),
                                FakeClient(lambda **kw: response(200, EXPOSED_WIDGET_BODY)))
        self.assertIn("title", result.evidence_fields)
        self.assertIn("sys_id.display_value", result.evidence_fields)

    def test_count_without_evidence_is_oracle(self):
        body = json.dumps({"result": {"data": {"results": {
            "meta": {"count": 42}, "results": []}}}})
        result = S.probe_widget(session(), S.Widget("w", "n"),
                                FakeClient(lambda **kw: response(200, body)))
        self.assertEqual(result.status, S.STATUS_COUNT_ORACLE)
        self.assertEqual(result.record_count, 42)
        self.assertIn("blind extraction", result.error)
        self.assertTrue(result.reproduction.oracle_hint)

    def test_oracle_hint_shows_both_sides_of_the_delta(self):
        hint = S.build_oracle_hint(session(), "w1")
        self.assertIn('"filterText":"a"', hint)
        self.assertIn('"filterText":"zqxj9"', hint)
        self.assertIn("count > 0", hint)
        self.assertIn("count == 0", hint)

    def test_zero_count_is_not_exposed(self):
        body = json.dumps({"result": {"data": {"results": {
            "meta": {"count": 0}, "results": []}}}})
        result = S.probe_widget(session(), S.Widget("w", "n"),
                                FakeClient(lambda **kw: response(200, body)))
        self.assertEqual(result.status, S.STATUS_NOT_EXPOSED)
        self.assertIsNone(result.reproduction)

    def test_404_is_widget_not_found(self):
        result = S.probe_widget(session(), S.Widget("w", "n"),
                                FakeClient(lambda **kw: response(404, "")))
        self.assertEqual(result.status, S.STATUS_WIDGET_MISSING)

    def test_invalid_token_response(self):
        body = json.dumps({"result": {"invalid_token": True}})
        result = S.probe_widget(session(), S.Widget("w", "n"),
                                FakeClient(lambda **kw: response(200, body)))
        self.assertEqual(result.status, S.STATUS_TOKEN_ERROR)
        self.assertEqual(result.error, "invalid_token response")

    def test_500_is_error(self):
        result = S.probe_widget(session(), S.Widget("w", "n"),
                                FakeClient(lambda **kw: response(500, "")))
        self.assertEqual(result.status, S.STATUS_ERROR)
        self.assertIn("500", result.error)

    def test_malformed_json_is_error_not_crash(self):
        result = S.probe_widget(session(), S.Widget("w", "n"),
                                FakeClient(lambda **kw: response(200, "<html>nope")))
        self.assertEqual(result.status, S.STATUS_ERROR)
        self.assertIn("parsing JSON", result.error)

    def test_transport_failure_is_error(self):
        result = S.probe_widget(session(), S.Widget("w", "n"),
                                FakeClient(lambda **kw: S.HttpError("connection refused")))
        self.assertEqual(result.status, S.STATUS_ERROR)
        self.assertIn("connection refused", result.error)

    def test_collect_samples_maps_fields_and_resolves_link(self):
        body = json.dumps({"result": {"data": {"results": {"meta": {"count": 1}, "results": [
            {"title": "T", "sys_id": "SID", "link": "?id=kb&sys_id=1",
             "short_description": "SD"}]}}}})
        samples = S.collect_samples(session(), "w", 5,
                                   FakeClient(lambda **kw: response(200, body)))
        self.assertEqual(len(samples), 1)
        self.assertEqual(samples[0].title, "T")
        self.assertEqual(samples[0].id, "SID")
        self.assertEqual(samples[0].snippet, "SD")
        self.assertEqual(samples[0].link,
                         "https://TARGET_HOST/sp?id=kb&sys_id=1")

    def test_sample_request_uses_requested_end(self):
        client = FakeClient(lambda **kw: response(200, EXPOSED_WIDGET_BODY))
        S.collect_samples(session(), "w", 7, client)
        self.assertEqual(client.requests[0]["body"], '{"payload":{"start":0,"end":7}}')


# --------------------------------------------------------------------------
class TestTableProbe(unittest.TestCase):

    LIST_BODY = json.dumps({"result": {"data": {"count": 5, "list": [
        {"sys_id": "abc", "display_field": {"display_value": "Widget Name"}}]}}})

    def test_url_query_is_sorted_like_go(self):
        url = S.build_table_url(session(), S.TableCandidate("incident", "number"))
        self.assertEqual(
            url,
            "https://TARGET_HOST/api/now/sp/widget/widget-simple-list?f=number&t=incident")

    def test_exposed_table_collects_samples(self):
        result = S.probe_table(session(), S.TableCandidate("sys_user", "name"), 10,
                               FakeClient(lambda **kw: response(200, self.LIST_BODY)))
        self.assertEqual(result.status, S.STATUS_EXPOSED)
        self.assertEqual(result.count, 5)
        self.assertEqual(result.sample_count, 1)
        self.assertEqual(result.samples[0].sys_id, "abc")
        self.assertEqual(result.samples[0].display_value, "Widget Name")
        self.assertEqual(result.reproduction.body, "{}")

    def test_count_only_table_is_oracle_with_hint(self):
        body = json.dumps({"result": {"data": {"count": 9, "list": []}}})
        result = S.probe_table(session(), S.TableCandidate("incident", "number"), 10,
                               FakeClient(lambda **kw: response(200, body)))
        self.assertEqual(result.status, S.STATUS_COUNT_ORACLE)
        self.assertEqual(result.count, 9)
        self.assertIn("widget-simple-list?t=incident&f=number",
                      result.reproduction.oracle_hint)

    def test_rows_without_evidence_are_oracle(self):
        body = json.dumps({"result": {"data": {"count": 3, "list": [{"nothing": "useful"}]}}})
        result = S.probe_table(session(), S.TableCandidate("x", "y"), 10,
                               FakeClient(lambda **kw: response(200, body)))
        self.assertEqual(result.status, S.STATUS_COUNT_ORACLE)

    def test_zero_count_not_exposed(self):
        body = json.dumps({"result": {"data": {"count": 0, "list": []}}})
        result = S.probe_table(session(), S.TableCandidate("x", "y"), 10,
                               FakeClient(lambda **kw: response(200, body)))
        self.assertEqual(result.status, S.STATUS_NOT_EXPOSED)

    def test_enumerate_returns_only_findings(self):
        def handler(method, url, headers, body):
            if "t=incident" in url:
                return response(200, self.LIST_BODY)
            return response(200, json.dumps({"result": {"data": {"count": 0, "list": []}}}))

        results = S.enumerate_tables(
            session(),
            [S.TableCandidate("incident", "number"), S.TableCandidate("quiet", "name")],
            10, 2, FakeClient(handler))
        self.assertEqual([r.table for r in results], ["incident"])

    def test_display_value_falls_back_to_first_nested(self):
        body = json.dumps({"result": {"data": {"count": 1, "list": [
            {"sys_id": "s", "other": {"display_value": "Zeta"},
             "another": {"display_value": "Alpha"}}]}}})
        result = S.probe_table(session(), S.TableCandidate("x", "y"), 10,
                               FakeClient(lambda **kw: response(200, body)))
        # Sorted, so the alphabetically-first display value wins -- matching Go.
        self.assertEqual(result.samples[0].display_value, "Alpha")

    def test_discovery_returns_empty_on_inaccessible_table(self):
        client = FakeClient(lambda **kw: response(403, ""))
        self.assertEqual(S.discover_tables(session(), 10, client), [])
        self.assertEqual(S.discover_widgets(session(), 10, client), [])

    def test_discovery_respects_limit(self):
        rows = [{"display_field": {"display_value": "t%d" % i}} for i in range(20)]
        body = json.dumps({"result": {"data": {"count": 20, "list": rows}}})
        found = S.discover_tables(session(), 5, FakeClient(lambda **kw: response(200, body)))
        self.assertEqual(len(found), 5)
        self.assertTrue(all(c.field == "name" for c in found))


# --------------------------------------------------------------------------
class TestTableAPI(unittest.TestCase):

    BODY = json.dumps({"result": [
        {"sys_id": "1", "name": "Alice", "email": "alice@corp.example"},
        {"sys_id": "2", "name": "Bob", "email": "bob@corp.example"}]})

    def test_exposed_uses_x_total_count(self):
        result = S.probe_table_api(
            session(), "sys_user", 10,
            FakeClient(lambda **kw: response(200, self.BODY, {"X-Total-Count": "4213"})))
        self.assertEqual(result.status, S.STATUS_EXPOSED)
        self.assertEqual(result.record_count, 4213)
        self.assertEqual(result.sample_count, 2)
        self.assertEqual(result.fields, ["email", "name", "sys_id"])
        self.assertEqual(result.samples[0].display_value, "Alice")

    def test_falls_back_to_row_count_without_header(self):
        result = S.probe_table_api(session(), "sys_user", 10,
                                   FakeClient(lambda **kw: response(200, self.BODY)))
        self.assertEqual(result.record_count, 2)

    def test_bad_total_count_header_falls_back(self):
        self.assertEqual(S.parse_x_total_count("not-a-number", 7), 7)
        self.assertEqual(S.parse_x_total_count("0", 7), 7)
        self.assertEqual(S.parse_x_total_count(" 12 ", 7), 12)

    def test_url_and_reproduction(self):
        result = S.probe_table_api(session(), "incident", 25,
                                   FakeClient(lambda **kw: response(200, self.BODY)))
        self.assertEqual(result.reproduction.url,
                         "https://TARGET_HOST/api/now/table/incident?sysparm_limit=25")
        self.assertEqual(result.reproduction.method, "GET")
        self.assertNotIn("Content-Type", result.reproduction.headers)

    def test_401_and_403_are_not_exposed(self):
        for status in (401, 403):
            result = S.probe_table_api(session(), "sys_user", 10,
                                       FakeClient(lambda **kw: response(status, "")))
            self.assertEqual(result.status, S.STATUS_NOT_EXPOSED, status)

    def test_404_notes_table_not_found(self):
        result = S.probe_table_api(session(), "nope", 10,
                                   FakeClient(lambda **kw: response(404, "")))
        self.assertEqual(result.status, S.STATUS_NOT_EXPOSED)
        self.assertEqual(result.error, "table not found")

    def test_empty_result_is_not_exposed(self):
        result = S.probe_table_api(session(), "sys_user", 10,
                                   FakeClient(lambda **kw: response(200, '{"result": []}')))
        self.assertEqual(result.status, S.STATUS_NOT_EXPOSED)

    def test_hints_applied_from_table_name(self):
        result = S.probe_table_api(session(), "sys_user", 10,
                                   FakeClient(lambda **kw: response(200, self.BODY)))
        self.assertTrue(any(h.category == S.IMPACT_PII for h in result.hints))

    def test_enumerate_keeps_only_exposed(self):
        def handler(method, url, headers, body):
            return response(200, self.BODY) if "sys_user" in url else response(403, "")

        results = S.enumerate_table_api(session(), ["sys_user", "incident"], 10, 2,
                                        FakeClient(handler))
        self.assertEqual([r.table for r in results], ["sys_user"])


# --------------------------------------------------------------------------
class TestClassification(unittest.TestCase):
    """Expectations lifted from the Go classify_test.go."""

    def test_sys_user_is_pii_inferred(self):
        hints = S.classify_table("sys_user", "", [])
        self.assertEqual(hints[0].category, S.IMPACT_PII)
        self.assertEqual(hints[0].basis, "inferred")

    def test_incident_is_operations_inferred(self):
        hints = S.classify_table("incident", "", [])
        self.assertEqual(hints[0].category, S.IMPACT_OPERATIONS)
        self.assertEqual(hints[0].basis, "inferred")

    def test_oauth_entity_is_credentials(self):
        hints = S.classify_table("oauth_entity", "", [])
        self.assertEqual(hints[0].category, S.IMPACT_CREDENTIALS)

    def test_sys_properties_is_credentials(self):
        self.assertEqual(S.classify_table("sys_properties", "", [])[0].category,
                         S.IMPACT_CREDENTIALS)

    def test_cmdb_model_and_ci_are_infrastructure(self):
        for table in ("cmdb_model", "cmdb_ci"):
            self.assertEqual(S.classify_table(table, "", [])[0].category,
                             S.IMPACT_INFRASTRUCTURE, table)

    def test_email_address_field_is_pii(self):
        hints = S.classify_table("unknown_table", "email_address", [])
        self.assertEqual(hints[0].category, S.IMPACT_PII)
        self.assertEqual(hints[0].basis, "inferred")

    def test_email_content_is_observed(self):
        hints = S.classify_table("unknown_table", "", [S.TableSample(display_value="a@b.com")])
        self.assertEqual(hints[0].category, S.IMPACT_PII)
        self.assertEqual(hints[0].basis, "observed")

    def test_internal_domains_are_observed_infrastructure(self):
        for value in ("host.corp ", "box.internal/", "srv.local"):
            hints = S.classify_table("unknown", "", [S.TableSample(display_value=value)])
            self.assertTrue(hints, value)
            self.assertEqual(hints[0].category, S.IMPACT_INFRASTRUCTURE, value)
            self.assertEqual(hints[0].basis, "observed", value)

    def test_observed_beats_inferred_for_same_category(self):
        hints = S.classify_table("sys_user", "", [S.TableSample(display_value="x@y.com")])
        pii = [h for h in hints if h.category == S.IMPACT_PII]
        self.assertEqual(pii[0].basis, "observed")

    def test_credential_content_pattern(self):
        hints = S.classify_table("x", "", [S.TableSample(display_value="api_key=abc123xyz")])
        self.assertTrue(any(h.category == S.IMPACT_CREDENTIALS and h.basis == "observed"
                            for h in hints))

    def test_bare_digits_are_not_treated_as_phone_numbers(self):
        hints = S.classify_table("unknown", "", [S.TableSample(display_value="5551234567")])
        self.assertEqual(hints, [])

    def test_widget_name_heuristics(self):
        self.assertTrue(any(h.category == S.IMPACT_OPERATIONS
                            for h in S.classify_widget("kb-article-page", [])))
        self.assertTrue(any(h.category == S.IMPACT_OPERATIONS
                            for h in S.classify_widget("ticket-attachments", [])))
        self.assertTrue(any(h.category == S.IMPACT_PII
                            for h in S.classify_widget("user-profile", [])))

    def test_widget_content_classified_from_samples(self):
        hints = S.classify_widget("plain", [S.RecordSample(snippet="mail me at a@b.org")])
        self.assertTrue(any(h.category == S.IMPACT_PII and h.basis == "observed"
                            for h in hints))

    def test_categories_emitted_in_severity_order(self):
        samples = [S.TableSample(display_value="a@b.com"),
                   S.TableSample(display_value="token=abcdefgh")]
        hints = S.classify_table("cmdb_ci", "", samples)
        order = [h.category for h in hints]
        self.assertEqual(order, sorted(order, key=S.CATEGORY_ORDER.index))

    def test_review_required_shape(self):
        hints = S.review_required_hint(12)
        self.assertEqual(hints[0].category, S.IMPACT_REVIEW)
        self.assertEqual(hints[0].basis, "none")
        self.assertEqual(hints[0].signals, ["records_returned:12"])

    def test_unknown_table_and_field_yields_nothing(self):
        self.assertEqual(S.classify_table("totally_unknown", "whatever", []), [])


# --------------------------------------------------------------------------
class TestHelpers(unittest.TestCase):

    def test_evidence_field_names(self):
        self.assertTrue(S.is_evidence_field("title"))
        self.assertTrue(S.is_evidence_field("a.b.display_value"))
        self.assertFalse(S.is_evidence_field("random_field"))
        self.assertFalse(S.is_evidence_field(""))

    def test_evidence_ignores_blank_strings(self):
        self.assertEqual(S.evidence_fields([{"title": "   "}]), [])

    def test_evidence_accepts_numbers_and_bools(self):
        self.assertEqual(S.evidence_fields([{"number": 7}]), ["number"])

    def test_resolve_link_variants(self):
        self.assertEqual(S.resolve_link("h", "https://x.example/a"), "https://x.example/a")
        self.assertEqual(S.resolve_link("h", "//x.example/a"), "https://x.example/a")
        self.assertEqual(S.resolve_link("h", "/sp/page"), "https://h/sp/page")
        self.assertEqual(S.resolve_link("h", "page"), "https://h/page")
        self.assertEqual(S.resolve_link("h", "?id=1"), "https://h/sp?id=1")
        self.assertEqual(S.resolve_link("h", ""), "")

    def test_shell_quote_escapes_single_quotes(self):
        self.assertEqual(S.shell_quote("it's"), "'it'\\''s'")

    def test_curl_headers_sorted(self):
        cmd = S.curl_command("GET", "https://h/x", {"B": "2", "A": "1"})
        self.assertLess(cmd.index("'A: 1'"), cmd.index("'B: 2'"))

    def test_merge_widgets_dedupes_and_sorts(self):
        merged = S.merge_widgets([S.Widget("b", "B"), S.Widget("a", "A")],
                                 [S.Widget("a", "A2")])
        self.assertEqual([w.id for w in merged], ["a", "b"])
        self.assertEqual(merged[0].name, "A2")

    def test_merge_table_candidates_sorted_by_table_then_field(self):
        merged = S.merge_table_candidates(
            [S.TableCandidate("t", "z"), S.TableCandidate("t", "a"),
             S.TableCandidate("s", "m")], None)
        self.assertEqual([(c.table, c.field) for c in merged],
                         [("s", "m"), ("t", "a"), ("t", "z")])

    def test_parse_duration(self):
        self.assertAlmostEqual(S.parse_duration("15s"), 15.0)
        self.assertAlmostEqual(S.parse_duration("200ms"), 0.2)
        self.assertAlmostEqual(S.parse_duration("2m"), 120.0)
        self.assertAlmostEqual(S.parse_duration("1.5"), 1.5)
        self.assertEqual(S.parse_duration(""), 0.0)

    def test_parse_duration_rejects_nonsense(self):
        with self.assertRaises(Exception):
            S.parse_duration("soon")

    def test_normalize_target_strips_scheme_and_slash(self):
        for raw in ("https://h.example/", "http://h.example", " h.example/ "):
            self.assertEqual(S.normalize_target(raw), "h.example")

    def test_abbreviate_and_truncate(self):
        self.assertEqual(S.abbreviate("abcdef", 3), "abc")
        self.assertEqual(S.truncate("abcdef", 3), "abc...")
        self.assertEqual(S.truncate("ab", 3), "ab")

    def test_encode_query_sorts_and_escapes(self):
        self.assertEqual(S.encode_query({"t": "a b", "f": "x&y"}), "f=x%26y&t=a+b")


# --------------------------------------------------------------------------
class TestFingerprint(unittest.TestCase):

    def test_build_tag_and_release_from_stats_do(self):
        def handler(method, url, headers, body):
            if url.endswith("/stats.do"):
                return response(200, "Build tag: glide-washingtondc-07-15-2024")
            return response(200, "")

        fp = S.fingerprint_instance(session(), FakeClient(handler), stats_do=True)
        self.assertEqual(fp.release, "Washington DC")
        self.assertIn("glide-washingtondc", fp.build_tag)
        self.assertIn("Washington DC", fp.version)

    def test_skips_stats_do_when_not_available(self):
        client = FakeClient(lambda **kw: response(200, "Build tag: zurich-1"))
        fp = S.fingerprint_instance(session(), client, stats_do=False)
        self.assertEqual(fp.build_tag, "")
        self.assertTrue(all("/stats.do" not in r["url"] for r in client.requests))

    def test_header_and_cookie_signals(self):
        def handler(method, url, headers, body):
            if method == "HEAD":
                return response(200, "", {"Server": "nginx",
                                          "Strict-Transport-Security": "max-age=1"},
                                cookies=[("glide_user_route", "x"), ("other", "y")])
            return response(404, "")

        fp = S.fingerprint_instance(session(), FakeClient(handler), stats_do=False)
        self.assertIn("header:server=nginx", fp.signals)
        self.assertIn("header:hsts=present", fp.signals)
        self.assertIn("cookie:glide_user_route", fp.signals)
        self.assertNotIn("cookie:other", fp.signals)

    def test_infer_release_known_and_unknown(self):
        self.assertEqual(S.infer_release("glide-yokohama-01"), "Yokohama")
        self.assertEqual(S.infer_release("something-else"), "")

    def test_fingerprint_survives_transport_errors(self):
        fp = S.fingerprint_instance(session(),
                                    FakeClient(lambda **kw: S.HttpError("down")),
                                    stats_do=True)
        self.assertEqual(fp.version, "")


# --------------------------------------------------------------------------
class TestSerialisation(unittest.TestCase):
    """The JSON must match the Go schema, including omitempty behaviour, or
    output from the two implementations cannot be diffed."""

    def test_table_result_uses_field_not_field_name(self):
        out = S.table_result_json(S.TableResult(table="t", field_name="f",
                                                status=S.STATUS_EXPOSED, count=1))
        self.assertIn("field", out)
        self.assertNotIn("field_name", out)
        self.assertEqual(out["field"], "f")

    def test_empty_optional_fields_omitted(self):
        out = S.widget_result_json(S.WidgetResult(id="i", name="n"))
        for key in ("sample_count", "evidence_fields", "samples", "hints",
                    "reproduction", "error"):
            self.assertNotIn(key, out, key)
        for key in ("id", "name", "status", "record_count"):
            self.assertIn(key, out, key)

    def test_oracle_hint_omitted_when_absent(self):
        repro = S.Reproduction("POST", "u", {}, "b", 200, "curl")
        self.assertNotIn("oracle_hint", S.reproduction_json(repro))
        repro.oracle_hint = "x"
        self.assertIn("oracle_hint", S.reproduction_json(repro))

    def test_target_result_omits_empty_collections(self):
        out = S.TargetResult(target="t", reachable=True, token_obtained=True).to_json()
        self.assertEqual(set(out), {"target", "reachable", "token_obtained", "stats_do"})

    def test_report_round_trips_as_json(self):
        report = S.build_report([S.TargetResult(target="t", reachable=True)], "direct", 6)
        text = json.dumps(report.to_json())
        parsed = json.loads(text)
        self.assertEqual(parsed["targets_scanned"], 1)
        self.assertEqual(parsed["targets_reachable"], 1)
        self.assertEqual(parsed["widgets_probed"], 6)
        self.assertEqual(parsed["proxy"], "direct")
        self.assertRegex(parsed["scan_time"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")

    def test_elapsed_ms_omitted_when_zero(self):
        report = S.build_report([], "direct", 0)
        self.assertNotIn("elapsed_ms", report.to_json())
        report.elapsed_ms = 5
        self.assertEqual(report.to_json()["elapsed_ms"], 5)


# --------------------------------------------------------------------------
class TestScoringAndReport(unittest.TestCase):

    def _exposed_target(self, name, count, category):
        hints = [S.Hint(category, "inferred", "r")]
        return S.TargetResult(
            target=name, reachable=True, token_obtained=True,
            widgets=[S.WidgetResult(id="w", name="w", status=S.STATUS_EXPOSED,
                                    record_count=count, hints=hints)])

    def test_credentials_outrank_pii_at_equal_volume(self):
        creds = self._exposed_target("a", 10, S.IMPACT_CREDENTIALS)
        pii = self._exposed_target("b", 10, S.IMPACT_PII)
        self.assertGreater(S.target_score(creds), S.target_score(pii))

    def test_oracle_scores_half_its_count(self):
        t = S.TargetResult(target="t", widgets=[S.WidgetResult(
            id="w", name="w", status=S.STATUS_COUNT_ORACLE, record_count=10)])
        self.assertEqual(S.target_score(t), 5)

    def test_not_exposed_scores_zero(self):
        t = S.TargetResult(target="t", widgets=[S.WidgetResult(
            id="w", name="w", status=S.STATUS_NOT_EXPOSED, record_count=99)])
        self.assertEqual(S.target_score(t), 0)

    def test_has_findings_and_errors(self):
        findings = S.build_report([self._exposed_target("a", 1, S.IMPACT_PII)], "direct", 1)
        self.assertTrue(findings.has_findings())
        self.assertFalse(findings.has_scan_errors())

        broken = S.build_report([S.TargetResult(target="b", error="unreachable: x")],
                                "direct", 1)
        self.assertFalse(broken.has_findings())
        self.assertTrue(broken.has_scan_errors())

    def test_target_has_findings_counts_table_results(self):
        t = S.TargetResult(target="t", table_findings=[
            S.TableResult(table="x", field_name="y", status=S.STATUS_EXPOSED, count=1)])
        self.assertTrue(S.target_has_findings(t))

    def test_vector_stats_aggregate_and_cap(self):
        targets = [self._exposed_target("a", 5, S.IMPACT_PII),
                   self._exposed_target("b", 7, S.IMPACT_PII)]
        stats = S.build_vector_stats(targets)
        self.assertEqual(stats[0][0], "w")
        self.assertEqual(stats[0][1], 2)      # two targets
        self.assertEqual(stats[0][2], 12)     # records summed

    def test_category_stats_count_targets_and_findings(self):
        targets = [self._exposed_target("a", 5, S.IMPACT_PII),
                   self._exposed_target("b", 7, S.IMPACT_PII)]
        stats = S.build_category_stats(targets)
        self.assertEqual(stats, [(S.IMPACT_PII, 2, 2)])

    def test_bar_len_never_zero_for_nonzero_value(self):
        self.assertEqual(S.bar_len(1, 1000, 20), 1)
        self.assertEqual(S.bar_len(0, 1000, 20), 0)
        self.assertEqual(S.bar_len(1000, 1000, 20), 20)

    def test_exposure_summary_wording(self):
        t = S.TargetResult(target="t", widgets=[
            S.WidgetResult(id="a", name="a", status=S.STATUS_EXPOSED, record_count=3),
            S.WidgetResult(id="b", name="b", status=S.STATUS_COUNT_ORACLE, record_count=4)])
        summary = S.target_exposure_summary(t)
        self.assertIn("records", summary)
        self.assertIn("count-only", summary)


# --------------------------------------------------------------------------
class TestClientBehaviour(unittest.TestCase):

    def test_rate_limit_spaces_requests(self):
        client = S.Client(rate=0.05)
        start = time.monotonic()
        for _ in range(3):
            client._throttle()
        self.assertGreaterEqual(time.monotonic() - start, 0.09)

    def test_no_rate_limit_is_immediate(self):
        client = S.Client(rate=0)
        start = time.monotonic()
        for _ in range(50):
            client._throttle()
        self.assertLess(time.monotonic() - start, 0.05)

    def test_unsupported_proxy_scheme_rejected(self):
        with self.assertRaises(S.HttpError) as ctx:
            S.Client(proxy="ftp://127.0.0.1:21")
        self.assertIn("unsupported proxy scheme", str(ctx.exception))

    def test_proxy_without_host_rejected(self):
        with self.assertRaises(S.HttpError):
            S.Client(proxy="socks5://")

    def test_http_proxy_configured_for_both_schemes(self):
        client = S.Client(proxy="http://127.0.0.1:8080")
        self.assertEqual(client.proxies,
                         {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"})

    def test_insecure_disables_verification(self):
        self.assertFalse(S.Client(insecure=True).verify)
        self.assertTrue(S.Client().verify)

    def test_sessions_are_per_thread(self):
        client = S.Client()
        seen = []

        def grab():
            seen.append(id(client._session))

        threads = [threading.Thread(target=grab) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(set(seen)), 3)

    def test_terse_unwraps_nested_exception_text(self):
        msg = S._terse(Exception(
            "HTTPSConnectionPool(host='x'): Max retries exceeded "
            "(Caused by NewConnectionError('<obj>: Failed to establish a new connection: "
            "[Errno 111] Connection refused'))"))
        self.assertIn("Connection refused", msg)
        self.assertNotIn("Max retries", msg)


# --------------------------------------------------------------------------
class TestCLI(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_version_exits_zero(self):
        self.assertEqual(S.main(["--version"]), 0)

    def test_no_targets_is_error(self):
        self.assertEqual(S.main(["--quiet"]), 1)

    def test_single_dash_flags_accepted(self):
        args = S.build_parser().parse_args(["-target", "h.example", "-fingerprint"])
        self.assertEqual(args.target, "h.example")
        self.assertTrue(args.fingerprint)

    def test_tables_defaults_on_and_can_be_disabled(self):
        self.assertTrue(S.build_parser().parse_args([]).tables)
        self.assertFalse(S.build_parser().parse_args(["--no-tables"]).tables)

    def test_targets_file_skips_comments_and_blanks(self):
        path = os.path.join(self.tmp, "hosts.txt")
        with open(path, "w") as fh:
            fh.write("# comment\n\nhttps://a.example/\nb.example\n")
        self.assertEqual(S.resolve_targets("", path), ["a.example", "b.example"])

    def test_bad_concurrency_rejected(self):
        self.assertEqual(S.main(["--target", "h", "--concurrency", "0", "--quiet"]), 1)
        self.assertEqual(S.main(["--target", "h", "--table-concurrency", "0", "--quiet"]), 1)

    def test_widgets_file_loading_and_validation(self):
        good = os.path.join(self.tmp, "w.json")
        with open(good, "w") as fh:
            json.dump([{"id": "abc123", "name": "x"}, {"id": "def456"}], fh)
        widgets = S.load_widgets_file(good)
        self.assertEqual([w.id for w in widgets], ["abc123", "def456"])
        self.assertEqual(widgets[1].name, "def456"[:8])

        bad = os.path.join(self.tmp, "bad.json")
        with open(bad, "w") as fh:
            json.dump([{"name": "no id"}], fh)
        with self.assertRaises(ValueError):
            S.load_widgets_file(bad)

    def test_tables_file_loading_and_validation(self):
        good = os.path.join(self.tmp, "t.json")
        with open(good, "w") as fh:
            json.dump([{"table": "incident", "field": "number"}], fh)
        self.assertEqual(S.load_tables_file(good)[0].table, "incident")

        bad = os.path.join(self.tmp, "badt.json")
        with open(bad, "w") as fh:
            json.dump([{"table": "incident"}], fh)
        with self.assertRaises(ValueError):
            S.load_tables_file(bad)

    def test_write_json_to_file(self):
        path = os.path.join(self.tmp, "out.json")
        S.write_json(S.build_report([], "direct", 0), path)
        with open(path) as fh:
            self.assertEqual(json.load(fh)["proxy"], "direct")

    def test_default_widget_list_matches_original(self):
        self.assertEqual(len(S.DEFAULT_WIDGETS), 6)
        self.assertEqual(S.DEFAULT_WIDGETS[0].id, "ff26f2b1db12220099f93691f0b8f5ce")
        self.assertEqual(S.DEFAULT_WIDGETS[0].name, "ticket-attachments")

    def test_default_candidate_counts_match_original(self):
        self.assertEqual(len(S.DEFAULT_TABLE_CANDIDATES), 26)
        self.assertEqual(len(S.DEFAULT_TABLE_API_TABLES), 12)


# --------------------------------------------------------------------------
class TestScanTarget(unittest.TestCase):

    def _cfg(self, client, **kw):
        base = dict(client=client, widgets=[S.Widget("w1", "ticket-attachments")],
                    table_candidates=[], enumerate_tables=False,
                    discover_widgets_limit=0, sample_count=3)
        base.update(kw)
        return S.ScanConfig(**base)

    def test_unreachable_target_records_error(self):
        client = FakeClient(lambda **kw: S.HttpError("Connection refused"))
        result = S.scan_target("h.example", self._cfg(client), S.Progress(1))
        self.assertFalse(result.reachable)
        self.assertIn("unreachable", result.error)

    def test_bootstrap_failure_recorded(self):
        def handler(method, url, headers, body):
            if url.endswith("/login.do"):
                return response(200, "no token")
            return response(200, "ok")

        result = S.scan_target("h.example", self._cfg(FakeClient(handler)), S.Progress(1))
        self.assertTrue(result.reachable)
        self.assertFalse(result.token_obtained)
        self.assertIn("bootstrap failed", result.error)

    def test_full_pass_finds_exposed_widget(self):
        def handler(method, url, headers, body):
            if url.endswith("/login.do"):
                return response(200, "g_ck = 'abc123'")
            if "/api/now/sp/widget/w1" in url:
                return response(200, EXPOSED_WIDGET_BODY)
            if url.endswith("/stats.do"):
                return response(404, "")
            return response(200, "ok")

        result = S.scan_target("h.example", self._cfg(FakeClient(handler)), S.Progress(1))
        self.assertTrue(result.token_obtained)
        self.assertEqual(result.widgets[0].status, S.STATUS_EXPOSED)
        self.assertTrue(result.widgets[0].hints)
        self.assertTrue(S.target_has_findings(result))

    def test_stats_do_detected(self):
        def handler(method, url, headers, body):
            if url.endswith("/login.do"):
                return response(200, "g_ck = 'abc123'")
            if url.endswith("/stats.do"):
                return response(200, "Build tag: zurich-1")
            return response(200, json.dumps(
                {"result": {"data": {"results": {"meta": {"count": 0}, "results": []}}}}))

        result = S.scan_target("h.example", self._cfg(FakeClient(handler)), S.Progress(1))
        self.assertTrue(result.stats_do)

    def test_cancelled_scan_returns_immediately(self):
        S.CANCELLED.set()
        try:
            client = FakeClient(lambda **kw: response(200, "g_ck = 'abc123'"))
            result = S.scan_target("h.example", self._cfg(client), S.Progress(1))
            self.assertEqual(result.error, "cancelled")
            self.assertEqual(client.requests, [])
        finally:
            S.CANCELLED.clear()

    def test_progress_line_reports_findings(self):
        prog = S.Progress(2)
        prog.done(True)
        self.assertIn("1/2", prog.line())
        self.assertIn("with findings", prog.line())
        prog2 = S.Progress(2)
        prog2.done(False)
        self.assertNotIn("with findings", prog2.line())


if __name__ == "__main__":
    unittest.main(verbosity=2)
