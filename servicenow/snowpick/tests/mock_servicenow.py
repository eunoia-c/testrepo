"""Mock ServiceNow instance for integration-testing the real HTTP transport.

The unit tests use a fake client and never touch a socket, so they prove the
logic but not the wire. This serves the response shapes the Go implementation
expects, over TLS, and rejects any request whose X-UserToken or session cookie
is wrong -- so a run against it proves the headers actually go out correctly.

It is reconstructed from the Go source, not from a real instance. Passing here
means the port matches the original's expectations; it does not prove a real
ServiceNow instance responds this way.

    openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
        -days 1 -nodes -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost"
    python3 tests/mock_servicenow.py . 8443 &
    python3 snowpick.py --target localhost:8443 --insecure --fingerprint --table-api
"""
import http.server, json, ssl, sys, threading

WIDGET_EXPOSED = "ff26f2b1db12220099f93691f0b8f5ce"

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a): pass

    def _send(self, code, body=b"", ctype="application/json", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Server", "nginx-mock")
        self.send_header("Strict-Transport-Security", "max-age=1")
        self.send_header("Set-Cookie", "glide_user_route=abc; Path=/")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        if self.path == "/":
            return self._send(200, b"ok", "text/plain")
        if self.path == "/login.do":
            body = b"<html><script>window.g_ck = 'aa11bb22cc33dd44';</script></html>"
            return self._send(200, body, "text/html",
                              {"Set-Cookie": "JSESSIONID=MOCKSESSION; Path=/"})
        if self.path == "/stats.do":
            return self._send(200, b"Build tag: glide-zurich-06-01-2026", "text/plain")
        if self.path.startswith("/api/now/table/sys_user"):
            body = json.dumps({"result": [
                {"sys_id": "u1", "name": "Alice Example", "email": "alice@corp.example"},
                {"sys_id": "u2", "name": "Bob Example", "email": "bob@corp.example"}]}).encode()
            return self._send(200, body, extra={"X-Total-Count": "8123"})
        if self.path.startswith("/api/now/table/"):
            return self._send(403, b'{"error":"denied"}')
        self._send(404, b'{"error":"not found"}')

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        if self.headers.get("X-UserToken") != "aa11bb22cc33dd44":
            return self._send(200, json.dumps({"result": {"invalid_token": True}}).encode())
        if "JSESSIONID=MOCKSESSION" not in (self.headers.get("Cookie") or ""):
            return self._send(200, json.dumps({"result": {"invalid_token": True}}).encode())

        if self.path.startswith("/api/now/sp/widget/" + WIDGET_EXPOSED):
            end = json.loads(raw).get("payload", {}).get("end", 1)
            rows = [{"title": "INC%04d" % i, "sys_id": {"display_value": "sid%d" % i},
                     "short_description": "contact ops@corp.example"} for i in range(end)]
            return self._send(200, json.dumps({"result": {"data": {"results": {
                "meta": {"count": 1372, "returned_results": len(rows),
                         "has_more_results": True}, "results": rows}}}}).encode())

        if self.path.startswith("/api/now/sp/widget/widget-simple-list"):
            if "t=sys_user" in self.path:
                return self._send(200, json.dumps({"result": {"data": {"count": 4400, "list": [
                    {"sys_id": "u1", "display_field": {"display_value": "alice@corp.example"}}]}}}).encode())
            if "t=incident" in self.path:   # count oracle: count, no rows
                return self._send(200, json.dumps(
                    {"result": {"data": {"count": 91, "list": []}}}).encode())
            return self._send(200, json.dumps(
                {"result": {"data": {"count": 0, "list": []}}}).encode())

        if self.path.startswith("/api/now/sp/widget/"):
            return self._send(200, json.dumps({"result": {"data": {"results": {
                "meta": {"count": 0}, "results": []}}}}).encode())
        self._send(404, b'{"error":"no widget"}')


if __name__ == "__main__":
    certdir = sys.argv[1]
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[2])), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certdir + "/cert.pem", certdir + "/key.pem")
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    srv.serve_forever()
