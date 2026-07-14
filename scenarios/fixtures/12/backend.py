#!/usr/bin/env python3
import json
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length < 1 or length > 262144:
            self.send_error(400)
            return
        review = json.loads(self.rfile.read(length))
        images = review.get("spec", {}).get("containers", [])
        allowed = all("danger-danger" not in item.get("image", "") for item in images)
        response = {
            "apiVersion": "imagepolicy.k8s.io/v1alpha1",
            "kind": "ImageReview",
            "status": {"allowed": allowed, "reason": "danger-danger images are denied" if not allowed else "allowed"},
        }
        payload = json.dumps(response, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):
        print(format % args, flush=True)


server = ThreadingHTTPServer(("0.0.0.0", 9443), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain("/var/lib/cks-simulator/scenarios/12/tls.crt", "/var/lib/cks-simulator/scenarios/12/tls.key")
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
