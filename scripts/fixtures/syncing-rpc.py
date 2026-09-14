"""HTTP startup fixture; deliberately never advertises a synchronized chain."""

import json
from http.server import BaseHTTPRequestHandler, HTTPServer

ZERO_HASH = "11111111111111111111111111111111"
STATUS = {
    "version": {"version": "smoke", "build": "smoke", "commit": "smoke"},
    "chain_id": "smoke",
    "protocol_version": 86,
    "latest_protocol_version": 86,
    "validators": [],
    "sync_info": {
        "latest_block_hash": ZERO_HASH,
        "latest_block_height": 0,
        "latest_state_root": ZERO_HASH,
        "latest_block_time": "2026-01-01T00:00:00Z",
        "syncing": True,
        "earliest_block_time": None,
    },
    "node_public_key": "ed25519:" + ZERO_HASH,
    "uptime_sec": 0,
    "genesis_hash": ZERO_HASH,
}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        response = {"jsonrpc": "2.0", "id": request.get("id")}
        if request.get("method") == "status":
            print("RPC status request", flush=True)
            response["result"] = STATUS
        else:
            response["error"] = {"code": -32601, "message": "Method not found"}
        body = json.dumps(response).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 3030), Handler).serve_forever()
