#!/usr/bin/env python3
"""
Local PCCS Proxy — drop-in replacement for Phala's collateral endpoint.

Accepts TDX quotes (hex-encoded, via multipart form POST) and returns
Intel attestation collateral by querying the local Intel PCCS service.

API contract (matches Phala):
  POST /api/v1/attestations/verify
  Content-Type: multipart/form-data
  Field: hex=<TDX quote in hex>

  Response 200:
  {
    "quote_collateral": {
      "tcb_info_issuer_chain": "<PEM>",
      "tcb_info": "<JSON string>",
      "tcb_info_signature": "<hex>",
      "qe_identity_issuer_chain": "<PEM>",
      "qe_identity": "<JSON string>",
      "qe_identity_signature": "<hex>",
      "pck_crl_issuer_chain": "<PEM>",
      "root_ca_crl": "<hex>",
      "pck_crl": "<hex>",
      "pck_certificate_chain": "<PEM>"
    }
  }

Usage:
  python3 scripts/local-pccs-proxy.py [--port 8082] [--pccs-url https://localhost:8081]
"""

import argparse
import http.server
import json
import ssl
import struct
import subprocess
import sys
import tempfile
import os
from http import HTTPStatus
from urllib.request import Request, urlopen
from urllib.parse import unquote


PCCS_BASE_URL = "https://localhost:8081"
LISTEN_PORT = 8082


def make_pccs_request(path):
    """Make a request to the local PCCS, returning (body_bytes, headers_dict)."""
    url = f"{PCCS_BASE_URL}{path}"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = Request(url)
    resp = urlopen(req, context=ctx, timeout=30)
    body = resp.read()
    headers = {k: v for k, v in resp.getheaders()}
    return body, headers


def extract_fmspc_and_ca_from_quote(quote_hex):
    """Parse a TDX quote (hex string) to extract FMSPC and CA type from the embedded PCK cert."""
    quote_bytes = bytes.fromhex(quote_hex)

    # Verify this is a TDX quote (version 4, TEE type 0x81)
    version = struct.unpack_from("<H", quote_bytes, 0)[0]
    tee_type = struct.unpack_from("<I", quote_bytes, 4)[0]
    if version != 4:
        raise ValueError(f"Unsupported quote version: {version} (expected 4)")
    if tee_type != 0x81:
        raise ValueError(f"Not a TDX quote: TEE type {tee_type:#x} (expected 0x81)")

    # Navigate to certification data:
    # Header(48) + TD Report Body(584) = 632 bytes
    # Then: sig_data_len(4) + signature(64) + attestation_key(64) + cert_data_type(2) + cert_data_size(4)
    cert_data_type_offset = 636 + 64 + 64
    cert_data_type = struct.unpack_from("<H", quote_bytes, cert_data_type_offset)[0]
    cert_data_size = struct.unpack_from("<I", quote_bytes, cert_data_type_offset + 2)[0]
    cert_data_start = cert_data_type_offset + 6
    cert_data = quote_bytes[cert_data_start : cert_data_start + cert_data_size]

    if cert_data_type == 5:
        # Type 5: PCK cert chain directly
        pem_chain = cert_data.decode("utf-8")
    elif cert_data_type == 6:
        # Type 6: QE Report Certification Data
        # QE Report(384) + QE Report Sig(64) + QE Auth Size(2) + QE Auth Data(var)
        # + inner cert type(2) + inner cert size(4) + inner cert data
        qe_auth_data_size = struct.unpack_from("<H", cert_data, 448)[0]
        inner_offset = 450 + qe_auth_data_size
        inner_cert_type = struct.unpack_from("<H", cert_data, inner_offset)[0]
        inner_cert_size = struct.unpack_from("<I", cert_data, inner_offset + 2)[0]
        if inner_cert_type != 5:
            raise ValueError(f"Unexpected inner cert type: {inner_cert_type}")
        pem_chain = cert_data[
            inner_offset + 6 : inner_offset + 6 + inner_cert_size
        ].decode("utf-8")
    else:
        raise ValueError(f"Unsupported certification data type: {cert_data_type}")

    # Extract first cert (PCK cert) and convert to DER to find FMSPC
    first_cert_end = pem_chain.find("-----END CERTIFICATE-----") + len(
        "-----END CERTIFICATE-----"
    )
    first_cert = pem_chain[:first_cert_end]

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".pem", delete=False
    ) as tmpf:
        tmpf.write(first_cert)
        tmpfile = tmpf.name

    try:
        result = subprocess.run(
            ["openssl", "x509", "-in", tmpfile, "-outform", "DER"],
            capture_output=True,
        )
        der = result.stdout
    finally:
        os.unlink(tmpfile)

    # Find FMSPC in DER: OID 1.2.840.113741.1.13.1.4
    base_oid = bytes.fromhex("2a864886f84d010d01")  # 1.2.840.113741.1.13.1
    fmspc = None
    pos = 0
    while True:
        idx = der.find(base_oid, pos)
        if idx < 0:
            break
        sub_oid_byte = der[idx + len(base_oid)]
        if sub_oid_byte == 0x04:  # .4 = FMSPC
            after_oid = der[idx + len(base_oid) + 1 :]
            for j in range(min(20, len(after_oid) - 1)):
                if after_oid[j] == 0x04 and after_oid[j + 1] == 0x06:
                    fmspc = after_oid[j + 2 : j + 8].hex()
                    break
            if fmspc:
                break
        pos = idx + 1

    if not fmspc:
        raise ValueError("Could not extract FMSPC from PCK certificate")

    # Determine CA type from intermediate cert subject
    second_cert_start = first_cert_end + 1
    second_cert_end = pem_chain.find(
        "-----END CERTIFICATE-----", second_cert_start
    ) + len("-----END CERTIFICATE-----")
    second_cert = pem_chain[second_cert_start:second_cert_end].strip()

    ca_type = "platform"  # default
    if "Processor" in second_cert or "processor" in second_cert:
        ca_type = "processor"
    else:
        # Double check via openssl
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".pem", delete=False
        ) as tmpf:
            tmpf.write(second_cert)
            tmpfile = tmpf.name
        try:
            result = subprocess.run(
                ["openssl", "x509", "-in", tmpfile, "-subject", "-noout"],
                capture_output=True,
                text=True,
            )
            if "Processor" in result.stdout:
                ca_type = "processor"
        finally:
            os.unlink(tmpfile)

    return fmspc, ca_type, pem_chain


def get_collateral(quote_hex):
    """Fetch all collateral pieces from the local PCCS for the given TDX quote."""
    fmspc, ca_type, pck_cert_chain = extract_fmspc_and_ca_from_quote(quote_hex)

    print(f"  FMSPC: {fmspc}, CA type: {ca_type}")

    # 1. TDX TCB Info
    tcb_body, tcb_headers = make_pccs_request(
        f"/tdx/certification/v4/tcb?fmspc={fmspc}"
    )
    tcb_json = json.loads(tcb_body)
    tcb_info = json.dumps(tcb_json["tcbInfo"], separators=(",", ":"))
    tcb_info_signature = tcb_json["signature"]
    tcb_info_issuer_chain = unquote(tcb_headers.get("TCB-Info-Issuer-Chain", ""))

    # 2. QE Identity (TDX)
    qe_body, qe_headers = make_pccs_request("/tdx/certification/v4/qe/identity")
    qe_json = json.loads(qe_body)
    qe_identity = json.dumps(qe_json["enclaveIdentity"], separators=(",", ":"))
    qe_identity_signature = qe_json["signature"]
    qe_identity_issuer_chain = unquote(qe_headers.get("SGX-Enclave-Identity-Issuer-Chain", ""))

    # 3. PCK CRL (PCCS returns hex-encoded DER as text)
    pck_crl_body, pck_crl_headers = make_pccs_request(
        f"/sgx/certification/v4/pckcrl?ca={ca_type}"
    )
    pck_crl_hex = pck_crl_body.decode("utf-8")
    pck_crl_issuer_chain = unquote(pck_crl_headers.get("SGX-PCK-CRL-Issuer-Chain", ""))

    # 4. Root CA CRL (PCCS returns hex-encoded DER as text)
    root_crl_body, _ = make_pccs_request("/sgx/certification/v4/rootcacrl")
    root_ca_crl_hex = root_crl_body.decode("utf-8")

    return {
        "quote_collateral": {
            "tcb_info_issuer_chain": tcb_info_issuer_chain,
            "tcb_info": tcb_info,
            "tcb_info_signature": tcb_info_signature,
            "qe_identity_issuer_chain": qe_identity_issuer_chain,
            "qe_identity": qe_identity,
            "qe_identity_signature": qe_identity_signature,
            "pck_crl_issuer_chain": pck_crl_issuer_chain,
            "root_ca_crl": root_ca_crl_hex,
            "pck_crl": pck_crl_hex,
            "pck_certificate_chain": pck_cert_chain,
        }
    }


def parse_multipart(content_type, body):
    """Minimal multipart/form-data parser to extract the 'hex' field."""
    # Extract boundary from content-type header
    for part in content_type.split(";"):
        part = part.strip()
        if part.startswith("boundary="):
            boundary = part[len("boundary=") :]
            # Remove quotes if present
            if boundary.startswith('"') and boundary.endswith('"'):
                boundary = boundary[1:-1]
            break
    else:
        raise ValueError("No boundary found in Content-Type")

    boundary_bytes = boundary.encode("utf-8")
    delimiter = b"--" + boundary_bytes

    parts = body.split(delimiter)
    for part in parts:
        if b"Content-Disposition:" not in part and b"content-disposition:" not in part:
            continue
        # Split headers from body
        header_end = part.find(b"\r\n\r\n")
        if header_end < 0:
            continue
        headers_section = part[:header_end].decode("utf-8", errors="replace")
        part_body = part[header_end + 4 :]
        # Remove trailing \r\n
        if part_body.endswith(b"\r\n"):
            part_body = part_body[:-2]

        if 'name="hex"' in headers_section or "name=hex" in headers_section:
            return part_body.decode("utf-8").strip()

    raise ValueError("'hex' field not found in multipart form data")


class CollateralHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/api/v1/attestations/verify":
            self.send_error(HTTPStatus.NOT_FOUND, "Not found")
            return

        content_type = self.headers.get("Content-Type", "")
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        try:
            if "multipart/form-data" in content_type:
                quote_hex = parse_multipart(content_type, body)
            elif "application/x-www-form-urlencoded" in content_type:
                # Also support URL-encoded form: hex=<value>
                decoded = body.decode("utf-8")
                for field in decoded.split("&"):
                    if field.startswith("hex="):
                        quote_hex = field[4:]
                        break
                else:
                    raise ValueError("'hex' field not found")
            elif "application/json" in content_type:
                data = json.loads(body)
                quote_hex = data.get("hex", "")
            else:
                # Try to parse as raw hex
                quote_hex = body.decode("utf-8").strip()

            if not quote_hex:
                raise ValueError("Empty quote")

            print(f"Received quote ({len(quote_hex)} hex chars)")
            collateral = get_collateral(quote_hex)

            response_body = json.dumps(collateral).encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response_body)))
            self.end_headers()
            self.wfile.write(response_body)
            print("  Collateral returned successfully")

        except Exception as e:
            print(f"  Error: {e}", file=sys.stderr)
            error_body = json.dumps({"error": str(e)}).encode("utf-8")
            self.send_response(HTTPStatus.INTERNAL_SERVER_ERROR)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(error_body)))
            self.end_headers()
            self.wfile.write(error_body)

    def do_GET(self):
        """Health check endpoint."""
        if self.path == "/health":
            body = json.dumps({"status": "ok"}).encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_error(HTTPStatus.NOT_FOUND, "Not found")

    def log_message(self, format, *args):
        print(f"[{self.log_date_time_string()}] {format % args}")


def main():
    global PCCS_BASE_URL, LISTEN_PORT

    parser = argparse.ArgumentParser(
        description="Local PCCS proxy — Phala-compatible collateral endpoint"
    )
    parser.add_argument(
        "--port", type=int, default=8082, help="Port to listen on (default: 8082)"
    )
    parser.add_argument(
        "--pccs-url",
        default="https://localhost:8081",
        help="URL of the local Intel PCCS (default: https://localhost:8081)",
    )
    parser.add_argument(
        "--bind",
        default="0.0.0.0",
        help="Address to bind to (default: 0.0.0.0)",
    )
    args = parser.parse_args()

    PCCS_BASE_URL = args.pccs_url.rstrip("/")
    LISTEN_PORT = args.port

    server = http.server.HTTPServer((args.bind, args.port), CollateralHandler)
    print(f"Local PCCS proxy listening on {args.bind}:{args.port}")
    print(f"Upstream PCCS: {PCCS_BASE_URL}")
    print("Endpoint: POST /api/v1/attestations/verify")
    print("Health:   GET  /health")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.server_close()


if __name__ == "__main__":
    main()
