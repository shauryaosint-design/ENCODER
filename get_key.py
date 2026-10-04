from http.server import BaseHTTPRequestHandler
import json
import time
import hmac
import hashlib
import os
import secrets
from base64 import b64encode
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ====================== CONFIG ======================
# Yeh values Vercel Environment Variables se aayengi
MASTER_SECRET = os.environ.get("MASTER_SECRET", "CHANGE_ME_TO_VERY_LONG_RANDOM_STRING_AT_LEAST_40_CHARS").encode()
API_TOKEN = os.environ.get("API_TOKEN", "CHANGE_ME_SUPER_SECRET_API_TOKEN")
KEY_VALIDITY = 60
LICENSE_EXPIRY = 1893456000  # Year 2030 - isko change kar sakte ho
MAX_DEVICES = 5

# Simple device tracking (production mein database use karo)
ACTIVE_DEVICES = {}

def derive_master_key():
    salt = hashlib.sha256(MASTER_SECRET + b"payload_salt_v2").digest()[:16]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return b64encode(kdf.derive(MASTER_SECRET))

def verify_hmac(data: dict, signature: str) -> bool:
    msg = json.dumps(data, sort_keys=True, separators=(',', ':')).encode()
    expected = hmac.new(MASTER_SECRET, msg, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)

class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length))

            token = body.get("token")
            fingerprint = body.get("fingerprint")
            timestamp = body.get("timestamp")
            nonce = body.get("nonce")
            signature = body.get("signature")

            if token != API_TOKEN:
                return self.respond(401, {"error": "Invalid token"})

            if not all([fingerprint, timestamp, nonce, signature]):
                return self.respond(400, {"error": "Missing fields"})

            now = int(time.time())
            if abs(now - int(timestamp)) > 45:
                return self.respond(403, {"error": "Timestamp expired"})

            data = {
                "fingerprint": fingerprint,
                "timestamp": timestamp,
                "nonce": nonce
            }
            if not verify_hmac(data, signature):
                return self.respond(403, {"error": "Bad signature"})

            if now > LICENSE_EXPIRY:
                return self.respond(403, {"error": "License expired"})

            if fingerprint not in ACTIVE_DEVICES:
                if len(ACTIVE_DEVICES) >= MAX_DEVICES:
                    return self.respond(403, {"error": "Max devices reached"})
                ACTIVE_DEVICES[fingerprint] = now
            else:
                ACTIVE_DEVICES[fingerprint] = now

            real_key = derive_master_key().decode()

            response = {
                "status": "ok",
                "key": real_key,
                "expires_in": KEY_VALIDITY,
                "server_time": now
            }
            self.respond(200, response)

        except Exception as e:
            self.respond(500, {"error": "Server error"})

    def respond(self, code, data):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
