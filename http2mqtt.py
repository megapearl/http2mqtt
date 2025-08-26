#!/usr/bin/env python3
import os
import sys
import signal
import logging
import json
import urllib.parse
import http.server
import socketserver
from typing import Tuple, Dict, Any, Optional

import paho.mqtt.client as mqtt
try:
    # Paho ≥ 2.0
    from paho.mqtt.client import CallbackAPIVersion  # noqa: F401
except Exception:
    CallbackAPIVersion = None  # Paho < 2.0 fallback

# =========================
# Configuration (env vars)
# =========================
MQTT_BROKER          = os.environ.get("MQTT_BROKER", "localhost")
MQTT_PORT            = int(os.environ.get("MQTT_PORT", "1883"))
TOPIC_PREFIX         = os.environ.get("TOPIC_PREFIX", "http2mqtt/")
MQTT_CLIENT_ID       = os.environ.get("MQTT_CLIENT_ID", "http2mqtt")
MQTT_USERNAME        = os.environ.get("MQTT_USERNAME")
MQTT_PASSWORD        = os.environ.get("MQTT_PASSWORD")
MQTT_RETAIN          = bool(int(os.environ.get("MQTT_RETAIN", "1")))
MQTT_QOS             = int(os.environ.get("MQTT_QOS", "1"))
MQTT_PROTOCOL        = os.environ.get("MQTT_PROTOCOL", "3.1.1")
HTTP_IP_ADDRESS      = os.environ.get("HTTP_IP_ADDRESS", "0.0.0.0")
HTTP_PORT            = int(os.environ.get("HTTP_PORT", "8080"))
HTTP_PAYLOAD_HEADER  = os.environ.get("HTTP_PAYLOAD_HEADER", "x-payload")
API_KEY              = os.environ.get("API_KEY")  # optional; if set, require auth

# Limits (basic sanity guardrails; optional)
MAX_TOPIC_LEN        = int(os.environ.get("MAX_TOPIC_LEN", "512"))
MAX_PAYLOAD_LEN      = int(os.environ.get("MAX_PAYLOAD_LEN", "4096"))

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("http2mqtt")

# Determine MQTT protocol version constant
_proto = (MQTT_PROTOCOL or "").strip().lower()
if _proto in ("5", "5.0", "v5", "mqttv5"):
    MQTT_PROTOCOL_CONST = mqtt.MQTTv5
elif _proto in ("3.1", "3.10", "v3.1", "mqttv31"):
    MQTT_PROTOCOL_CONST = mqtt.MQTTv31
else:
    MQTT_PROTOCOL_CONST = mqtt.MQTTv311

logger.info("Using MQTT protocol version: %s", MQTT_PROTOCOL_CONST)

# Initialize persistent MQTT client
if CallbackAPIVersion is not None:  # Paho ≥ 2.0
    mqtt_client = mqtt.Client(
        client_id=MQTT_CLIENT_ID,
        protocol=MQTT_PROTOCOL_CONST,
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
    )
else:  # Paho < 2.0
    mqtt_client = mqtt.Client(client_id=MQTT_CLIENT_ID, protocol=MQTT_PROTOCOL_CONST)

if MQTT_USERNAME and MQTT_PASSWORD:
    mqtt_client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)

# Helpful reconnect backoff for flaky links
try:
    mqtt_client.reconnect_delay_set(min_delay=1, max_delay=30)
except Exception:
    pass

mqtt_client.connect(MQTT_BROKER, MQTT_PORT)
mqtt_client.loop_start()

# Naive in-memory idempotency store
_IDEMP_STORE: Dict[str, Dict[str, Any]] = {}

# =========================
# Helpers
# =========================
def publish_message(topic: str, payload: str, qos: int = MQTT_QOS, retain: bool = MQTT_RETAIN) -> None:
    """
    Publish a message to MQTT with the configured prefix.
    """
    if not topic or len(topic) > MAX_TOPIC_LEN:
        raise ValueError(f"Topic invalid/too long (max {MAX_TOPIC_LEN})")
    if payload is None or len(str(payload)) > MAX_PAYLOAD_LEN:
        raise ValueError(f"Payload missing/too long (max {MAX_PAYLOAD_LEN})")

    full_topic = f"{TOPIC_PREFIX}{topic.lstrip('/')}"
    result = mqtt_client.publish(full_topic, payload, qos=qos, retain=retain)
    if result.rc == mqtt.MQTT_ERR_SUCCESS:
        logger.info("Published to %s: %s", full_topic, payload)
    else:
        logger.error("Failed to publish (%s) to %s", result.rc, full_topic)
        raise RuntimeError(f"MQTT publish error: {result.rc}")

def coerce_bool(val: Any, default: bool = False) -> bool:
    if val is None:
        return default
    s = str(val).strip().lower()
    return s in ("1", "true", "yes", "on")

def coerce_int(val: Any, default: int) -> int:
    try:
        return int(val)
    except (TypeError, ValueError):
        return default

def make_msg_response(topic: str, payload: str, qos: int, retain: bool,
                      msg_id: Optional[str] = None, success: bool = True) -> Dict[str, Any]:
    return {
        "id": msg_id or "",
        "topic": TOPIC_PREFIX + topic.lstrip("/"),
        "payload": payload,
        "qos": qos,
        "retain": retain,
        "result": {"success": bool(success)},
    }

def require_api_key(handler: "HTTPHandler", qs: Optional[Dict[str, Any]] = None) -> bool:
    """
    Enforce API key when configured.
    - Preferred: header X-API-Key
    - Legacy GET fallback: query param 'apikey' (only for GET /v1/messages)
    """
    if not API_KEY:
        return True

    provided = handler.headers.get("X-API-Key")

    # Fallback only for GET and only via query string (legacy devices)
    if not provided and handler.command == "GET" and isinstance(qs, dict):
        provided = qs.get("apikey")

    if provided == API_KEY:
        return True

    wants_json = True
    try:
        wants_json = handler._wants_json(qs or {})
    except Exception:
        pass

    handler._set_error(401, "Unauthorized", as_json=wants_json)
    return False

def parse_json_or_form(handler: "HTTPHandler", raw_body: str):
    """
    Parse body as JSON or form; returns (data, how) where how in {"json","form"}.
    """
    ctype = (handler.headers.get("Content-Type") or "").split(";")[0].strip().lower()
    if ctype == "application/json":
        try:
            return json.loads(raw_body or "{}"), "json"
        except json.JSONDecodeError:
            handler._set_error(400, "Invalid JSON body", as_json=True)
            return None, None
    elif ctype in ("application/x-www-form-urlencoded", "multipart/form-data", ""):
        data = urllib.parse.parse_qs(raw_body or "", keep_blank_values=True)
        flat = {k: (v[-1] if isinstance(v, list) else v) for k, v in data.items()}
        return flat, "form"
    else:
        handler._set_error(415, f"Unsupported Content-Type: {ctype}", as_json=True)
        return None, None

def _html_escape(s: Any) -> str:
    return (str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;"))

def render_page(status: Optional[Dict[str, Any]] = None) -> bytes:
    """
    Return the HTML for the main page, optionally with a status banner.
    status example:
      {"ok": True/False, "title": "...", "details": {...}}
    """
    banner = ""
    if status is not None:
        cls = "ok" if status.get("ok") else "err"
        title = _html_escape(status.get("title", ""))
        details = status.get("details", {})
        items = "".join(
            f"<li><strong>{_html_escape(k)}:</strong> <code>{_html_escape(v)}</code></li>"
            for k, v in details.items()
        )
        banner = f"""
        <div class="banner {cls}">
          <div class="banner-title">{title}</div>
          <ul class="details">{items}</ul>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>HTTP → MQTT Bridge</title>
  <style>
    body {{ font-family: Arial, sans-serif; background: #f4f4f4; color: #333; }}
    .container {{ max-width: 620px; margin: 40px auto; background: #fff; padding: 22px; border-radius: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.08); }}
    h1 {{ text-align: center; font-size: 1.6em; margin-top: 0; }}
    label {{ display: block; margin-top: 14px; font-weight: 600; }}
    input[type=text], input[type=number] {{ width: 100%; padding: 9px; margin-top: 6px; box-sizing: border-box; border:1px solid #ddd; border-radius:8px; }}
    input[type=checkbox] {{ margin-top: 10px; }}
    button {{ margin-top: 20px; width: 100%; padding: 12px; background: #007BFF; color: #fff; border: none; border-radius: 8px; font-size: 1em; cursor: pointer; }}
    button:hover {{ background: #0056b3; }}
    .info {{ font-size: 0.9em; color: #555; margin-bottom: 10px; }}
    .banner {{ border-radius: 10px; padding: 12px 14px; margin-bottom: 12px; }}
    .banner.ok {{ background: #e8f5e9; border: 1px solid #c8e6c9; }}
    .banner.err {{ background: #ffebee; border: 1px solid #ffcdd2; }}
    .banner-title {{ font-weight: 700; margin-bottom: 6px; }}
    .details {{ margin: 0; padding-left: 18px; }}
    .footer {{ margin-top: 12px; text-align: center; font-size:.9em; color:#666; }}
    code {{ background:#f6f6f6; padding:2px 5px; border-radius:6px; white-space: nowrap; }}
    pre code {{ white-space: pre; }}
  </style>
</head>
<body>
  <div class="container">
    <h1>HTTP → MQTT Bridge</h1>
    <p class="info">Topic Prefix: <code>{_html_escape(TOPIC_PREFIX)}</code></p>
    {banner}
    <form method="post" action="/publish">
      <label>Topic:<input type="text" name="topic" placeholder="e.g. home/sensor/temp" required></label>
      <label>Payload:<input type="text" name="payload" placeholder="e.g. 23.5" required></label>
      <label>QoS:<input type="number" name="qos" min="0" max="2" value="{MQTT_QOS}" required></label>
      <label><input type="checkbox" name="retain" {'checked' if MQTT_RETAIN else ''}> Retain message</label>
      <button type="submit">Publish</button>
    </form>
    <div class="footer">
      Legacy GET is supported for old devices:
      <code>/v1/messages?topic=...&amp;payload=...&amp;qos=0..2&amp;retain=0|1</code>
    </div>
  </div>
</body>
</html>"""
    return html.encode("utf-8")

SECURE_DEFAULT_HEADERS = {
    # Basic security hygiene for a simple app
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    # Minimal CSP: allow inline styles (since CSS is inline here); no scripts
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; form-action 'self'",
}

# =========================
# HTTP server
# =========================
class HTTPHandler(http.server.BaseHTTPRequestHandler):
    server_version = "http2mqtt/1.0"
    sys_version = ""  # don’t leak Python version

    # --- utility responses ---
    def _set_response(self, status: int = 200, headers: Optional[Dict[str, str]] = None, body: bytes = b""):
        self.send_response(status)
        hdrs = dict(SECURE_DEFAULT_HEADERS)
        if headers:
            hdrs.update(headers)
        for k, v in hdrs.items():
            self.send_header(k, v)
        if "Content-Length" not in hdrs:
            self.send_header("Content-Length", str(len(body)))
        try:
            self.end_headers()
        except ConnectionResetError:
            return
        if body:
            try:
                self.wfile.write(body)
            except ConnectionResetError:
                pass

    def _set_error(self, status: int, message: str, as_json: bool = False):
        if as_json:
            payload = json.dumps({"error": message}).encode("utf-8")
            self._set_response(status, {"Content-Type": "application/json; charset=utf-8"}, payload)
        else:
            body = render_page({"ok": False, "title": f"Error {status}", "details": {"message": message}})
            self._set_response(status, {"Content-Type": "text/html; charset=utf-8"}, body)

    def _wants_json(self, container: Dict[str, Any]) -> bool:
        # If query/form has format=json OR Accept header asks for JSON
        if "format" in container and str(container["format"]).lower() == "json":
            return True
        accept = self.headers.get("Accept", "")
        return "application/json" in accept and "text/html" not in accept

    def _parse_query(self, path: str) -> Tuple[urllib.parse.ParseResult, Dict[str, Any]]:
        """
        Tolerant query parsing: converts extra '?' to '&' so buggy URLs like
        /?topic=foo?payload=bar become /?topic=foo&payload=bar
        """
        parsed = urllib.parse.urlparse(path)
        q = parsed.query.replace("?", "&")
        qs = urllib.parse.parse_qs(q, keep_blank_values=True)
        flat = {k: (v[0] if isinstance(v, list) and v else "") for k, v in qs.items()}
        return parsed, flat

    # --- GET ---
    def do_GET(self):
        parsed, qs = self._parse_query(self.path)
        path = parsed.path

        # HTML UI
        if path == "/":
            self._set_response(200, {"Content-Type": "text/html; charset=utf-8"}, render_page())
            return

        # Health
        if path == "/v1/health":
            self._set_response(200, {"Content-Type": "application/json; charset=utf-8"},
                               json.dumps({"status": "ok"}).encode("utf-8"))
            return

        # Config
        if path == "/v1/config":
            cfg = {"topic_prefix": TOPIC_PREFIX, "qos_default": MQTT_QOS, "retain_default": MQTT_RETAIN}
            self._set_response(200, {"Content-Type": "application/json; charset=utf-8"},
                               json.dumps(cfg).encode("utf-8"))
            return

        # Favicon
        if path == "/favicon.ico":
            self._set_response(204)
            return

        # Legacy GET publish (for old SIP phones)
        if path == "/v1/messages" and "topic" in qs and "payload" in qs:
            if not require_api_key(self, qs):
                return
            topic   = (qs.get("topic") or "").strip()
            payload = qs.get("payload")
            qos     = coerce_int(qs.get("qos"), MQTT_QOS)
            retain  = coerce_bool(qs.get("retain"), MQTT_RETAIN)

            if not topic or payload is None or payload == "":
                self._set_error(400, "Fields 'topic' and 'payload' are required.", as_json=self._wants_json(qs))
                return

            try:
                publish_message(topic, str(payload), qos, retain)
                response = make_msg_response(topic, str(payload), qos, retain, success=True)
                if self._wants_json(qs):
                    self._set_response(200, {"Content-Type": "application/json; charset=utf-8"},
                                       json.dumps(response).encode("utf-8"))
                else:
                    status = {"ok": True, "title": "MQTT publish succeeded (via GET)", "details": response}
                    self._set_response(200, {"Content-Type": "text/html; charset=utf-8"}, render_page(status))
            except Exception as e:
                self._set_error(500, str(e), as_json=self._wants_json(qs))
            return

        # Not found
        self._set_error(404, "Not found", as_json=True)

    # --- POST ---
    def do_POST(self):
        # For POST, header auth only (no query fallback)
        if not require_api_key(self, None):
            return

        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8")

        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # Idempotency
        idem_key = self.headers.get("Idempotency-Key")
        if idem_key and idem_key in _IDEMP_STORE:
            prior = _IDEMP_STORE[idem_key]
            self._set_response(201, {"Content-Type": "application/json; charset=utf-8"},
                               json.dumps(prior).encode("utf-8"))
            return

        data, how = parse_json_or_form(self, raw)
        if data is None:
            return  # error already returned

        # Allow payload via header override
        header_payload = self.headers.get(HTTP_PAYLOAD_HEADER)
        if header_payload is not None:
            data["payload"] = header_payload

        # Route: POST /v1/messages
        if path == "/v1/messages":
            topic = (str(data.get("topic") or "")).strip()
            payload = data.get("payload")
            qos = coerce_int(data.get("qos"), MQTT_QOS)
            retain = coerce_bool(data.get("retain"), MQTT_RETAIN)

            if not topic or payload is None or str(payload) == "":
                self._set_error(400, "Fields 'topic' and 'payload' are required.", as_json=True)
                return

            try:
                publish_message(topic, str(payload), qos, retain)
                msg_id = os.urandom(8).hex()
                result = make_msg_response(topic, str(payload), qos, retain, msg_id=msg_id, success=True)
                if idem_key:
                    _IDEMP_STORE[idem_key] = result
                self._set_response(201, {"Content-Type": "application/json; charset=utf-8"},
                                   json.dumps(result).encode("utf-8"))
            except Exception as e:
                self._set_error(500, str(e), as_json=True)
            return

        # Route: POST /v1/topics/{topic}/messages
        prefix = "/v1/topics/"
        suffix = "/messages"
        if path.startswith(prefix) and path.endswith(suffix) and len(path) > len(prefix) + len(suffix):
            topic_enc = path[len(prefix):-len(suffix)]
            topic = urllib.parse.unquote(topic_enc).strip("/")
            payload = data.get("payload")
            qos = coerce_int(data.get("qos"), MQTT_QOS)
            retain = coerce_bool(data.get("retain"), MQTT_RETAIN)

            if not topic or payload is None or str(payload) == "":
                self._set_error(400, "Path topic and body 'payload' are required.", as_json=True)
                return

            try:
                publish_message(topic, str(payload), qos, retain)
                msg_id = os.urandom(8).hex()
                result = make_msg_response(topic, str(payload), qos, retain, msg_id=msg_id, success=True)
                if idem_key:
                    _IDEMP_STORE[idem_key] = result
                self._set_response(201, {"Content-Type": "application/json; charset=utf-8"},
                                   json.dumps(result).encode("utf-8"))
            except Exception as e:
                self._set_error(500, str(e), as_json=True)
            return

        # UI convenience: /publish from HTML form (renders banner)
        if path == "/publish":
            topic = (str(data.get("topic") or "")).strip()
            payload = data.get("payload")
            qos = coerce_int(data.get("qos"), MQTT_QOS)
            retain = ("retain" in data) if how == "form" else coerce_bool(data.get("retain"), MQTT_RETAIN)

            if not topic or payload is None or str(payload) == "":
                self._set_response(
                    400,
                    {"Content-Type": "text/html; charset=utf-8"},
                    render_page({"ok": False, "title": "Validation error", "details": {"topic": topic, "payload": payload}}),
                )
                return
            try:
                publish_message(topic, str(payload), qos, retain)
                status = {"ok": True, "title": "MQTT publish succeeded",
                          "details": make_msg_response(topic, str(payload), qos, retain)}
                self._set_response(200, {"Content-Type": "text/html; charset=utf-8"}, render_page(status))
            except Exception as e:
                self._set_response(500, {"Content-Type": "text/html; charset=utf-8"},
                                   render_page({"ok": False, "title": "Publish failed", "details": {"error": str(e)}}))
            return

        # Not found
        self._set_error(404, "Not found", as_json=True)

class ThreadedHTTPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

def run():
    server = ThreadedHTTPServer((HTTP_IP_ADDRESS, HTTP_PORT), HTTPHandler)
    logger.info(f"HTTP server is running on {HTTP_IP_ADDRESS}:{HTTP_PORT}")

    def shutdown_handler(signum, frame):
        logger.info("Shutting down server and MQTT client...")
        try:
            server.shutdown()
        except Exception:
            pass
        mqtt_client.loop_stop()
        try:
            mqtt_client.disconnect()
        except Exception:
            pass
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)
    server.serve_forever()

if __name__ == "__main__":
    run()
