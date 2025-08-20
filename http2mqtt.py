#!/usr/bin/env python3
import os
import sys
import signal
import logging
import json
import urllib.parse
import http.server
import socketserver

import paho.mqtt.client as mqtt

# Configuration from environment variables
MQTT_BROKER         = os.environ.get("MQTT_BROKER", "localhost")
MQTT_PORT           = int(os.environ.get("MQTT_PORT", "1883"))
TOPIC_PREFIX        = os.environ.get("TOPIC_PREFIX", "http2mqtt/")
MQTT_CLIENT_ID      = os.environ.get("MQTT_CLIENT_ID", "http2mqtt")
MQTT_USERNAME       = os.environ.get("MQTT_USERNAME")
MQTT_PASSWORD       = os.environ.get("MQTT_PASSWORD")
MQTT_RETAIN         = bool(int(os.environ.get("MQTT_RETAIN", "1")))
MQTT_QOS            = int(os.environ.get("MQTT_QOS", "1"))
MQTT_PROTOCOL       = os.environ.get("MQTT_PROTOCOL", "3.1.1")
HTTP_IP_ADDRESS     = os.environ.get("HTTP_IP_ADDRESS", "0.0.0.0")
HTTP_PORT           = int(os.environ.get("HTTP_PORT", "8080"))
HTTP_PAYLOAD_HEADER = os.environ.get("HTTP_PAYLOAD_HEADER", "x-payload")

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)

# Determine MQTT protocol version constant
_proto = MQTT_PROTOCOL.strip().lower()
if _proto in ("5", "5.0", "v5", "mqttv5"):
    MQTT_PROTOCOL = mqtt.MQTTv5
elif _proto in ("3.1", "3.10", "v3.1", "mqttv31"):
    MQTT_PROTOCOL = mqtt.MQTTv31
else:
    MQTT_PROTOCOL = mqtt.MQTTv311

logger.info("Using MQTT protocol version: %s", MQTT_PROTOCOL)

# Initialize persistent MQTT client
mqtt_client = mqtt.Client(client_id=MQTT_CLIENT_ID, protocol=MQTT_PROTOCOL)
if MQTT_USERNAME and MQTT_PASSWORD:
    mqtt_client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)
mqtt_client.connect(MQTT_BROKER, MQTT_PORT)
mqtt_client.loop_start()

def publish_message(topic: str, payload: str, qos: int = MQTT_QOS, retain: bool = MQTT_RETAIN) -> None:
    """
    Publish a message to MQTT with the configured prefix.
    """
    full_topic = f"{TOPIC_PREFIX}{topic.lstrip('/')}"
    result = mqtt_client.publish(full_topic, payload, qos=qos, retain=retain)
    if result.rc == mqtt.MQTT_ERR_SUCCESS:
        logger.info("Published to %s: %s", full_topic, payload)
    else:
        logger.error("Failed to publish (%s) to %s", result.rc, full_topic)
        raise RuntimeError(f"MQTT publish error: {result.rc}")

def render_page(status=None):
    """
    Return the HTML for the main page, optionally with a status banner.
    Status should be a dict like:
      {"ok": True/False, "title": "...", "details": {...} }
    """
    banner = ""
    if status is not None:
        cls = "ok" if status.get("ok") else "err"
        title = status.get("title", "")
        details = status.get("details", {})
        # Build a small details list
        items = "".join(
            f"<li><strong>{k}:</strong> <code>{str(v)}</code></li>"
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
    .container {{ max-width: 560px; margin: 40px auto; background: #fff; padding: 22px; border-radius: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.08); }}
    h1 {{ text-align: center; font-size: 1.5em; margin-top: 0; }}
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
    code {{ background:#f6f6f6; padding:2px 5px; border-radius:6px; }}
  </style>
</head>
<body>
  <div class="container">
    <h1>HTTP → MQTT Bridge</h1>
    <p class="info">Topic Prefix: <code>{TOPIC_PREFIX}</code></p>
    {banner}
    <form method="post" action="/publish">
      <label>Topic:<input type="text" name="topic" placeholder="e.g. home/sensor/temp" required></label>
      <label>Payload:<input type="text" name="payload" placeholder="e.g. 23.5" required></label>
      <label>QoS:<input type="number" name="qos" min="0" max="2" value="{MQTT_QOS}" required></label>
      <label><input type="checkbox" name="retain" {'checked' if MQTT_RETAIN else ''}> Retain message</label>
      <button type="submit">Publish</button>
    </form>
    <div class="footer">You can also publish via GET: <code>/?topic=...&amp;payload=...&amp;qos=0..2&amp;retain=0|1</code></div>
  </div>
</body>
</html>"""
    return html.encode('utf-8')

class HTTPHandler(http.server.BaseHTTPRequestHandler):
    def _set_response(self, status=200, headers=None, body=b""):
        self.send_response(status)
        headers = headers or {}
        for k, v in headers.items():
            self.send_header(k, v)
        if 'Content-Length' not in headers:
            self.send_header('Content-Length', str(len(body)))
        try:
            self.end_headers()
        except ConnectionResetError:
            return
        if body:
            try:
                self.wfile.write(body)
            except ConnectionResetError:
                pass

    def _set_error(self, status, message, as_json=False):
        if as_json:
            payload = json.dumps({"error": message}).encode('utf-8')
            self._set_response(status, {'Content-Type': 'application/json'}, payload)
        else:
            body = render_page({
                "ok": False,
                "title": f"Error {status}",
                "details": {"message": message}
            })
            self._set_response(status, {'Content-Type': 'text/html; charset=utf-8'}, body)

    def _wants_json(self, qs):
        if 'format' in qs and qs['format'][0].lower() == 'json':
            return True
        accept = self.headers.get('Accept', '')
        return 'application/json' in accept

    def _parse_query(self, path):
        # Be tolerant of multiple '?' by turning extras into '&'
        # Example bad URL: /?topic=foo?payload=bar   ->  /?topic=foo&payload=bar
        parsed = urllib.parse.urlparse(path)
        q = parsed.query.replace('?', '&')
        qs = urllib.parse.parse_qs(q, keep_blank_values=True)
        return parsed, qs

    def do_GET(self):
        parsed, qs = self._parse_query(self.path)

        # 1) Publish if proper query parameters
        if 'topic' in qs and 'payload' in qs:
            topic = qs['topic'][0]
            payload = qs['payload'][0]
            try:
                qos = int(qs.get('qos', [str(MQTT_QOS)])[0])
                retain = bool(int(qs.get('retain', [str(int(MQTT_RETAIN))])[0]))
            except ValueError:
                qos, retain = MQTT_QOS, MQTT_RETAIN

            try:
                publish_message(topic, payload, qos, retain)
                response = {
                    "topic":   TOPIC_PREFIX + topic.lstrip('/'),
                    "payload": payload,
                    "qos":     qos,
                    "retain":  retain,
                    "result": {"success": True}
                }
                if self._wants_json(qs):
                    body = json.dumps(response, indent=4).encode('utf-8')
                    self._set_response(200, {'Content-Type': 'application/json'}, body)
                else:
                    status = {
                        "ok": True,
                        "title": "MQTT publish succeeded",
                        "details": response
                    }
                    self._set_response(200, {'Content-Type': 'text/html; charset=utf-8'}, render_page(status))
            except Exception as e:
                self._set_error(500, str(e), as_json=self._wants_json(qs))

        # 2) Favicon => no content
        elif parsed.path == '/favicon.ico':
            self._set_response(204)

        # 3) Web UI form (home)
        elif parsed.path == '/':
            self._set_response(200, {'Content-Type': 'text/html; charset=utf-8'}, render_page())

        # 4) Anything else
        else:
            self._set_error(400, 'Bad request', as_json=self._wants_json(qs))

    def do_POST(self):
        # Allow posting via form or raw body; also allow payload via header if present
        length = int(self.headers.get('Content-Length', 0))
        raw = self.rfile.read(length).decode('utf-8')
        data = urllib.parse.parse_qs(raw, keep_blank_values=True)

        # Prefer header payload if provided
        header_payload = self.headers.get(HTTP_PAYLOAD_HEADER)
        topic   = data.get('topic', [''])[0]
        payload = header_payload if header_payload is not None else data.get('payload', [''])[0]
        try:
            qos = int(data.get('qos', [str(MQTT_QOS)])[0])
        except ValueError:
            qos = MQTT_QOS
        retain = 'retain' in data

        wants_json = self._wants_json(data)

        if not topic or payload is None or payload == '':
            return self._set_error(400, 'Both topic and payload are required.', as_json=wants_json)

        try:
            publish_message(topic, payload, qos, retain)
            response = {
                "topic":   TOPIC_PREFIX + topic.lstrip('/'),
                "payload": payload,
                "qos":     qos,
                "retain":  retain,
                "result": {"success": True}
            }
            if wants_json:
                body = json.dumps(response, indent=4).encode('utf-8')
                self._set_response(200, {'Content-Type': 'application/json'}, body)
            else:
                status = {
                    "ok": True,
                    "title": "MQTT publish succeeded",
                    "details": response
                }
                self._set_response(200, {'Content-Type': 'text/html; charset=utf-8'}, render_page(status))
        except Exception as e:
            self._set_error(500, str(e), as_json=wants_json)

class ThreadedHTTPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True

def run():
    server = ThreadedHTTPServer((HTTP_IP_ADDRESS, HTTP_PORT), HTTPHandler)
    logger.info(f"HTTP server is running on {HTTP_IP_ADDRESS}:{HTTP_PORT}")

    def shutdown_handler(signum, frame):
        logger.info("Shutting down server and MQTT client...")
        server.shutdown()
        mqtt_client.loop_stop()
        mqtt_client.disconnect()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)
    server.serve_forever()

if __name__ == '__main__':
    run()
