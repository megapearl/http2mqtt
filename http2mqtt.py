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
    # default to 3.1.1
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

class HTTPHandler(http.server.BaseHTTPRequestHandler):
    def _set_response(self, status=200, headers=None, body=b""):
        self.send_response(status)
        headers = headers or {}
        for k, v in headers.items():
            self.send_header(k, v)
        if 'Content-Length' not in headers:
            self.send_header('Content-Length', str(len(body)))
        # End headers, ignore client disconnects
        try:
            self.end_headers()
        except ConnectionResetError:
            return
        # Write body if present, ignore client disconnects
        if body:
            try:
                self.wfile.write(body)
            except ConnectionResetError:
                pass

    def _set_error(self, status, message):
        payload = json.dumps({"error": message}).encode('utf-8')
        self._set_response(status, {'Content-Type': 'application/json'}, payload)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)

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
                    "topic":   TOPIC_PREFIX + topic,
                    "payload": payload,
                    "qos":     qos,
                    "retain":  retain,
                    "result": {"success": True}
                }
                body = json.dumps(response, indent=4).encode('utf-8')
                self._set_response(200, {'Content-Type': 'application/json'}, body)
            except Exception as e:
                self._set_error(500, str(e))

        # 2) Favicon => no content
        elif parsed.path == '/favicon.ico':
            self._set_response(204)

        # 3) Web UI form
        elif parsed.path == '/':
            html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>HTTP → MQTT Bridge</title>
  <style>
    body {{ font-family: Arial, sans-serif; background: #f4f4f4; color: #333; }}
    .container {{ max-width: 500px; margin: 50px auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
    h1 {{ text-align: center; font-size: 1.5em; }}
    label {{ display: block; margin-top: 15px; }}
    input[type=text], input[type=number] {{ width: 100%; padding: 8px; margin-top: 5px; box-sizing: border-box; }}
    input[type=checkbox] {{ margin-top: 10px; }}
    button {{ margin-top: 20px; width: 100%; padding: 10px; background: #007BFF; color: #fff; border: none; border-radius: 4px; font-size: 1em; cursor: pointer; }}
    button:hover {{ background: #0056b3; }}
    .info {{ font-size: 0.9em; color: #555; margin-bottom: 10px; }}
  </style>
</head>
<body>
  <div class="container">
    <h1>HTTP → MQTT Bridge</h1>
    <p class="info">Topic Prefix: <code>{TOPIC_PREFIX}</code></p>
    <form method="post" action="/publish">
      <label>Topic:<input type="text" name="topic" placeholder="e.g. home/sensor/temp" required></label>
      <label>Payload:<input type="text" name="payload" placeholder="e.g. 23.5" required></label>
      <label>QoS:<input type="number" name="qos" min="0" max="2" value="{MQTT_QOS}" required></label>
      <label><input type="checkbox" name="retain" {'checked' if MQTT_RETAIN else ''}> Retain message</label>
      <button type="submit">Publish</button>
    </form>
  </div>
</body>
</html>"""
            body = html.encode('utf-8')
            self._set_response(200, {'Content-Type': 'text/html'}, body)

        # 4) Anything else
        else:
            self._set_error(400, 'Bad request')

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        raw = self.rfile.read(length).decode('utf-8')
        data = urllib.parse.parse_qs(raw)

        topic   = data.get('topic', [''])[0]
        payload = data.get('payload', [''])[0]
        try:
            qos = int(data.get('qos', [str(MQTT_QOS)])[0])
        except ValueError:
            qos = MQTT_QOS
        retain = 'retain' in data

        if not topic or not payload:
            return self._set_error(400, 'Both topic and payload are required.')

        try:
            publish_message(topic, payload, qos, retain)
            response = {
                "topic":   TOPIC_PREFIX + topic,
                "payload": payload,
                "qos":     qos,
                "retain":  retain,
                "result": {"success": True}
            }
            body = json.dumps(response, indent=4).encode('utf-8')
            self._set_response(200, {'Content-Type': 'application/json'}, body)
        except Exception as e:
            self._set_error(500, str(e))

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
