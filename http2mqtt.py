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

# Configuration
MQTT_BROKER = os.environ.get("MQTT_BROKER", "localhost")
MQTT_PORT = int(os.environ.get("MQTT_PORT", "1883"))
TOPIC_PREFIX = os.environ.get("TOPIC_PREFIX", "http2mqtt/")
MQTT_CLIENT_ID = os.environ.get("MQTT_CLIENT_ID", "http2mqtt")
MQTT_USERNAME = os.environ.get("MQTT_USERNAME")
MQTT_PASSWORD = os.environ.get("MQTT_PASSWORD")
MQTT_RETAIN = bool(int(os.environ.get("MQTT_RETAIN", "1")))
MQTT_QOS = int(os.environ.get("MQTT_QOS", "1"))

HTTP_IP_ADDRESS = os.environ.get("HTTP_IP_ADDRESS", "0.0.0.0")
HTTP_PORT = int(os.environ.get("HTTP_PORT", "8080"))
HTTP_PAYLOAD_HEADER = os.environ.get("HTTP_PAYLOAD_HEADER", "x-payload")

# Logging setup
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Initialize and start MQTT client
mqtt_client = mqtt.Client(client_id=MQTT_CLIENT_ID)
if MQTT_USERNAME and MQTT_PASSWORD:
    mqtt_client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)
mqtt_client.connect(MQTT_BROKER, MQTT_PORT)
mqtt_client.loop_start()

def publish_message(topic: str, payload: str, qos: int = MQTT_QOS, retain: bool = MQTT_RETAIN) -> bool:
    """
    Publish a message to the MQTT broker with the configured prefix.
    """
    full_topic = f"{TOPIC_PREFIX}{topic.lstrip('/')}"
    result = mqtt_client.publish(full_topic, payload, qos=qos, retain=retain)
    if result.rc == mqtt.MQTT_ERR_SUCCESS:
        logger.info("Published to %s: %s", full_topic, payload)
        return True
    else:
        logger.error("Publish failed (rc=%s) for topic %s", result.rc, full_topic)
        return False

class HTTPHandler(http.server.BaseHTTPRequestHandler):
    def _respond(self, status: int = 200, content_type: str = "text/html", body: bytes = b""):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status: int, message: str):
        payload = json.dumps({"error": message}).encode('utf-8')
        self._respond(status, "application/json", payload)

    def _render_form(self) -> bytes:
        html = f"""
<html>
<body>
    <h1>MQTT Publish Interface</h1>
    <p>Topic Prefix: <code>{TOPIC_PREFIX}</code></p>
    <form method="post" action="/publish">
        <label>Topic:<input type="text" name="topic" required></label><br>
        <label>Payload:<input type="text" name="payload" required></label><br>
        <label>QoS:<input type="number" name="qos" value="{MQTT_QOS}" min="0" max="2"></label><br>
        <label>Retain:<input type="checkbox" name="retain" {'checked' if MQTT_RETAIN else ''}></label><br>
        <button type="submit">Publish</button>
    </form>
</body>
</html>
"""
        return html.encode('utf-8')

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == '/':
            self._respond(body=self._render_form())
            return

        topic = parsed.path.lstrip('/')
        payload = self.headers.get(HTTP_PAYLOAD_HEADER) or parsed.query
        if not topic or not payload:
            return self._error(400, "Both topic and payload are required.")

        if not publish_message(topic, payload):
            return self._error(500, "Failed to publish message.")

        response = {
            "topic": TOPIC_PREFIX + topic,
            "payload": payload,
            "qos": MQTT_QOS,
            "retain": MQTT_RETAIN,
            "result": {"success": True}
        }
        body = json.dumps(response, indent=4).encode('utf-8')
        self._respond(200, "application/json", body)

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        raw = self.rfile.read(length).decode('utf-8')
        data = urllib.parse.parse_qs(raw)
        topic = data.get('topic', [''])[0]
        payload = data.get('payload', [''])[0]
        try:
            qos = int(data.get('qos', [MQTT_QOS])[0])
        except ValueError:
            qos = MQTT_QOS
        retain = 'retain' in data

        if not topic or not payload:
            return self._error(400, "Both topic and payload are required.")

        if not publish_message(topic, payload, qos, retain):
            return self._error(500, "Failed to publish message.")

        response = {
            "topic": TOPIC_PREFIX + topic,
            "payload": payload,
            "qos": qos,
            "retain": retain,
            "result": {"success": True}
        }
        body = json.dumps(response, indent=4).encode('utf-8')
        self._respond(200, "application/json", body)


def run():
    server = socketserver.ThreadingTCPServer((HTTP_IP_ADDRESS, HTTP_PORT), HTTPHandler)
    logger.info("Starting server at %s:%s", HTTP_IP_ADDRESS, HTTP_PORT)

    def _shutdown(signum, frame):
        logger.info("Shutting down...")
        server.shutdown()
        mqtt_client.loop_stop()
        mqtt_client.disconnect()
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)
    server.serve_forever()

if __name__ == "__main__":
    run()