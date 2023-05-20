import http.server
import socketserver
import urllib.parse
import paho.mqtt.client as mqtt
import json
import os


# Parse environment variables or set default values
MQTT_BROKER = os.environ.get('MQTT_BROKER', 'localhost')
MQTT_PORT = int(os.environ.get('MQTT_PORT', '1883'))
TOPIC_PREFIX = os.environ.get('TOPIC_PREFIX', 'http2mqtt/')
MQTT_CLIENT_ID = os.environ.get('MQTT_CLIENT_ID', 'http2mqtt')
MQTT_USERNAME = os.environ.get('MQTT_USERNAME', 'username')
MQTT_PASSWORD = os.environ.get('MQTT_PASSWORD', 'password')
MQTT_RETAIN = int(os.environ.get('MQTT_RETAIN', '1'))
MQTT_QOS = int(os.environ.get('MQTT_QOS', '1'))
HTTP_PORT = int(os.environ.get('HTTP_PORT', '8080'))
HTTP_PAYLOAD_HEADER = os.environ.get('HTTP_PAYLOAD_HEADER', 'x-payload')
HTTP_IP_ADDRESS = os.environ.get('HTTP_IP_ADDRESS', '0.0.0.0')


class IncomingHTTPRequest(http.server.BaseHTTPRequestHandler):
    def _set_response(self, status_code=200, headers=None, data=None):
        self.send_response(status_code)
        if headers:
            for header, value in headers.items():
                self.send_header(header, value)
        self.end_headers()

        response_html = """
        <html>
        <body>
            <div id="response-data"></div>
        </body>
        </html>
        """
        self.wfile.write(response_html.encode('utf-8'))

    def _set_error_response(self, status_code, error_message):
        self.send_response(status_code)
        self.send_header("Content-type", "application/json")
        self.end_headers()

        response_data = {
            "error": error_message
        }
        response_data_json = json.dumps(response_data, indent=4)
        self.wfile.write(response_data_json.encode("utf-8"))

    def do_GET(self):
        if self.path == '/':
            self._set_response()
            topic_prefix_html = f'<p>Topic Prefix: {TOPIC_PREFIX}</p>'
            form_html = b'<html><body><form method="POST" action="/publish"><label for="topic">Topic:</label><br><input type="text" id="topic" name="topic" required><br><label for="payload">Payload:</label><br><input type="text" id="payload" name="payload" required><br><label for="qos">QoS:</label><br><input type="number" id="qos" name="qos" min="0" max="2" value="1" required><br><label for="retain">Retain:</label><br><input type="number" id="retain" name="retain" min="0" max="1" value="1" required><br><input type="submit" value="Publish"></form></body></html>'
            self.wfile.write(topic_prefix_html.encode('utf-8') + form_html)
        else:
            parsed_url = urllib.parse.urlparse(self.path)
            topic = parsed_url.path[1:].lstrip('/')
            payload = self.headers.get(HTTP_PAYLOAD_HEADER, '') or parsed_url.query
            if topic and payload:
                self.publish_message(topic, payload)
                response_data = {
                    "topic": TOPIC_PREFIX + topic,
                    "payload": payload,
                    "retain": MQTT_RETAIN,
                    "qos": MQTT_QOS,
                    "result": {"success": True}
                }
                self._set_response()
                response_data_html = '<pre>' + json.dumps(response_data, indent=4) + '</pre>'
                self.wfile.write(response_data_html.encode('utf-8'))
            else:
                self._set_response(400)
                self.wfile.write(b'Both topic and payload are required.')

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        parsed_data = urllib.parse.parse_qs(post_data)
        topic = parsed_data.get('topic', [''])[0].lstrip('/')  # Remove the leading '/'
        payload = parsed_data.get('payload', [''])[0]
        qos = int(parsed_data.get('qos', ['1'])[0])
        retain = int(parsed_data.get('retain', ['1'])[0])

        if topic and payload:
            self.publish_message(topic, payload, qos, retain)
            response_data = {
                "topic": TOPIC_PREFIX + topic,
                "payload": payload,
                "retain": retain,
                "qos": qos,
                "result": {"success": True}
            }
            self._set_response()
            response_data_html = '<pre>' + json.dumps(response_data, indent=4) + '</pre>'
            self.wfile.write(response_data_html.encode('utf-8'))
        else:
            self._set_response(400)
            self.wfile.write(b'Both topic and payload are required.')

    def publish_message(self, topic, payload, qos=1, retain=1):
        try:
            prefixed_topic = TOPIC_PREFIX + topic

            def on_publish(client, userdata, mid):
                print(f"Message published to topic: {prefixed_topic}")

            client = mqtt.Client(client_id=MQTT_CLIENT_ID)
            client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)
            client.connect(MQTT_BROKER, MQTT_PORT)

            client.on_publish = on_publish

            client.loop_start()
            client.publish(prefixed_topic, payload, qos=qos, retain=retain)
            client.loop_stop()
            client.disconnect()
        except Exception as e:
            print(f"Error occurred while publishing message: {str(e)}")
            self._set_error_response(500, "Internal Server Error")


class ThreadedHTTPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


if __name__ == "__main__":
    with ThreadedHTTPServer((HTTP_IP_ADDRESS, HTTP_PORT), IncomingHTTPRequest) as httpd:
        print(f'HTTP server is running on {HTTP_IP_ADDRESS}:{HTTP_PORT}')
        httpd.serve_forever()
