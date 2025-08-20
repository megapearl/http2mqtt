# HTTP → MQTT Bridge

A lightweight bridge that exposes a REST-style HTTP API (with legacy GET support) to publish messages to an MQTT broker.  
Perfect for IoT integrations, webhooks, SIP phones, or simple testing.

---

## 🚀 Features

- **REST API** for clean integrations (`/v1/messages`, `/v1/topics/{topic}/messages`)
- **Legacy GET fallback** for devices that cannot send POST (e.g. SIP phones)
- **HTML Web UI** at `/` with a simple publish form and live feedback
- **Built-in security headers** (CSP, X-Content-Type-Options, Referrer-Policy, X-Frame-Options)
- **Configurable maximum topic/payload length** for safety
- **Persistent MQTT client** with reconnect backoff for resilience
- **Threaded HTTP server** for concurrent requests
- **Health & config endpoints** for monitoring
- **Optional API key & idempotency support**
- **Docker-ready** with multi-stage build

---

## 🛠️ Installation

### Prerequisites

- Python **3.8+**
- MQTT broker accessible on your network
- Docker & Docker Compose (optional)

### From Source

```bash
git clone https://github.com/megapearl/http2mqtt.git
cd http2mqtt
pip install --upgrade pip
pip install -r requirements.txt
python http2mqtt.py
```

---

## 🐳 Docker

### Build & Run

```bash
# Build image
docker build -t http2mqtt .

# Run container
docker run -d   --name http2mqtt   -p 8080:8080   -e MQTT_BROKER=yourmqttbroker.local   -e MQTT_PORT=1883   -e TOPIC_PREFIX=http2mqtt/   http2mqtt:latest
```

### Docker Compose

```bash
docker-compose up -d
# Stop
docker-compose down
```

Service is then available on `http://localhost:8080/`.

---

## ⚙️ Configuration

| Variable              | Default         | Description                               |
|-----------------------|-----------------|-------------------------------------------|
| `MQTT_BROKER`         | `localhost`     | MQTT broker host or IP                     |
| `MQTT_PORT`           | `1883`          | MQTT broker port                           |
| `TOPIC_PREFIX`        | `http2mqtt/`    | MQTT topic prefix                          |
| `MQTT_CLIENT_ID`      | `http2mqtt`     | MQTT client identifier                     |
| `MQTT_USERNAME`       | *(empty)*       | MQTT auth username (if required)           |
| `MQTT_PASSWORD`       | *(empty)*       | MQTT auth password (if required)           |
| `MQTT_RETAIN`         | `1`             | Default retain flag (0 or 1)               |
| `MQTT_QOS`            | `1`             | Default QoS level (0, 1, or 2)             |
| `MQTT_PROTOCOL`       | `3.1.1`         | MQTT protocol version (`3.1.1` or `5`)     |
| `HTTP_IP_ADDRESS`     | `0.0.0.0`       | HTTP server bind address                   |
| `HTTP_PORT`           | `8080`          | HTTP server port                           |
| `HTTP_PAYLOAD_HEADER` | `x-payload`     | Header name to override payload            |
| `API_KEY`             | *(empty)*       | Optional API key for auth (`X-API-Key`)    |
| `MAX_TOPIC_LEN`       | `512`           | Maximum allowed topic length (characters)  |
| `MAX_PAYLOAD_LEN`     | `4096`          | Maximum allowed payload length (characters)|

---

## 🔐 Authentication

If `API_KEY` is set, requests must authenticate.

- **Preferred (modern clients):** send header `X-API-Key: <value>`.
- **Legacy GET fallback (only for `/v1/messages` GET):** append `&apikey=<value>` to the URL.  
  This is accepted **only** when `API_KEY` is configured and **only** on the GET endpoint to support old devices that cannot set headers.

> ⚠️ Use HTTPS. Query-string API keys can appear in logs or referrers.

Examples:

```text
GET /v1/messages?topic=frontdoor-voip&payload=ip_changed&apikey=SECRET123
```

```bash
curl -X POST http://localhost:8080/v1/messages   -H 'Content-Type: application/json'   -H 'X-API-Key: SECRET123'   -d '{"topic":"frontdoor-voip","payload":"ip_changed"}'
```

---

## 📝 Usage

### 1. REST API

#### Publish message (generic)
```bash
POST /v1/messages
Content-Type: application/json

{
  "topic": "frontdoor-voip",
  "payload": "ip_changed",
  "qos": 1,
  "retain": false
}
```

#### Publish to specific topic
```bash
POST /v1/topics/frontdoor-voip/messages
Content-Type: application/json

{
  "payload": "ip_changed",
  "qos": 1,
  "retain": 0
}
```

#### Health check
```bash
GET /v1/health
# → {"status":"ok"}
```

#### Config
```bash
GET /v1/config
# → {"topic_prefix":"http2mqtt/","qos_default":1,"retain_default":true}
```

---

### 2. Legacy GET (for SIP phones or limited clients)

```text
GET /v1/messages?topic=frontdoor-voip&payload=ip_changed&qos=1&retain=0[&apikey=SECRET]
```

---

### 3. Web UI

Open in browser:

```
http://localhost:8080/
```

You get a simple form to publish MQTT messages and see success/failure in-page.

---

## 🔑 Optional Features

- **Idempotency**  
  Add header `Idempotency-Key: <uuid>` to `POST /v1/messages` to avoid duplicate publishes.

- **Payload override via header**  
  You can override the payload with the `x-payload` header:
  ```bash
  curl -X POST http://localhost:8080/v1/messages     -H 'Content-Type: application/x-www-form-urlencoded'     -H 'x-payload: my_payload'     -d 'topic=test/topic'
  ```

---

## 📜 License

This project is licensed under the [MIT License](LICENSE).  
Feel free to use and adapt it for your own projects!
