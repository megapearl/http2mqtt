# HTTP → MQTT Bridge

A lightweight bridge that exposes an HTTP interface to publish messages to an MQTT broker. Suitable for IoT integrations, webhooks, or simple testing.

---

## 🚀 Features

- **HTTP GET/POST** endpoints for publishing MQTT messages
- **Configurable** via environment variables
- **Persistent MQTT client** for performance
- **Threaded HTTP server** for concurrent requests
- **Docker-ready** with optimized multi-stage build
- **Health checks** and structured logging

---

## 🛠️ Installation

### Prerequisites

- Python **3.8+**
- Docker & Docker Compose (optional)

### From Source

1. **Clone** this repo:
   ```bash
   git clone https://github.com/megapearl/http2mqtt.git
   cd http2mqtt
   ```

2. **Install dependencies**:
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

3. **Run**:
   ```bash
   python http2mqtt.py
   ```

---

## 🐳 Docker

### Build & Run

```bash
# Build image
docker build -t http2mqtt .

# Run container
docker run -d \
  --name http2mqtt \
  -p 8080:8080 \
  -e MQTT_BROKER=yourmqttbroker.local \
  -e MQTT_PORT=1883 \
  -e TOPIC_PREFIX=http2mqtt/ \
  http2mqtt:latest
```

### Docker Compose

```bash
# Start services
docker-compose up -d
# Stop
docker-compose down
```

Service is then available on `http://localhost:8080/`.

---

## ⚙️ Configuration

| Variable            | Default            | Description                           |
|---------------------|--------------------|---------------------------------------|
| `MQTT_BROKER`       | `localhost`        | MQTT broker host or IP               |
| `MQTT_PORT`         | `1883`             | MQTT broker port                     |
| `TOPIC_PREFIX`      | `http2mqtt/`       | MQTT topic prefix                    |
| `MQTT_CLIENT_ID`    | `http2mqtt`        | MQTT client identifier               |
| `MQTT_USERNAME`     |                    | MQTT auth username (if required)     |
| `MQTT_PASSWORD`     |                    | MQTT auth password (if required)     |
| `MQTT_RETAIN`       | `1`                | Default retain flag (0 or 1)         |
| `MQTT_QOS`          | `1`                | Default QoS level (0, 1, or 2)       |
| `HTTP_IP_ADDRESS`   | `0.0.0.0`          | HTTP server bind address             |
| `HTTP_PORT`         | `8080`             | HTTP server port                     |
| `HTTP_PAYLOAD_HEADER` | `x-payload`      | Header name to override payload      |

---

## 📝 Usage

- **Publish via GET**:
  ```text
  GET /my/topic?payload=hello
  Header: x-payload: world   # optional override
  ```
- **Publish via POST**:
  ```text
  POST /publish
  Content-Type: application/x-www-form-urlencoded
  Body: topic=my/topic&payload=hello&qos=2&retain=1
  ```

The service responds with JSON:

```json
{
  "topic": "http2mqtt/my/topic",
  "payload": "hello",
  "qos": 2,
  "retain": true,
  "result": { "success": true }
}
```

---

## 🔍 Health Check

- **Endpoint**: `GET /` serves a simple form and returns HTTP 200.

- **Docker Compose**: `healthcheck` command is defined to use `wget --spider`.

---

## 📜 License

This project is licensed under the [MIT License](LICENSE). Feel free to use and adapt it!
