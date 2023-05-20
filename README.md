
## MQTT HTTP Bridge

This script creates an HTTP server that acts as a bridge between HTTP requests and MQTT messages. It allows you to publish MQTT messages by sending HTTP requests with the desired topic and payload.

### Prerequisites

Before running the script, make sure you have the following prerequisites installed:

- Python 3.x
- Paho MQTT library (`paho-mqtt`)

### Installation

1. Clone the repository or download the script file.
2. Install the required dependencies by running the following command:

   ```bash
   pip install paho-mqtt
   ```

### Configuration

The script uses environment variables for configuration. You can set the following environment variables or use the default values:

- `MQTT_BROKER`: MQTT broker hostname or IP address. Default: `shed-mqtt.flissinger.com`
- `MQTT_PORT`: MQTT broker port. Default: `1883`
- `TOPIC_PREFIX`: Prefix to be added to the MQTT topic. Default: `home-domotica/`
- `MQTT_CLIENT_ID`: MQTT client ID. Default: `freebsd-fileserver`
- `MQTT_USERNAME`: MQTT username. Default: `donald`
- `MQTT_PASSWORD`: MQTT password. Default: `delta123`
- `MQTT_RETAIN`: MQTT retain flag (0 or 1). Default: `1`
- `MQTT_QOS`: MQTT quality of service level (0, 1, or 2). Default: `1`
- `HTTP_PORT`: HTTP server port. Default: `8080`
- `HTTP_PAYLOAD_HEADER`: HTTP request header field to specify the payload. Default: `x-payload`
- `HTTP_IP_ADDRESS`: IP address for the HTTP server to bind to. Default: `0.0.0.0`

### Usage

To start the MQTT HTTP bridge, run the following command:

```bash
python script.py
```

The HTTP server will start listening on the specified IP address and port. You can access the web interface by opening a web browser and navigating to `http://<IP_ADDRESS>:<HTTP_PORT>`. The default IP address is `0.0.0.0` (all interfaces) and the default port is `8080`.

The web interface allows you to publish MQTT messages by submitting a form with the desired topic, payload, QoS, and retain settings.

### License

This script is licensed under the [MIT License](LICENSE).

---
