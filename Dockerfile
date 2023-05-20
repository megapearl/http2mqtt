FROM python:3.4-alpine
ADD . /http2mqtt
WORKDIR /http2mqtt
RUN pip install -r requirements.txt
CMD ["python", "http2mqtt.py"]
