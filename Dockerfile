# Use a smaller, security-focused base image
FROM python:3.11-alpine AS builder

# Install build dependencies
RUN apk add --no-cache --virtual .build-deps \
        gcc musl-dev linux-headers \
    && pip install --no-cache-dir --upgrade pip setuptools wheel

# Copy source and build
WORKDIR /app
COPY requirements.txt .
RUN pip wheel --no-cache-dir --no-deps --wheel-dir /wheels -r requirements.txt
COPY . .

# Final stage: minimal runtime image
FROM python:3.11-alpine

# Copy wheels and install
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links=/wheels paho-mqtt

# Copy application code
COPY --from=builder /app /app
WORKDIR /app

# Drop root privileges for security
RUN addgroup -S http2mqtt && adduser -S http2mqtt -G http2mqtt
USER http2mqtt

# Expose HTTP port
EXPOSE 8080

# Use a unbuffered stdout for easier logging
ENV PYTHONUNBUFFERED=1

CMD ["python", "http2mqtt.py"]