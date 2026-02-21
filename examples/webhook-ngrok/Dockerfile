FROM python:3.11-slim

WORKDIR /app

# Install ngrok + curl (and certs)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates \
  && curl -fsSL https://ngrok-agent.s3.amazonaws.com/ngrok.asc \
    | tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null \
  && echo "deb https://ngrok-agent.s3.amazonaws.com buster main" \
    | tee /etc/apt/sources.list.d/ngrok.list >/dev/null \
  && apt-get update && apt-get install -y --no-install-recommends ngrok \
  && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY *.py ./
COPY routes/ ./routes/

# Start gunicorn + ngrok in the same container
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV PORT=8080

CMD ["/entrypoint.sh"]