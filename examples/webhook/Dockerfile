FROM node:20-slim

WORKDIR /app

# Install curl/certs, the ngrok agent, and cloudflared so a single image can run
# behind either tunnel (selected at runtime via TUNNEL=ngrok|cloudflared).
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
  && curl -fsSL https://ngrok-agent.s3.amazonaws.com/ngrok.asc \
       | tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null \
  && echo "deb https://ngrok-agent.s3.amazonaws.com buster main" \
       | tee /etc/apt/sources.list.d/ngrok.list >/dev/null \
  && apt-get update && apt-get install -y --no-install-recommends ngrok \
  && curl -fsSL https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 \
       -o /usr/local/bin/cloudflared \
  && chmod +x /usr/local/bin/cloudflared \
  && rm -rf /var/lib/apt/lists/*

# tsx (used by entrypoint to run the TS entry directly) is a devDependency, so
# install the full dependency set rather than --omit=dev.
COPY package.json package-lock.json* ./
RUN npm ci

COPY tsconfig.json ./
COPY src/ ./src/
COPY traffic-policy.yaml ./

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV PORT=8080
ENV TUNNEL=none

EXPOSE 8080

CMD ["/entrypoint.sh"]
