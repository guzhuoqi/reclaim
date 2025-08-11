FROM node:20-bookworm

# Install Python and pip for mitmproxy and addon deps
RUN apt-get update -y && \
    apt-get install -y --no-install-recommends python3 python3-pip python3-venv ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /opt/reclaim

# Copy and build attestor-core (for local script execution inside addon)
COPY ./attestor-core/package.json ./attestor-core/package-lock.json /opt/reclaim/attestor-core/
RUN mkdir -p /opt/reclaim/attestor-core/src/scripts \
    && sh -lc 'echo "" > /opt/reclaim/attestor-core/src/scripts/prepare.sh' \
    && cd /opt/reclaim/attestor-core && npm ci
COPY ./attestor-core /opt/reclaim/attestor-core
RUN cd /opt/reclaim/attestor-core && npm run build && npm prune --omit=dev

# Create compatibility symlink for code paths expecting /opt/attestor-core
RUN ln -s /opt/reclaim/attestor-core /opt/attestor-core

# Copy addon code after base is ready, preserve repo structure
COPY ./mitmproxy2swagger /opt/reclaim/mitmproxy2swagger
WORKDIR /opt/reclaim/mitmproxy2swagger/mitmproxy_addons

# Python deps for mitmweb runtime
# Use isolated venv to avoid PEP 668 restriction
RUN python3 -m venv /venv
ENV PATH="/venv/bin:${PATH}"
RUN pip3 --version && python3 --version && pip3 install --no-cache-dir "mitmproxy>=11.0.2,<12" websocket-client requests

# Create data/logs directories inside container
RUN mkdir -p /app/mitmproxy_addons/logs /app/mitmproxy_addons/data

EXPOSE 8080 8082

# Default command: run mitmweb and sidecar flows proxy to avoid 403 from cross-container clients
CMD ["sh", "-lc", "(/venv/bin/python flows_proxy.py & echo $! > /tmp/flows_proxy.pid) && /venv/bin/mitmweb -s attestor_forwarding_addon.py --listen-host 0.0.0.0 --listen-port 8080 --set web_host=0.0.0.0 --set web_port=8082 --set web_open_browser=false --set block_global=false --set block_private=false | tee -a logs/mitmweb.log"]


