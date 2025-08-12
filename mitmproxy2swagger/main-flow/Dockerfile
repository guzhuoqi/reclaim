ARG BASE_IMAGE=node:20-bookworm
FROM ${BASE_IMAGE}

WORKDIR /app/main-flow

# System dependencies: install Python and curl on Debian (node base)
RUN apt-get update -y \
    && apt-get install -y --no-install-recommends python3 python3-pip python3-venv curl \
    && rm -rf /var/lib/apt/lists/*

# Use isolated virtualenv to avoid PEP 668 restrictions
RUN python3 -m venv /venv
ENV PATH="/venv/bin:${PATH}"

# Copy minimal files first for better caching
COPY ./mitmproxy2swagger/main-flow/requirements.txt /app/main-flow/requirements.txt
RUN /venv/bin/pip install --no-cache-dir -r /app/main-flow/requirements.txt
RUN /venv/bin/pip install --no-cache-dir "ruamel.yaml>=0.17.32,<0.19" json-stream==2.3.2 msgpack==1.0.7

# Copy project files
COPY ./mitmproxy2swagger/main-flow /app/main-flow
COPY ./mitmproxy2swagger/mitmproxy_addons /app/mitmproxy_addons
COPY ./mitmproxy2swagger/feature-library /app/feature-library
COPY ./mitmproxy2swagger/mitmproxy2swagger /app/mitmproxy2swagger

# Ensure runtime directories
RUN mkdir -p /app/main-flow/logs /app/main-flow/data /app/main-flow/uploads /app/main-flow/temp

ENV API_SERVER_HOST=0.0.0.0 \
    API_SERVER_PORT=8000 \
    MITM_HOST=mitm \
    MITM_PORT=8082 \
    PYTHONPATH=/app

EXPOSE 8000

CMD ["sh", "-lc", "/venv/bin/python /app/main-flow/independent_api_server.py"]


