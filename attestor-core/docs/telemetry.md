# Telemetry

We use Elastic to collect telemetry data. If running your own attestor, you can specify the `ELASTIC*` variables in your `.env` file to send telemetry data to your own Elastic instance.
Refer to [.env.sample](../.env.sample) for the required variables.

We sample the following data:
1. Each WebSocket connection made to the attestor
2. Each RPC call made to the attestor (request metadata, response metadata etc.)
3. Each tunnel created by the attestor (host, port, geolocation)