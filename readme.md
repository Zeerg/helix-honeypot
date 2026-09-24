# Helix Honeypot

Helix is a small honeypot for Kubernetes API reconnaissance, a misconfigured kubelet façade, and basic HTTP, TCP, and UDP probes. It returns bounded simulated responses and writes one structured event per interaction to standard output.

Kubernetes and HTTP modes return bounded simulated responses. TCP and UDP modes record connection/datagram metadata and byte counts, but do not reply to the sender.

The Kubernetes API façade is the main product surface. It is useful for detecting and studying clients that probe exposed control planes; it is not a Kubernetes control plane, a conformance server, or a place to run workloads.

## Safety boundary

- Helix never connects to or changes a real Kubernetes cluster.
- The default listeners bind to loopback and unprivileged ports.
- Request bodies, query strings, authorization and cookie values, and configured honeytoken values are not written to event logs. User-agent collection is opt-in.
- The container runs as an unprivileged user with a read-only filesystem and no Linux capabilities. The Compose bridge disables sensor-to-sensor communication and outbound IP masquerading, while publishing sensor ports on loopback. These bridge settings do not enforce a complete outbound traffic block; apply an egress-deny firewall rule at the host or cloud network boundary when that guarantee is required.
- Do not put real credentials or production data in a honeypot. Deploy public sensors in a dedicated, restricted network and review the event privacy settings before collection.

Helix is designed to observe and safely emulate. It does not stream unbounded responses, create redirect loops, execute submitted objects, or attempt to disrupt remote scanners.

## Quick start

Start the Kubernetes sensor. Its published port is available only on the local machine:

```sh
docker compose up --build -d
docker compose logs -f k8s
```

Probe the simulated Kubernetes API and its health endpoints:

```sh
curl http://127.0.0.1:8080/version
curl http://127.0.0.1:8080/readyz
```

Start all four sensor modes when needed:

```sh
docker compose --profile all up --build -d
```

Stop the sensors with `docker compose down`.

To load structured settings and honeytokens into the Kubernetes container, copy `config.example.toml` to the ignored local `config.toml`, edit it with synthetic values, then start the optional config overlay:

```sh
cp config.example.toml config.toml
docker compose -f docker-compose.yaml -f docker-compose.config.yaml up --build -d k8s
```

The overlay mounts the file read-only. `HELIX_CONFIG_FILE` can point to a different host path. Host-published ports can be changed with `HELIX_K8S_PUBLISHED_PORT`, `HELIX_HTTP_PUBLISHED_PORT`, `HELIX_TCP_PUBLISHED_PORT`, and `HELIX_UDP_PUBLISHED_PORT`; they bind to `127.0.0.1` unless `HELIX_PUBLISH_HOST` is deliberately changed.

The image also works without Compose. It ships `config.docker.toml` baked in at `/etc/helix/config.toml`, which binds every sensor to `0.0.0.0` and seeds the `payments` and `monitoring` namespaces plus a synthetic honeytoken Secret, so a pulled image is immediately reachable and looks inhabited:

```sh
docker run --rm -p 127.0.0.1:8080:8080 ghcr.io/zeerg/helix-honeypot:latest
curl http://127.0.0.1:8080/version
```

(`latest` tracks `main`, `edge` tracks `develop`, and `v*` releases get semver tags; use `helix-honeypot:local` for a local `docker build`.)

Override the baked file by bind-mounting over `/etc/helix/config.toml` or setting `HELIX_CONFIG`; environment variables still take precedence. The bare binary keeps loopback-only defaults — the `0.0.0.0` binds exist only in the container image, where published ports are the operator's explicit choice.

To run directly with Go, the default mode is Kubernetes:

```sh
go run ./cmd
```

Set `HELIX_RUN_MODE` to `http`, `tcp`, `udp`, or `kubelet` to select another sensor. `def` mode has been retired because its previous infinite-response behavior could consume unbounded resources.

## Configuration

The optional TOML file is `./config.toml`; set `HELIX_CONFIG` to use a different path. Environment values override file values. If no file exists, Helix starts with safe defaults.

Start from the checked-in example with `cp config.example.toml config.toml` and edit the values for the lab.

| Setting | Environment variable | Default |
| --- | --- | --- |
| Sensor mode | `HELIX_RUN_MODE` (`RUN_MODE` is also accepted) | `k8s` |
| Kubernetes bind address | `HELIX_K8S_HOST` | `127.0.0.1` |
| Kubernetes port | `HELIX_K8S_PORT` | `8080` |
| Kubernetes TLS (`https://`, self-signed serving cert unless files given) | `HELIX_K8S_TLS_ENABLED`, `HELIX_K8S_TLS_CERT_FILE`, `HELIX_K8S_TLS_KEY_FILE` | off, generated |
| Kubernetes API profile | `HELIX_K8S_API_VERSION` | `v1.37` |
| Kubernetes pod network base | `HELIX_K8S_IP_BASE` (`IP_BASE`) | `10.42.0.0` |
| Additional Kubernetes namespaces | `HELIX_K8S_NAMESPACES` (comma-separated) | built-ins only |
| Synthetic Secret lures | `HELIX_K8S_HONEYTOKENS` (`name[@ns]:k=v,k=v` entries, `;`-separated) | none |
| HTTP bind address / port | `HELIX_HTTP_HOST`, `HELIX_HTTP_PORT` | `127.0.0.1`, `8081` |
| TCP bind address / port | `HELIX_TCP_HOST`, `HELIX_TCP_PORT` | `127.0.0.1`, `9022` |
| UDP bind address / port | `HELIX_UDP_HOST`, `HELIX_UDP_PORT` | `127.0.0.1`, `9053` |
| Kubelet bind address / port | `HELIX_KUBELET_HOST`, `HELIX_KUBELET_PORT` | `127.0.0.1`, `10250` |
| Kubelet node name | `HELIX_KUBELET_NODE_NAME` | `worker-01` |
| Kubelet TLS (kubelets are HTTPS; set `false` for plain HTTP) | `HELIX_KUBELET_TLS_ENABLED`, `HELIX_KUBELET_TLS_CERT_FILE`, `HELIX_KUBELET_TLS_KEY_FILE` | on, generated |
| Event format | `HELIX_LOG_FORMAT` | `json` |
| Include user-agent in events | `HELIX_LOG_INCLUDE_USER_AGENT` | `false` |
| Trusted proxy CIDRs | `HELIX_LOG_TRUSTED_PROXY_CIDRS` (comma-separated) | none |
| File event sink | `HELIX_LOG_FILE` (container: mount a writable volume, e.g. `-v $PWD/logs:/logs` + `/logs/events.jsonl`) | none |
| Splunk HEC sink | `HELIX_SPLUNK_URL`, `HELIX_SPLUNK_TOKEN`, `HELIX_SPLUNK_INDEX`, `HELIX_SPLUNK_SOURCETYPE`, `HELIX_SPLUNK_SOURCE` | none |
| Elasticsearch sink | `HELIX_ELASTICSEARCH_URL` (or `HELIX_ELK_URL`), `HELIX_ELASTICSEARCH_INDEX`, `HELIX_ELASTICSEARCH_TOKEN`, `HELIX_ELASTICSEARCH_USERNAME`, `HELIX_ELASTICSEARCH_PASSWORD` | none |
| Generic HTTP sink | `HELIX_HTTP_SINK_URL`, `HELIX_HTTP_SINK_TOKEN`, `HELIX_HTTP_SINK_HEADERS` (`Name:Value` entries, `;`-separated) | none |

Structured synthetic Kubernetes Secrets are configured in TOML with `[[k8s.honeytokens]]` entries containing `name`, optional `namespace`, optional `type` (defaults to `Opaque`), and a `data` map. They can also come entirely from the environment: `HELIX_K8S_HONEYTOKENS="api-token@payments:token=x1,user=admin;db-creds:password=x2"` creates two `Opaque` Secrets — `api-token` in `payments`, `db-creds` in `default`. Values with commas or semicolons need TOML. The built-in namespaces are `default`, `kube-system`, `kube-public`, and `kube-node-lease`; names in `k8s.namespaces` or `HELIX_K8S_NAMESPACES` add custom namespaces. A honeytoken can use a built-in namespace or a custom namespace listed in configuration. The legacy `token_names` and `token_values` fields and the `HELIX_K8S_TOKEN_NAMES` / `HELIX_K8S_TOKEN_VALUES` comma-separated environment variables remain supported for older deployments. Kubernetes resource generation uses `HELIX_K8S_GENERATE_KUBE_SYSTEM` and `HELIX_K8S_GENERATE_RANDOMNESS`.

Use synthetic-only honeytoken data. The config file is limited to 1 MiB. Namespace lists may contain at most 64 lowercase DNS labels, each at most 63 bytes. Structured honeytokens are limited to 64 entries, 16 data keys per entry, and 256 data keys total; each honeytoken needs at least one data key. Honeytoken names are lowercase DNS subdomains; types are `Opaque` or a lowercase DNS domain/name string up to 256 bytes; data keys use Kubernetes Secret key characters and are limited to 253 bytes. Each structured data value is limited to 4 KiB, and structured plus legacy token payloads together are limited to 16 KiB. Legacy token lists allow at most 64 entries each, with entries up to 256 bytes; legacy names and values together are capped at 16 KiB.

Event logging defaults to JSON. User-agent collection is off by default, and the trusted proxy list is empty, so forwarded client-address headers are not trusted unless their proxy CIDRs are configured. Set `HELIX_LOG_FORMAT` to `text` for key-value text output. Use `HELIX_LOG_TRUSTED_PROXY_CIDRS` only for networks that contain proxies you control; up to 16 valid CIDRs are accepted. The direct socket peer is always retained separately from a client address derived from a trusted X-Forwarded-For chain.

Bind hosts must be literal IPv4 or IPv6 addresses; hostnames are rejected so starting a sensor cannot trigger DNS lookups. Use `0.0.0.0` only when the listener should accept connections on every container interface.

Container listeners bind inside the container, while Compose publishes ports on `127.0.0.1`. Change the host-side mapping deliberately if another machine needs access. Keep any public deployment behind network controls and resource limits.

## Events

Events are one-line structured records written to stdout, so Docker, systemd, or a container platform can collect them without a database. JSON Lines is the default; key-value text is optional. Events include a UTC timestamp, event ID, sensor, peer address, and bounded protocol metadata such as HTTP method, sanitized request path, status, and byte counts. Query strings and payloads are omitted because they commonly carry credentials or personal data. Configured honeytoken values and common encodings are redacted from HTTP methods, paths, and opt-in user-agent fields; ambiguous or deeply encoded user-agent values are omitted. HTTP body counting is capped at 64 KiB and discards the bytes after counting them. A client address is added only when the connection came through a configured trusted proxy.

One sink of each type can be enabled purely from the environment — `docker run -e HELIX_SPLUNK_URL=... -e HELIX_SPLUNK_TOKEN=...` needs no TOML file at all. Setting the anchor variable (`*_URL` or `HELIX_LOG_FILE`) appends that sink; use TOML for multiple sinks of one type or custom header maps.

`[[logging.sinks]]` entries fan the same sanitized events out to external collectors. Supported sink types are `file` (append-only JSON Lines), `splunk` (HTTP Event Collector; a bare base URL gets `/services/collector/event` appended), `elasticsearch`/`elk` (the `_bulk` NDJSON API, requiring an `index`; authenticate with `token` as an API key or `username`/`password` as basic auth), and `http` (a generic NDJSON webhook with optional static `headers` or a Bearer `token`). Up to 8 sinks are allowed. Remote sinks batch events asynchronously — up to 64 events or 256 KiB per batch, flushed every second — and drop rather than block when the destination or the queue cannot keep up. Deliveries accept `http` and `https` endpoints, keep TLS certificate verification enabled, never follow redirects, and send at most two attempts per batch. Sink tokens, passwords, and header values are added to the event redaction set so credentials cannot appear in shipped records.

## Kubelet mode

`HELIX_RUN_MODE=kubelet` emulates a kubelet with anonymous read access — the misconfiguration that makes real nodes worth scanning. `/pods` and `/runningpods` return a static workload list for the configured `node_name`, and `/healthz`, `/metrics`, `/metrics/cadvisor`, `/stats/summary`, `/configz`, `/logs/`, and `/containerLogs/<ns>/<pod>/<container>` return bounded plausible data. Streaming endpoints (`/exec`, `/attach`, `/portforward`, `/run`, `/cri`) always refuse with a kubelet-style upgrade error; the attempt is still recorded as an event.

## Kubernetes API profile

Helix defaults to the Kubernetes `v1.37` discovery and version profile and accepts simulated profiles from `v1.19` through `v1.37`. It is a bounded emulator, not a Kubernetes control plane or conformance server. Its in-memory object store is limited to 4,096 objects, 32 MiB total, and 256 KiB per object. List pages contain at most 100 objects and 1 MiB; concurrent list work and watches are capped. Watch replay, bookmarks, and full Kubernetes schema fidelity are not modeled.

The repository contains compressed OpenAPI v2 snapshots through `v1.27`; those are served only for their matching profiles. OpenAPI v3 and a current `v1.37` schema are not modeled yet, so clients requesting them receive a Kubernetes-style `NotFound` response rather than a stale schema presented as current.

## Development

Use Go 1.27 or newer:

```sh
make build
make run
make docker
```

`make run` starts the default Kubernetes sensor. Configuration uses the same environment variables described above. GitHub Actions builds and tests Go packages and the container on pushes and pull requests; pushes to `main`, `develop`, and `v*` tags additionally build multi-arch (amd64/arm64) images with provenance and SBOM attestations and publish them to `ghcr.io/zeerg/helix-honeypot`.

## License

MIT. See [LICENSE.txt](LICENSE.txt).
