# Banner Fingerprint

Golang client + server banner fingerprinting system. The server loads JSON rules once at startup, exposes an HTTP API, and runs in Docker Compose. The client is a host-side CLI.

## Start Server

```bash
docker compose up -d --build
curl -i http://localhost:8080/health
```

Expected health response:

```json
{"status":"ok"}
```

## Run Client

From this directory:

```bash
go build ./...
go run ./cmd/client -server http://localhost:8080 -file data/input.json
```

Raw JSON output:

```bash
go run ./cmd/client -server http://localhost:8080 -file data/input.json -json
```

## API

```http
GET /health
POST /fingerprint
```

`POST /fingerprint` accepts:

```json
[
  {"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"}
]
```

It returns:

```json
[
  {
    "ip":"1.2.3.4",
    "port":22,
    "protocol":"SSH",
    "product":"OpenSSH",
    "version":"8.9p1",
    "os_hint":"Ubuntu",
    "confidence":0.95
  }
]
```

## Rules

All fingerprint knowledge lives in `rules/fingerprints.json`. The engine only loads rules, sorts by priority, matches each rule, extracts fields through rule-provided regex/template pairs, and applies confidence penalties:

- version extraction failure: `-0.2`
- product extraction failure: `-0.2`
- final confidence clamped to `0..1`

Invalid rules are skipped during startup. If no valid rules remain, the server exits. Runtime misses or dirty banner data return `protocol:"unknown"` without panicking.

## Self Test

The included `data/input.json` contains 23 records covering:

- SSH: OpenSSH 8.9p1 Ubuntu, 9.3 Debian, 4.3
- HTTP: nginx, Apache, Jetty, Microsoft-IIS
- MySQL handshake banners
- Redis `+PONG`, `-ERR`, `-NOAUTH`
- FTP ProFTPD, vsFTPd, Pure-FTPd
- TLS record prefixes
- unknown and dirty data

Run:

```bash
docker compose up -d --build
go run ./cmd/client -file data/input.json
```

Expected: all 23 rows return a result, and unrecognized samples return `protocol` as `unknown`.

## Validation

```bash
go vet ./...
go build ./...
docker compose up -d --build
curl -fsS http://localhost:8080/health
go run ./cmd/client -file data/input.json
docker compose ps
```

Container hardening:

- multi-stage build from `golang:1.22-alpine` to `gcr.io/distroless/static-debian12:nonroot`
- `USER 65532:65532`
- `read_only: true`
- `/tmp` tmpfs
- `cap_drop: [ALL]`
- `security_opt: no-new-privileges:true`
- only `8080:8080` is published
- healthcheck runs `/app/server healthcheck`, which performs a real HTTP GET to `/health`
