# tplink_archer_exporter

Prometheus exporter for TP-Link Archer routers (AX80 and relatives) — the web UI with `;stok=` in the URL.

Verified against an AX80 on firmware 1.4.1.

## Layout

```
cmd/tplink_exporter/  the exporter: flags, HTTP, shutdown
cmd/recon/            endpoint scout — logs in, probes, dumps decrypted JSON
internal/tpapi/       the protocol client: crypto, session, redaction
internal/exporter/    parsers, poll loop, prometheus.Collector
grafana/              importable dashboard
```

Worth re-running `cmd/recon` after a firmware update: a field that changed name goes missing from the snapshot quietly,
not loudly.

## Exporter

Polls ~23 endpoints on its own ticker and serves the last snapshot at
`/metrics`. A scrape never reaches the router: it reads whatever the last poll produced, so Prometheus may scrape as
often as it likes.

```bash
printf '%s' 'router-password' > tplink_password   # gitignored
docker network create monitoring
docker run -d --name tplink-exporter --network monitoring \
  -p 127.0.0.1:9110:9110 \
  -e TPLINK_HOST=192.168.0.1 -e TPLINK_PASSWORD_FILE=/run/secrets/pw \
  -v "$PWD/tplink_password:/run/secrets/pw:ro" \
  ghcr.io/akentyev/tplink_archer_exporter:latest
```

The password goes in through a file because `-e TPLINK_PASSWORD` lands in
`docker inspect` and in `docker compose config` output. The `-p` is there only
so the `curl` below reaches it from this host; the deployment further down
publishes nothing.

It is up within one poll:

```bash
docker logs tplink-exporter                         # "starting", then quiet
curl -s localhost:9110/metrics | grep '^tplink_up'  # 1 once a poll has landed
```

`tplink_up 0` with `tplink_session_blocked 1` means a browser holds the router's session, not that anything is broken —
see [One session](#one-session).

The published image carries `linux/amd64` and `linux/arm64`. Asking one which
build it is needs no configuration — no router, no password:

```bash
docker run --rm --pull=always ghcr.io/akentyev/tplink_archer_exporter:latest -version
```

Without `--pull=always` the answer is whatever `:latest` meant when this host
first pulled it.

Building it here instead — for a change that is not published yet — is
`docker build -t tplink_archer_exporter:local .`, one architecture, the
builder's; `docker-compose.build.yml` does the same within compose.

`docker-compose.yml` is the same with a restart policy and a Docker secret; the
container name is the same one, so `docker rm -f tplink-exporter` first. It
tracks `:latest`, which `up -d` alone does not re-resolve — upgrading is
`docker compose pull && docker compose up -d`. Without a container:

```bash
go build -o bin/tplink_exporter ./cmd/tplink_exporter
TPLINK_HOST=192.168.0.1 TPLINK_PASSWORD='...' ./bin/tplink_exporter
```

**Go 1.26 or later**, and not only for the language: `net.ParseMAC` reads bare twelve-hex only from 1.26 on, and
`vpn?form=vpn_user_devices` spells its device ids that way. On an older toolchain those stay unnormalised and split a
device in two. The Dockerfile pins the patch release and sets `GOTOOLCHAIN=local`, so a container build cannot drift.

```yaml
scrape_configs:
  - job_name: tplink_exporter
    static_configs:
      - targets: [ 'tplink-exporter:9110' ]
```

### Reaching it

The metrics carry the network's MAC addresses, IP addresses, host names and ARP table — the same map this repository
refuses to commit — and nothing here authenticates a scrape. Nothing is exposed by default. Two ways to reach it:

**Over a container network, nothing published.** The default. A scraper joined to the same network reads
`tplink-exporter:9110` directly; the port never appears on the host.

Names resolve on any user-defined network, which includes the one compose creates for a project by itself — a scraper
declared in this same file would need no `networks:` key at all. `monitoring` exists for the scraper that is not in this
file: a separate stack, or a plain `docker run`, which lands on Docker's legacy `bridge` where names do not resolve at
all.

Being `external: true`, it has to exist before either stack starts, and compose refuses to start without it:

```
network monitoring declared as external, but could not be found
```

`docker network create monitoring` once, then the scraper's own compose file declares the same thing:

```yaml
services:
  victoria-metrics:
    networks: [ monitoring ]
networks:
  monitoring:
    name: monitoring
    external: true
```

Neither stack owns it, so `docker compose down` on one leaves the other reachable.

**Published on the host,** when a scraper cannot join that network and the exposure is acceptable — a production scraper
against an exporter on a workstation, for one:

```bash
docker compose -f docker-compose.yml -f docker-compose.expose.yml up -d   # 0.0.0.0:9110
docker run ... -p 9110:9110 ...                                           # the same, without compose
./bin/tplink_exporter -listen :9110                                       # the same, without a container
docker run ... -p 127.0.0.1:9110:9110 ...                                 # narrowed to this host
```

The overlay also drops `external` from the network, so it needs no
`docker network create` — nothing joins the exporter that way when the scraper comes in through the port. Compose makes
its own under a different name, which leaves a real `monitoring` on the same host untouched.

Outside a container the exporter binds `127.0.0.1:9110`, so serving the network takes an explicit `-listen`.

### Configuration

Every flag but `-version` falls back to an environment variable, which is what the container uses; the flag wins when
both are set. `-version` asks a question rather than setting anything, so it has none.

| flag                | env                       | default          | meaning                                          |
|---------------------|---------------------------|------------------|--------------------------------------------------|
| `-host`             | `TPLINK_HOST`             | —                | required; a bare address gets `http://`          |
| `-user`             | `TPLINK_USER`             | `admin`          | the local login has no user field                |
| —                   | `TPLINK_PASSWORD`         | —                | required, or the file below                      |
| `-password-file`    | `TPLINK_PASSWORD_FILE`    | —                | alternative, for a Docker secret                 |
| `-listen`           | `TPLINK_LISTEN`           | `127.0.0.1:9110` | HTTP address; the image sets `:9110`             |
| `-interval`         | `TPLINK_INTERVAL`         | `60s`            | poll period                                      |
| `-timeout`          | `TPLINK_TIMEOUT`          | `30s`            | bounds one whole poll cycle                      |
| `-request-timeout`  | `TPLINK_REQUEST_TIMEOUT`  | `10s`            | per HTTP request                                 |
| `-min-backoff`      | `TPLINK_MIN_BACKOFF`      | `1m`             | first wait after a failed cycle                  |
| `-max-backoff`      | `TPLINK_MAX_BACKOFF`      | `15m`            | ceiling for the backoff and the cooldown         |
| `-session-cooldown` | `TPLINK_SESSION_COOLDOWN` | `5m`             | stay away once losing the session repeats        |
| `-session-renew`    | `TPLINK_SESSION_RENEW`    | `30m`            | replace the session on a schedule; 0 disables it |
| `-push-url`         | `TPLINK_PUSH_URL`         | —                | OTLP receiver; push mode, and no listener at all |
| `-push-label`       | `TPLINK_PUSH_LABELS`      | —                | repeatable `name=value`; comma-separated in env  |
| `-push-buffer`      | `TPLINK_PUSH_BUFFER`      | `300`            | cycles kept unsent while the receiver is down    |
| `-push-timeout`     | `TPLINK_PUSH_TIMEOUT`     | `10s`            | one send, its drain of the buffer included       |
| `-log-level`        | `TPLINK_LOG_LEVEL`        | `info`           | debug, info, warn, error                         |
| `-version`          | —                         | —                | print the version and exit                       |
| —                   | `TZ`                      | the host's       | the zone the router's wall clock is read in      |

There is no `-password` flag on purpose: a flag is visible in `ps`. Only the trailing newline is stripped from either
source, since spaces can be part of a password, and setting both is refused.

An interval under 30s starts with a warning: ~23 requests every few seconds is more than this hardware wants, and it
makes the router's UI slow for whoever else is using it.

### What it says in the log

At `info` a healthy exporter is quiet: one `starting` line and nothing more. Every other line marks a change of state,
so a repeated one is itself the signal.

| line                               | level | means                                                                                                                |
|------------------------------------|-------|----------------------------------------------------------------------------------------------------------------------|
| `starting`                         | info  | the build, then the settings it resolved, password source included; never the password                               |
| `endpoint stopped answering`       | warn  | one source failed, with its path and error. Once per outage, not per cycle                                           |
| `endpoint answering again`         | info  | that source came back                                                                                                |
| `most of the cycle did not answer` | warn  | over half the sources failed at once — usually the session gone mid-cycle                                            |
| `login failed`                     | warn  | `session_blocked=true` means a browser holds the session; anything else is a wrong password or an unreachable router |
| `not logging in`                   | info  | staying away on purpose: the cooldown after a taken session, or the hourly cap                                       |
| `the session was taken`            | warn  | someone logged in to the web UI                                                                                      |
| `polling again`                    | info  | back after a spell of not polling. Once, on the first good cycle                                                     |
| `session renewed`                  | info  | the scheduled replacement, every `-session-renew`                                                                    |
| `the cycle ran out of time`        | warn  | the whole cycle hit `-timeout`; a sick router rather than a lost session                                             |
| `polled`                           | debug | per-cycle duration and how many sources failed                                                                       |

A single dead endpoint is a warn line and nothing else — `tplink_up` stays 1, because a partial snapshot is still
served.

### One session

The AX80 serves **one** web session, and the exporter never takes it from you.
`Force` stays false, so a browser holding the session gets a refused login here, not the other way round:
`tplink_session_blocked` goes to 1 and the poller waits, doubling from `-min-backoff` to `-max-backoff` until the tab is
closed or the router times it out.

**Do not run it on the machine you browse the router from.** That protection is the firmware's, and the firmware defends
a session against other *devices*: a login from the address that already holds one replaces it silently, with no
conflict reported and no warning in the UI. Measured both ways on an AX80 — from a second device the login is refused,
from the same device it succeeds and throws the browser out. Against that case the exporter has only its own rule: one
lost session costs a cycle, a second one within the hour makes it go quiet for
`-session-cooldown` — doubling towards `-max-backoff` while it keeps happening — and it never makes more than six login
attempts an hour, because the firmware carries a two-hour lock for what it reads as concurrent logins. That lock
triggers on multiple devices, not on a rate; the cap is a proxy for it.

While that lasts `tplink_up` is 0 and the snapshot stops advancing — read its age as
`time() - tplink_snapshot_timestamp_seconds` rather than assuming the values are current. A quiet spell can outlast it:
five minutes of cooldown is exactly the staleness window, and the doubling reaches fifteen, at which point
`/metrics` carries the exporter's own health and nothing about the router. Alerts over clients and leases want
`unless tplink_session_blocked == 1`, otherwise every visit to the router's UI raises "device gone".

A session that ends on its own is indistinguishable from one a person took, and two such losses inside an hour are what
send the poller quiet. So it replaces its own every `-session-renew`, 30m by default and 0 to switch it off, rather than
holding one until something ends it: it polls, then logs out and back in at the end of the cycle, on a session it has
just used successfully. A renewal that fails therefore costs no data, and `tplink_session_lost_total` keeps meaning what
it says.

`SIGINT` and `SIGTERM` log out before exiting, which frees the session at once instead of leaving it to expire.

### Metrics

`/metrics` is the list, each with its own HELP line. Speeds are bytes per second, traffic counters are bytes, CPU and
memory are ratios in 0..1 — the units the firmware actually uses, not the ones its UI displays.

These describe the exporter rather than the router:

| metric                                 |                                                                                               |
|----------------------------------------|-----------------------------------------------------------------------------------------------|
| `tplink_exporter_build_info`           | always 1; `version`, `revision` and `go_version` say which build is running                   |
| `tplink_up`                            | 1 when the last poll reached the router                                                       |
| `tplink_session_blocked`               | 1 when the web UI is presumed busy: a refused login, or staying away after losing the session |
| `tplink_session_lost_total`            | cycles that ended with the session gone                                                       |
| `tplink_login_suppressed_total`        | logins held back by the cooldown or the hourly cap                                            |
| `tplink_scrape_errors_total{endpoint}` | endpoint failures since start                                                                 |
| `tplink_endpoints_failed`              | endpoints missing from the snapshot being served                                              |
| `tplink_snapshot_timestamp_seconds`    | when the snapshot being served was taken                                                      |

A cycle that loses one endpoint keeps the rest: the snapshot is assembled from whatever answered, and the failure lands
in `tplink_scrape_errors_total`. So
`tplink_up` at 1 with a climbing error count means partial data, not none —
`tplink_endpoints_failed` says how much.

Once a snapshot is five poll intervals old the collector stops serving it: the router metrics and
`tplink_endpoints_failed` go with it, and what is left is the exporter's own health, including
`tplink_snapshot_timestamp_seconds` — so the age of what is gone stays readable.

`tplink_router_clock_timestamp_seconds` is the router's wall clock, and the firmware reports a TP-Link zone index rather
than an offset — so the exporter reads that clock in its own zone. Set `TZ` to the router's, or the metric shows the
difference between the two zones and calls it drift.

What did not answer is absent rather than zero. A missing `status?form=internet`
publishes no `tplink_wan_status` at all, instead of a 0 that reads as "the internet is down"; the same holds for the
security flags, where a 0 nobody read would be worse.

### Push mode

`-push-url` is the second way to deliver metrics, an alternative to `/metrics` rather than a replacement for it: set it
and the exporter sends every cycle's snapshot as OTLP/HTTP to a receiver instead of serving it, and no HTTP listener
starts at all — `-listen` answers nothing while a push URL is set. Pull needs something to reach the exporter, which on
a workstation-plus-datacenter setup means `0.0.0.0:9110` open to the exporter's whole segment; push makes only the
outbound connection.

A push goes out **after every cycle, including a failed one** — a router that stopped answering has to look different
from an exporter that did, so `tplink_up 0` and the error counters travel exactly when the router does not. The
snapshot's points carry `Snapshot.TakenAt`, the moment the router answered (or the cycle's start, when it never did),
not the moment the batch left. Process metrics (`go_*`, `process_*`) travel too, as a second OTLP body stamped with the
send time instead — they describe "now", and buffering an hour-old goroutine count would describe a moment already
gone.

`job` and `instance` are not something the exporter emits in pull mode; a scraper adds both, from its own config, to
everything it reads back, `go_*`/`process_*` included. Push has no scraper, so the exporter adds them itself, as
attributes on every point of both bodies: `job` defaults to `tplink_exporter`, `instance` to the router's address as
the client holds it, scheme included — a bare `-host 192.168.0.1` becomes `http://192.168.0.1` by the time anything
labels a point, since that is what the client prepends before its first request, not the flag's own text. That is the
reverse of pull, where `instance` is the address of the exporter a scraper reached — **switching mode changes what
`instance` means and splits a series' history across the change**, the same series suddenly reporting under two
different `instance` values with no overlap, and a dashboard variable or alert written against the bare address
matches nothing until it accounts for the scheme. `-push-label name=value`, repeatable, adds anything else
(`env=prod`, `site=home`); one named `job` or `instance` overrides the default instead of adding a second label.

**Alerting is not the same in push, because `tplink_up` still describes the router, not the exporter.** A dead
exporter simply stops sending, so nothing ever reports `tplink_up 0` — there is no scrape to fail and no process to be
missing from it. Watch the data instead: `time() - tplink_push_last_success_timestamp_seconds`, or
`absent_over_time(tplink_up[...])` — and **size that window against `-max-backoff`, not against a few cycles**. A push
rides the poller's cycle, and a login the router refused or never answered arms the poller's backoff, which replaces
the interval rather than adding to it: at the defaults an unreachable router thins the sends out to one every 1, 2, 4,
8 and then 15 minutes, for as long as it stays unreachable. A window a few cycles wide therefore fires on the router's
outage rather than the exporter's, and `tplink_up 0` goes stale between the samples that still carry it; a window above
`-max-backoff` — `20m` against the default `15m` — waits for a real silence. `tplink_session_blocked` rides the same
backoff, since a browser holding the session is a refused login like any other; what keeps the `-interval` rhythm is the
cooldown after a session taken from the exporter mid-cycle, and only that. The pull alert, `tplink_up == 0 unless
tplink_session_blocked == 1`, still means exactly what it always meant — the router is unreachable — it just stops
doubling as the exporter's own health check.

A receiver that is down does not cost a cycle: up to `-push-buffer` snapshots (300 by default, five hours of history at
the 60s default interval) wait in memory, oldest first, and go out with their **original** cycle timestamps once the
receiver answers again — read correctly by anything that keeps the timestamp it was sent, rather than substituting the
time of receipt. What does not fit is dropped and counted, never silently: `tplink_push_dropped_total` is batches
evicted from a full buffer or refused outright by the receiver. Watching an outage through the metrics themselves:
`tplink_push_buffered` climbs and `tplink_push_total{result="failed"}` grows by one a cycle while it lasts; the
receiver's answer, once it comes back, arrives as `tplink_push_total{result="ok"}` jumping by the whole drained batch
in one step rather than one at a time, and `tplink_push_last_success_timestamp_seconds` keeps the time of the last
success before the gap until that jump.

`-push-timeout` bounds one send, the buffer's drain included, and the individual HTTP request inside it — one value,
two ceilings, so it cannot be zero: that would remove both at once.

Shutdown in push mode chains three separate waits, not one. The poller's last cycle still owes it a push — buffer
drain included — capped by `-push-timeout`; its own deferred logout runs next, capped by whichever of `-timeout` and
`-request-timeout` is smaller; only after both does a second, final drain of whatever that push could not deliver run,
capped by a fixed ten seconds that does **not** scale with `-push-timeout`. At default timeouts that is up to thirty
seconds end to end, not the ten `docker stop` waits by default before killing the process. That number is not new:
`docker-compose.yml` in this repository has carried `stop_grace_period: 30s` since its first commit, well before push
mode existed, sized for the logout alone against a configurable `-timeout`/`-request-timeout` — it happens to also
cover push's three-part chain at the defaults, but raising `-push-timeout` grows the chain while that fixed ten
seconds does not shrink to compensate, so the margin narrows; raise `stop_grace_period` by the same amount alongside
it.

Point `-push-url` at a receiver's OTLP/HTTP metrics endpoint, `/opentelemetry/v1/metrics` on VictoriaMetrics:

```bash
docker run -d --rm -p 8428:8428 victoriametrics/victoria-metrics:latest \
  -opentelemetry.promoteAllResourceAttributes=false \
  -opentelemetry.promoteScopeMetadata=false
./bin/tplink_exporter -host 192.168.0.1 \
  -push-url http://127.0.0.1:8428/opentelemetry/v1/metrics
```

The two receiver flags keep the series clean: without them each row also carries `scope.name`, `scope.version`,
`service.name` and `service.instance.id`, promoted from OTLP resource and scope metadata into ordinary labels — none of
it needed, since `job` and `instance` already carry what those would say. Confirmed against
`victoriametrics/victoria-metrics:latest`: rows land with `job`, `instance` and the cycle's timestamp and nothing else;
process metrics carry the same two labels, stamped with the send time instead; a receiver stopped for several cycles
and brought back received the buffered batches first, each with its original timestamp, landing on an instance that
did not exist yet when those cycles ran; `tplink_push_dropped_total` stayed at zero throughout; and nothing answered on
`-listen` for the whole run.

## Dashboard

`grafana/tplink-archer.json` draws the whole snapshot in nine rows — overview, a watchlist of the conditions worth an
alert, WAN, router, clients, DHCP, VPN, exposure, and the exporter's own health beside them so that "no clients" and
"the router did not answer" cannot be confused.

It needs a Prometheus-compatible datasource holding these metrics; VictoriaMetrics serves them through Grafana's
Prometheus datasource type. Dashboards → New → Import → Upload JSON file, then answer the one input, `DS_PROMETHEUS`.
Or:

```bash
curl -sX POST http://grafana:3000/api/dashboards/import -u admin:admin \
  -H 'Content-Type: application/json' \
  -d "{\"dashboard\": $(cat grafana/tplink-archer.json), \"overwrite\": true,
       \"inputs\": [{\"name\": \"DS_PROMETHEUS\", \"type\": \"datasource\",
                     \"pluginId\": \"prometheus\", \"value\": \"DATASOURCE_UID\"}]}"
```

Two variables: `datasource` re-points every panel at once, `instance` picks exporters and defaults to all of them.

`ip` and `hostname` live only in `tplink_client_info`, so a client panel that wants a readable name joins against it on
`(mac, instance)`. The panel descriptions say why `instance` is in there.

A permanent lease has no `tplink_dhcp_lease_expiry_seconds` series, so its expiry cells in the lease table are empty
rather than holding a far-future placeholder, and sorting on "expires in" still puts the soonest first.

## Recon

```bash
go build -o bin/recon ./cmd/recon

TPLINK_HOST=http://192.168.0.1 TPLINK_PASSWORD='...' ./bin/recon -out recon-out
```

Read-only: it sends nothing but reporting operations and never writes settings.

`-host` and `-password` are required and have no defaults — each also reads
`TPLINK_HOST` / `TPLINK_PASSWORD`.

Other flags: `-all` sweeps all 160 endpoints the web UI knows instead of the focus list, `-extra 'admin/foo?form=bar'`
adds your own, `-force` (default on)
evicts an existing web session on `user conflict`, `-debug` logs raw traffic.

Output is `recon-out/<path>.<op>.json` per answering path+operation pair, plus
`index.json` summarising what answered and what did not.

Besides `read`/`load`/`list`, some forms take their own operation names —
`game_accelerator` wants `loadDevice`, `client_speed_limit` wants `read_max`. These were extracted from the router's JS,
so a `no such callback` answer means the endpoint is absent from this firmware build, not that the verb was guessed
wrong.

**The AX80 allows one web session.** Close the browser tab before running, or recon will evict it (with `-force=false`
it refuses instead). It always logs out on exit.

## Protocol

Read out of the router's own JS bundle: `/webpages/js/`, chunks
`update-store-*.js` and `index-J8*.js`.

### Behaviour depends on the device's certification

The firmware keeps a `CertificationService.FEATURE_MAP` table and switches features on according to a list of
certifications served by an endpoint that is **unauthenticated and unencrypted**:

```
POST /cgi-bin/luci/;stok=/device_config?form=config   body: operation=read
  -> {"success":true,"data":{"certification":["SG CLS L1 STAGE2"], ...}}
```

| feature                      | enabled by           | effect on the wire                              |
|------------------------------|----------------------|-------------------------------------------------|
| `2_login_SHA256`             | RG, SG L1 S2, CE RED | `h=` is SHA-256, not MD5                        |
| `5_gdpr`                     | SG L1 S2, CE RED     | bodies and replies are encrypted at all         |
| `12_replace_hash`            | SG L1 S2             | after login `h=` becomes SHA-256 of the payload |
| `13_rsa_pad_with_pkcs1_oaep` | SG L1 S2             | login signature uses OAEP, not PKCS#1 v1.5      |

The reference device reports `["SG CLS L1 STAGE2"]`, so everything is on. A device with a different certification
(`US FCC` and such) has `5_gdpr` off and sends plain form bodies; the client handles both.

### Bootstrap — unauthenticated, unencrypted

```
POST /cgi-bin/luci/;stok=/login?form=keys   body: operation=read
  -> {"success":true,"data":{"password":["<n hex>","<e hex>"],
                             "mode":"router","username":""}}
POST /cgi-bin/luci/;stok=/login?form=auth   body: operation=read
  -> {"success":true,"data":{"key":["<n hex>","<e hex>"],"seq":<int>}}
```

Both moduli are **2048-bit**, hex in upper case. Note the extra scalars in the
`keys` reply: `mode` and `username` sit next to the key pair, so `data` cannot be decoded as `map[string][]string`.

### Session state

1. AES key and IV are **16 random decimal digits** each (`generateRandomIntString`, `KEY_LEN = 128/8`, `IV_LEN = 16`).
   Those ASCII characters go straight in as the 16 AES-128 key bytes. That is ~53 bits of entropy, but it is what the
   firmware expects — the router reads the key back out of the login signature.
2. `h` = SHA-256 (`"admin"` + password). The user name is hardcoded in the firmware; the local login has no field for
   it.
3. `seq` comes from `form=auth` once and never changes.

### Every request

```
data = base64(AES-128-CBC(PKCS#7(body)))   body is urlencoded, "operation=read"
s    = seq + len(data)                     len of the base64 string
```

Then the signature, and here there are two **different** mechanisms:

```
login: sign = RSA( "k=<key>&i=<iv>&h=<h>&s=<s>" )
after: sign = HMAC-SHA256( "h=<h>&s=<s>", key = "k=<key>&i=<iv>" )
```

The AES key travels to the router exactly once, inside the login signature; afterwards the router remembers it and the
signature is just a MAC. RSA is not used at all after login.

Both signatures are cut into **53-character** chunks (`SIGNATURE_OFFSET`) — a flat constant, not derived from the key
size — each chunk sealed separately and the results concatenated as hex.

RSA padding depends on the caller, not the key:

- login password — **PKCS#1 v1.5** (jsbn `pkcs1pad2`), hex left-padded with zeroes to the modulus width;
- login signature — **OAEP** with SHA-1 as both digest and MGF1 hash and an empty label (node-rsa's default) when
  `13_rsa_pad_with_pkcs1_oaep` is on, otherwise v1.5 as well.

With `12_replace_hash`, after login `h` is **overwritten** before signing with
`SHA-256(data)` of the current request, and stays that way for later ones.

The wire body is `sign=<...>&data=<...>` as form data.

### Replies

With encryption on, the router answers `{"data":"<base64>"}`, and the plaintext of that string is the **whole
envelope**, `{"success":..., "errorcode":...,
"data":...}`. Even `success` cannot be read without decrypting first.

### Login and logout

```
POST /cgi-bin/luci/;stok=/login?form=login
  body: operation=login&password=<RSA(password) hex>
```

The web UI adds `confirm=true` only on a **second** attempt, after the router answers `errorCode: "user conflict"` and
the user confirms evicting the other session. Recon does the same under `-force`.

The reply carries `stok`; the cookie carries `sysauth`. Every later path is
`/cgi-bin/luci/;stok=<stok>/admin/<module>?form=<form>`.

Logout is `admin/system?form=logout` with an **empty body** — the UI passes
`undefined`, which serialises to an empty string — not `operation=write`.

### A Go-specific note

Current AX80 firmware serves 2048-bit moduli, so `crypto/rsa` works. But it refuses keys below 1024 bits and some older
Archers hand out 512, so
`internal/tpapi/crypto.go` keeps a hand-rolled PKCS#1 v1.5 path for them.

### Re-deriving it after a firmware update

The same method re-checks the protocol when the firmware changes. Nothing here needs a login, so it costs no web
session.

```bash
curl -s --compressed "$TPLINK_HOST/webpages/index.html"      # --compressed matters: it is gzipped
# -> <script src="./js/index-XXXX.js">, the loader
```

The loader names ~66 chunks; those chunks name more. Crawl `"\./([\w.-]+\.js)"`
recursively until no new names appear — around 276 files, four rounds. Then:

| what                                 | where to grep                                    |
|--------------------------------------|--------------------------------------------------|
| crypto, signatures, `NO_ENCRYPT_URL` | `update-store-*.js`                              |
| login flow, `h=` hash                | `index-J8*.js`                                   |
| feature gates                        | `FeatureEnum`, `CertificationService`            |
| endpoints and their operations       | `.read(`, `.load(`, `.request(X,{operation:"Y"}` |

Two traps worth knowing. Endpoint paths are sometimes assembled from a variable plus a suffix (`` `${n}_2g` ``), so a
literal-only grep misses them and invents forms that do not exist. And operation names are not always `read`/`load` —
resolve the variable holding the URL, then read the operation out of the same call.

Units are decided by the render path, not by the field name: the traffic formatter divides by 1024 against
`["KB","MB","GB","TB"]` (so bytes), the network map multiplies speed by 8 before Kbps (so bytes/s), and the performance
card renders `value * 100` (so ratios, not percent).

## Secrets

The router returns live credentials to ordinary `operation=read` calls: Wi-Fi PSKs for every band (both in `wireless_*`
and inside `status?form=all` as
`wireless_2g_psk_key`), WireGuard and VPN private keys, DDNS passwords and the admin account. A recon tool needs field
**names**, never their values, so masking lives in `internal/tpapi/redact.go` and runs **immediately after a reply is
decrypted**, inside `Client.Call` — not at the writer. A secret cannot leak by accident because it never reaches the
caller.

The rule is default-deny: a field is masked when its name hints at a credential (`pass`, `pwd`, `psk`, `key`, `secret`,
`token`, `credential`, `cert`,
`private`) unless the name *describes* a credential rather than being one:

- suffixes `_version`, `_cipher`, `_type`, `_mode`, `_status`, … — so
  `psk_version: "sae_transition"` and `psk_cipher: "aes"` survive;
- prefixes `support_`, `hide_`, `enable_`, `is_`, … — capability flags such as
  `support_guest_dynpasswd`, `hide_password_recovery`.

The value becomes `<redacted>` but **the field stays**. Numbers and booleans are left alone (a numeric `key` is an
index) and so are empty strings, since "present but unset" is useful signal.

One deliberate over-match: `key` in `game_accelerator` and `device_priority` is a MAC rather than a secret, but it is
indistinguishable by name from the real
`key` in `vpn?form=server`. It is masked; nothing is lost, because the same MAC sits in the neighbouring `mac` field.

Dumps stay private regardless — they carry MAC addresses, IPs, hostnames and SSIDs. `recon-out/` is gitignored for that
reason.

## Tests

```bash
go test ./... -race -shuffle=on
```

Both flags are load-bearing: the poller runs in a goroutine and part of the suite drives it on `testing/synctest` with
fake clocks, and the logging tests replace `slog.SetDefault` globally, so the order they run in has to stay irrelevant.
GitHub Actions runs the same line on every pull request, beside `gofmt`, `go vet`, `go mod tidy -diff`, `staticcheck`,
`go build` and `actionlint`.

`client_test.go` stands up a fake router implementing the server half of the scheme: it parses the login signature
(RSA/OAEP), takes the AES key out of it, checks `s = seq + len(data)` and the credential hash, then verifies the HMAC on
every later request and answers with a sealed envelope. It runs twice — once as a certified device with every feature
on, once as a bare one with no encryption at all.

A fake router proves the wire format is self-consistent, not that the firmware accepts it. That takes a sweep: 156 of
the 164 path-and-operation pairs probed answer on an AX80.
