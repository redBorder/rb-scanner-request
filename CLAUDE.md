# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`rb-scanner-request` is a Go daemon that polls a redBorder manager for pending
vulnerability/network scan jobs, runs the corresponding scan script locally as a
subprocess, tracks job state in a local SQLite database, and reports completion back
to the manager. It runs as a systemd service (`resources/systemd/redborder-scanner.service`)
on redBorder sensor nodes and is packaged as an RPM.

## Build, test, and run

All Go source lives in `src/rb-scanner-request/` — always run Go commands from that
directory (there's no top-level `go.mod`; one is generated on demand).

```
cd src/rb-scanner-request

make            # go mod init/tidy/vendor, then go build -o rb-scanner-request
make test       # go test -race -v (note: no *_test.go files currently exist)
make coverage   # go test -covermode=count + go tool cover
make clean      # removes binary and vendor/
```

From the repo root, `make` (top-level Makefile) delegates into
`src/rb-scanner-request/` and copies the resulting binary to the repo root.
`make rpm` builds the RPM via `packaging/rpm/`.

Run the binary directly for local testing (see README.md for full flag list):

```
./rb-scanner-request -url http://localhost -config ./sensor.json -db ./scanjobs.sql -sleep 60
```

`-url` is mandatory; the process exits immediately if it's not set. `-vuls` points to
the vulnerability scan script (default `/usr/lib/redborder/bin/rb_scan_vulnerabilities.sh`
in the RPM install, `/opt/rb/bin/rb_scan_vulnerabilities.sh` per the flag default in code).

There is no linter configured; there are currently no Go tests in the repo despite the
`make test`/`make coverage` targets existing.

## Commit conventions

- Never add a "Co-Authored-By" line, "Generated with Claude Code" note, or any other
  attribution to Claude/Claude Code in commit messages.
- Keep commit messages short and descriptive — get to the point, no filler.
- Do not use conventional-commit prefixes (`feat:`, `fix:`, `bug:`, etc.).
- Split changes into separate commits by the files/area they touch — don't bundle
  unrelated files into a single commit.

## Architecture

Single Go package (`main`) split by responsibility across a handful of files, wired
together in `main.go`'s `init()`/`main()`:

- **`main.go`** — flag parsing, logger setup, and the top-level poll loop. On every
  `-sleep` tick it: (1) calls the API for each configured sensor to fetch new scans and
  upserts them into the local DB (`StoreJob`), then (2) walks all non-finished local jobs
  and either starts a new one (`Status == "new"`), checks whether a running one
  (`Pid > 0`) has exited or should be cancelled, or finalizes a job that was marked
  `"cancelling"` before it ever got a PID.
- **`config.go`** — shared struct definitions only (no logic): `Sensor`/`Sensors` (parsed
  from the sensor config JSON file, e.g. `sensor.json`), `KafkaConfig`, `Job` (local DB
  row), `Scan`/`ScanResponse` (API wire format), and the `*Config` structs used to
  construct `APIClient`/`Database`/`Scanner`.
- **`client.go`** — `APIClient`, a thin HTTP wrapper around two manager endpoints:
  `GET /api/v1/sensors/{uuid}/scans` (fetch pending scans) and
  `PUT /api/v1/sensors/{uuid}/scans/{jobid}/finish` (report completion). Honors
  `-no-check-certificate` for TLS verification.
- **`database.go`** — `Database`, a `mattn/go-sqlite3`-backed store for the `Scanjobs`
  table. Owns job lifecycle transitions (`new` → `running` → `finished`, plus
  `cancelling`) and a startup migration (`migrateScanJobs`) that adds the `ProfileType`
  column to older DBs in place — follow this pattern (inspect `pragma_table_info`, then
  `ALTER TABLE` conditionally) for future schema changes rather than dropping/recreating.
- **`scanner.go`** — `Scanner`, launches the scan as a detached OS subprocess
  (`os/exec`) with `-t <target> -p <ports> -s <jobid> -k <kafka broker> -d -e <enrichment
  JSON>`, and can cancel a running scan by `pkill`-ing its child processes. `Enrichment()`
  looks up the sensor matching a job's UUID in the parsed sensor config and serializes it
  to JSON to pass along to the script.

### Job routing by profile type

`Job.ProfileType` (also present on the API's `Scan` struct) selects which external
script `main.go` invokes when starting a job: `0` → vulnerabilities script (`-vuls`
flag / `vulnerabilities_path`), `1` → network/host discovery script
(`networkmap_path`, currently hardcoded, not exposed as a flag). Unknown values log a
warning and fall back to the vulnerabilities script. The actual scan scripts live under
`resources/bin/` (shell wrappers) and `resources/scripts/` (Ruby implementations) and
are installed to `/usr/lib/redborder/bin` and `/usr/lib/redborder/scripts` by the RPM —
they are invoked as external processes, not called into from Go.

### Process/PID tracking

Scans are long-running external processes. The daemon does not keep them in memory
across loop iterations — job state is entirely reconstructed each tick by re-reading
non-finished jobs from SQLite and checking `Pid` liveness via `PidExists` (a
signal-0-based check in `main.go`), so the loop is safe to restart at any time without
losing track of in-flight scans.

### Packaging

- `packaging/rpm/rb-scanner-request.spec` + `packaging/rpm/Makefile` build the RPM via
  `mock`, using `git describe` for versioning (`VERSION` file at repo root is used by CI
  for release tagging, not by the RPM build itself).
- `.github/workflows/rpm.yml` builds and publishes the RPM as a GitHub release on every
  push to `master`/`main`, tagged from the `VERSION` file; it fails fast if that tag
  already exists.
- `src/rb-scanner-request/glide.yaml` reflects an older dependency setup (glide); the
  current build uses Go modules (`make vendor` runs `go mod init/tidy/vendor`) — treat
  `glide.yaml` as stale/historical rather than authoritative for dependencies.
