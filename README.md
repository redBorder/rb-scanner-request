# rb-scanner-resquest

Application written in GO that checks if the redBorder manager has scans requests on queue.

## Network Topology Discovery

Profile type `2` runs `rb_network_topology.sh`: IPv4 host discovery and traceroute,
without port scanning or expansion from local routes. The target is limited to
1,024 addresses; execution is limited to 300 seconds. Missing hops remain gaps.
This shows observed IP paths, not physical cabling or switch-port attachment.

Complete version-1 snapshots are published to `rb_network_topology` with a broker
acknowledgement. `topology_json` is a JSON string containing nodes and links; retain
it as a string dimension in Druid. The ingestion template is
`resources/druid/network_topology.json`. Adjust it for your installed Druid version
and broker configuration before deploying. Events are capped at 900,000 encoded bytes.

Deploy the matching web UI first (including `/fail` and capability filtering), then
Kafka/Druid ingestion and this agent. Polls advertise `profile_types=0,1,2`;
unsupported types are rejected rather than dispatched as vulnerability scans.
The web UI selects a scan and authorized scanner viewpoint independently. It may
show pending results briefly while Druid catches up. No SQL migration is needed.

Requirements: Nmap with privileges for traceroute, Ruby with REXML and Poseidon,
and the packaged wrapper/script under `/usr/lib/redborder`. Tests perform no scans:

```
ruby test/network_topology_test.rb
# After preparing Go dependencies, from src/rb-scanner-request:
go test -race ./...
```

Process failures are persisted and reported using `/fail`; cancelled process groups
are stopped together. A lost process after restart is treated as failed unless its
completion was already persisted. HTTP calls have a 30-second timeout. Existing
UUID-only callback authentication and the default TLS setting are unchanged.

## Installing

To install this application ensure you have the `GOPATH` environment variable

1. Clone this repo and cd to the project


2. Install dependencies and compile

```
glide install
make
```

## Usage

Usage of **rb-scanner-resquest** and default values:

```
-daemon
  	Start in daemon mode
-hash string
  	Hash to use in the request (default: UUID located in /opt/rb/etc/rb-uuid)
-log string
  	Log file (default "log")
-no-check-certificate
  	Dont check if the certificate is valid
-pid string
  	File containing PID (default "pid")
-sleep int
  	Time between requests in seconds (default 60)
-url string
  	Protocol and hostname to connect (default "http://localhost")
-vuls string
    Set the vulnerabilities scanner script path (default: "/opt/rb/bin/rb_scan_vulnerabilities.sh")
-config string
    Set the configuration file path (default: "./sensor.json")
-db string
    Set the sql database file path (default: "./scanjobs.sql")            	
```
