# rb-scanner-resquest

Application written in GO that checks if the redBorder manager has scans requests on queue.

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
-vulnerabilities-script string
    Set the vulnerabilities scanner script path (default: "/opt/rb/bin/rb_scan_vulnerabilities.sh")
-hostdiscovery-script string
    Set the vulnerabilities scanner script path (default: "/opt/rb/bin/rb_host_discovery.sh")
-config string
    Set the configuration file path (default: "./sensor.json")
-db string
    Set the sql database file path (default: "./scanjobs.sql")            	
```
