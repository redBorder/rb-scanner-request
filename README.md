# rb-scanner-resquest

Application written in GO that checks if the redBorder manager has scans requests on queue.

## Installing

To install this application ensure you have the `GOPATH` environment variable

1. Clone this repo and cd to the project


2. Install dependencies and compile

```
git build .
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
  	Time between requests in seconds (default 300)
-url string
  	Protocol and hostname to connect (default "http://localhost")
```
