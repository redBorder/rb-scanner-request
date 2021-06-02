package main

import (
	// "database/sql"
	"net/http"

	// "github.com/Sirupsen/logrus"
)

// APIClientConfig stores the client api configuration
type APIClientConfig struct {
	Insecure   bool          // If true, skip SSL verification
	URL        string        // API url
	Hash       string        // Required hash to perform the registration
  Auth_token string
	Cpus       int           // Number of CPU of the computer
	Memory     uint64        // Amount of memory of the computer
	DeviceType int           // Type of the requesting device
	//Logger     *logrus.Entry // Logger to use
	HTTPClient *http.Client  // HTTP Client to wrap
}

type scanOptions struct {
  target string
  sensors string
  ports string
}

// response structure for scan request
type Options struct {
  Id int `json:"id"`
  Sensors   []string `json:"sensors"`
  ScanType   int `json:"scan_type"`
  Target   []string `json:"target"`
  Status   string `json:"status"`
  RunAt   string `json:"run_at"`
  ScanHistoryId int `json:"scan_history_id"`
}

type Response struct{
  Query bool `json:"query"`
  ScanRequest Options `json:"scan_request"`
}
var HostDiscovery string = "/opt/rb/bin/rb_host_discovery.sh"
var VulnerabiliesScan string = "/opt/rb/bin/rb_nmap.sh"
//
