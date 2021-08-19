package main

import (
	"database/sql"
	"net/http"
	"github.com/Sirupsen/logrus"
)

// APIClientConfig stores the client api configuration
type APIClientConfig struct {
	Insecure   bool          // If true, skip SSL verification
	URL        string        // API url
	Hash       string        // Required hash to perform the registration
    Auth_token string
	Logger     *logrus.Entry // Logger to use
	HTTPClient *http.Client  // HTTP Client to wrap
}

// structures used to read the scanner sensor config file created by chef
type Sensors struct {
    Sensors []Sensor `json:"sensors"`
}

type Sensor struct {
    Name   string `json:"name"`
    Uuid   string `json:"uuid"`
    Ip     string `json:"ip"`
}

// DatabaseConfig stores the database configuration
type DatabaseConfig struct {
	sqldb  *sql.DB
	dbFile string
	Logger *logrus.Logger // Logger to use
}

// ScannerConfig stores the scanner configuration
type ScannerConfig struct {
	sqldb  *Database
	Logger *logrus.Logger
}

// info of a local job, created from a scan retrieved from the manager and stored in the local db
type Job struct {
	Id     int
	Jobid  int
	Target string
	Ports  string
	Status string
	Pid    int
	Uuid   string
}

// structure to process the scans retrieved from the manager with an api call
type ScanResponse struct{
	Query bool `json:"query"`
	Scans []Scan `json:"scans"`
}

// response structure for scan request
type Scan struct {
	Scan_id     int `json:"scan_id"`
	Target_addr string `json:"target_addr"`
	Target_port string `json:"target_port"`
	Status      string `json:"status"`
}

// absolute paths of scripts used
var HostDiscovery string = "/opt/rb/bin/rb_host_discovery.sh"
var VulnerabiliesScan string = "/opt/rb/bin/rb_scan_vulnerabilities.sh"
var PortScan string = "/opt/rb/bin/rb_port_scan.sh"
