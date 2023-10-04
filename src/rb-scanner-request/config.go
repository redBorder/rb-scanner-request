package main

import (
	"database/sql"
	"net/http"
	"github.com/sirupsen/logrus"
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
    ServiceProviderUuid string `json:"service_provider_uuid"`
    Namespace string `json:"namespace"`
    NamespaceUuid string `json:"namespace_uuid"`
    Organization string `json:"organization"`
    OrganizationUuid string `json:"organization_uuid"`
    building string `json:"building"`
    buildingUuid string `json:building_uuid`
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

type KafkaConfig struct {
	Broker string `json:"kafka"`
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
var VulnerabilitiesScan string = ""
var PortScan string = "/opt/rb/bin/rb_port_scan.sh"
