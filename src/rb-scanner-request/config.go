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
	// SNMP credentials of the scanner. Never part of the enrichment sent to the scripts and Kafka
	SNMP *SNMPConfig `json:"snmp,omitempty"`
	ServiceProvider string `json:"service_provider"`
    ServiceProviderUuid string `json:"service_provider_uuid"`
    Namespace string `json:"namespace"`
    NamespaceUuid string `json:"namespace_uuid"`
    Organization string `json:"organization"`
    OrganizationUuid string `json:"organization_uuid"`
    building string `json:"building"`
    buildingUuid string `json:building_uuid`
	Campus string `json:"campus"`
	CampusUuid string `json:"campus_uuid"`
	Deployment string `json:"deployment"`
	DeploymentUuid string `json:"deployment_uuid"`
	Zone string `json:"zone"`
	ZoneUuid string `json:"zone_uuid"`
	Market string `json:"market"`
	MarketUuid string `json:"market_uuid"`
	Floor string `json:"floor"`
	FloorUuid string `json:"floor_uuid"`
}

// SNMPConfig holds the SNMP credentials the topology scan uses to read LLDP/CDP neighbors
type SNMPConfig struct {
	Version       string `json:"version"`
	Community     string `json:"community"`
	SecurityLevel string `json:"security_level"`
	Username      string `json:"username"`
	AuthProtocol  string `json:"auth_protocol"`
	AuthPassword  string `json:"auth_password"`
	PrivProtocol  string `json:"priv_protocol"`
	PrivPassword  string `json:"priv_password"`
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
	ProfileType  int
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
	ProfileType int `json:"profile_type"`
}

// absolute paths of scripts used
var HostDiscovery string = "/opt/rb/bin/rb_host_discovery.sh"
var VulnerabilitiesScan string = ""
var PortScan string = "/opt/rb/bin/rb_port_scan.sh"
