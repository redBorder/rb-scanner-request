package main

import (
	"flag"
	 //"io/ioutil"
	//"os"
	"runtime"
	// "strings"
	 "time"
  "fmt"

	// "github.com/Sirupsen/logrus"
	// "github.com/capnm/sysinfo"
)

var version string
var goVersion = runtime.Version()

var (
	debug         *bool       // Debug flag
	apiURL        *string     // API url
	hash          *string     // Required hash to perform the registration
	deviceAlias   *string     // Given alias of the device
	sleepTime     *int        // Time between requests
	insecure      *bool       // If true, skip SSL verification
	certFile      *string     // Path to store de certificate
	dbFile        *string     // File to persist the state
	daemonFlag    *bool       // Start in daemon mode
	pid           *string     // Path to PID file
	logFile       *string     // Log file
	nodenameFile  *string     // File to store nodename
	scriptFile    *string     // Script to call after the certificate has been obtained
	scriptLogFile *string     // Log to save the result of the script called
	//si            *sysinfo.SI // System information
  auth_token    *string     // API url auth_token
)

// Global logger
//var logger = logrus.New()

func init(){
  scriptFile = flag.String("script", "/opt/rb/bin/rb_register_finish.sh", "Script to call after the certificate has been obtained")
	debug = flag.Bool("debug", false, "Show debug info")
  hash = flag.String("hash", "00000000-0000-0000-0000-000000000000", "Hash to use in the request")

	apiURL = flag.String("url", "https://10.0.203.100/api/v1/scanner/", "Protocol and hostname to connect")
  auth_token = flag.String("auth-token", "4u29xzXa5vMVJd9fxNsW1Bc5eBrmRmu29ooUGqKr", "Authentication token")

	sleepTime = flag.Int("sleep", 60, "Time between requests in seconds")
	deviceAlias = flag.String("type", "", "Type of the registering device")
	insecure = flag.Bool("no-check-certificate", false, "Dont check if the certificate is valid")
	certFile = flag.String("cert", "/opt/rb/etc/chef/client.pem", "Certificate file")
	dbFile = flag.String("db", "", "File to persist the state")
	daemonFlag = flag.Bool("daemon", false, "Start in daemon mode")
	pid = flag.String("pid", "pid", "File containing PID")
	logFile = flag.String("log", "log", "Log file")
	nodenameFile = flag.String("nodename", "", "File to store nodename")
	//versionFlag := flag.Bool("version", false, "Display version")

	flag.Parse()

	// if *versionFlag {
	// 	displayVersion()
	// 	os.Exit(0)
	// }

	// Init logger
	// if *debug {
	// 	logger.Level = logrus.DebugLevel
	// }

}

func main(){
	apiClient := NewAPIClient(
		APIClientConfig{
			URL:        *apiURL,
			Hash:       *hash,
      Cpus:       4,
    	Memory:     1024,
    	DeviceType: 1,
      Auth_token: *auth_token,
			Insecure:   true,
		},
	)

	daemonize()
	for{
		scanRequest(apiClient)
		// wait until the next request
		time.Sleep(time.Duration(*sleepTime) * time.Second)
	}
}

func scanRequest(apiClient *APIClient,){

	request, err := apiClient.GetScanRequest()

  if err != nil {
    fmt.Println(err)
  } else {
    fmt.Println(request)

		if checkSensor(request.ScanRequest.Sensors){
			fmt.Println("\nThis request is mine")
			//RunScan(request)

			if checkDate(request.ScanRequest.RunAt){
				fmt.Println("Its time for this request")
				RunScan(request)
			} else {
				fmt.Println("Not time for this request")
			}

			apiClient.UpdateScanRequest(request.ScanRequest.Id, UUID)
		} else {
			fmt.Println("\nThis request is not mine")
		}
  }

}
