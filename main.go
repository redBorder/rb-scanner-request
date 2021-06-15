package main

import (
	"flag"
	"runtime"
	 "time"
//  "fmt"
	"strconv"
	"os"
	"github.com/sirupsen/logrus"
)

var version string = "1.0"
var goVersion = runtime.Version()

// Global logger
var logger = logrus.New()

var (
	debug         *bool       // Debug flag
	apiURL        *string     // API url
	UUIDhash      *string     // Required hash to perform the registration
	deviceAlias   *string     // Given alias of the device
	sleepTime     *int        // Time between requests
	insecure      *bool       // If true, skip SSL verification
	certFile      *string     // Path to store de certificate
	dbFile        *string     // File to persist the state
	daemonFlag    *bool       // Start in daemon mode
	pid           *string     // Path to PID file
	logFile       *string     // Log file
	scriptFile    *string     // Script to call after the certificate has been obtained
	scriptLogFile *string     // Log to save the result of the script called
	//si            *sysinfo.SI // System information
  auth_token    *string     // API url auth_token
)


func init(){
  scriptFile = flag.String("script", "/opt/rb/bin/rb_register_finish.sh", "Script to call after the certificate has been obtained")
	debug = flag.Bool("debug", false, "Show debug info")
  UUIDhash = flag.String("hash", UUID, "Hash to use in the request")
	apiURL = flag.String("url", "https://10.0.203.100/api/v1/scanner/", "Protocol and hostname to connect")
  auth_token = flag.String("auth-token", "4u29xzXa5vMVJd9fxNsW1Bc5eBrmRmu29ooUGqKr", "Authentication token")
	sleepTime = flag.Int("sleep", 60, "Time between requests in seconds")
	deviceAlias = flag.String("type", "", "Type of the registering device")
	//insecure = flag.Bool("no-check-certificate", false, "Dont check if the certificate is valid")
	//certFile = flag.String("cert", "/opt/rb/etc/chef/client.pem", "Certificate file")
	//dbFile = flag.String("db", "", "File to persist the state")
	logFile = flag.String("log", "log", "Log file")
	daemonFlag = flag.Bool("daemon", false, "Start in daemon mode")
	pid = flag.String("pid", "pid", "File containing PID")
	versionFlag := flag.Bool("version", false, "Display version")

	flag.Parse()

	if *versionFlag {
		displayVersion()
		os.Exit(0)
	}
	customFormatter := new(logrus.TextFormatter)
	customFormatter.TimestampFormat = "2006-01-02 15:04:05"
	logger.SetFormatter(customFormatter)
	customFormatter.FullTimestamp = true
}

func main(){
	apiClient := NewAPIClient(
		APIClientConfig{
			URL:        *apiURL,
			Hash:       *UUIDhash,
      Auth_token: *auth_token,
			Insecure:   true,
			Logger: logrus.NewEntry(logger),
		},
	)

	if *daemonFlag {
		daemonize()
		for{
			scanRequest(apiClient)
			// wait until the next request
			time.Sleep(time.Duration(*sleepTime) * time.Second)
		}
	} else {
		// Single Request
		scanRequest(apiClient)
	}
}

func scanRequest(apiClient *APIClient,){

	request, err := apiClient.GetScanRequest()

  if err != nil {
    logger.Errorf(err.Error())
  } else {
    //fmt.Println(request)

		if checkSensor(request.ScanRequest.Sensors){
			logger.Infoln("This request is mine")

			if checkDate(request.ScanRequest.RunAt){
				logger.Infoln("Its time for this request")
				response := RunScan(request)
				if response {
					apiClient.UpdateScanRequest(request.ScanRequest.Id)
					logger.Infoln("Removed UUID from Scan Request [" + strconv.Itoa(request.ScanRequest.Id) + "]")
				}
			} else {
				apiClient.config.Logger.Infoln("Not time for this request")
				logger.Infoln("Not time for this request")
			}
		} else {
			logger.Infoln("This request is not mine")
		}
  }

}
