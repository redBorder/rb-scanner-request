package main

import (
	"flag"
	"runtime"
	 "time"
//  "fmt"
	//"strings"
	"strconv"
	"os"
	"github.com/sirupsen/logrus"
	"github.com/x-cray/logrus-prefixed-formatter"
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
	//daemonFlag    *bool       // Start in daemon mode
	pid           *string     // Path to PID file
	scriptFile    *string     // Script to call after the certificate has been obtained
	scriptLogFile *string     // Log to save the result of the script called
	//si            *sysinfo.SI // System information
  auth_token    *string     // API url auth_token
)


func init(){
  // scriptFile = flag.String("script", "/opt/rb/bin/rb_scan_vulnerabilities.sh", "Script to call after the certificate has been obtained")
	debug = flag.Bool("debug", false, "Show debug info")
  UUIDhash = flag.String("hash", UUID, "Hash to use in the request")
	apiURL = flag.String("url", "https://10.0.203.100/api/v1/scanner/", "Protocol and hostname to connect")
  auth_token = flag.String("auth-token", "4u29xzXa5vMVJd9fxNsW1Bc5eBrmRmu29ooUGqKr", "Authentication token")
	sleepTime = flag.Int("sleep", 60, "Time between requests in seconds")
	//insecure = flag.Bool("no-check-certificate", false, "Dont check if the certificate is valid")
	//certFile = flag.String("cert", "/opt/rb/etc/chef/client.pem", "Certificate file")
	//daemonFlag = flag.Bool("daemon", false, "Start in daemon mode")
	pid = flag.String("pid", "pid", "File containing PID")
	versionFlag := flag.Bool("version", false, "Display version")

	flag.Parse()

	if *versionFlag {
		displayVersion()
		os.Exit(0)
	}

	logger = &logrus.Logger{
        Out:   os.Stderr,
        Level: logrus.DebugLevel,
        Formatter: &prefixed.TextFormatter{
            TimestampFormat : "2006-01-02 15:04:05",
            FullTimestamp:true,
            ForceFormatting: true,
        },
    }

	// f, _ := os.OpenFile(*logFile, os.O_APPEND | os.O_CREATE | os.O_RDWR, 0666)
	// logger.SetOutput(f)
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

	// if *daemonFlag {
	// 	daemonize()
		for{
			scanRequest(apiClient)
			// wait until the next request
			time.Sleep(time.Duration(*sleepTime) * time.Second)
		}
	// } else {
	// 	// Single Request
	// 	scanRequest(apiClient)
	// }
}

func scanRequest(apiClient *APIClient,){

	request, err, request_json := apiClient.GetScanRequest()
	
  if err != nil {
    logger.Errorf(err.Error())
  } else {
		if checkSensor(request.ScanRequest.Sensors){
			if checkDate(request.ScanRequest.RunAt){
				if *debug == true {
					logger.Infoln("Request taken: " + strconv.Itoa(request.ScanRequest.Id))
					logger.Infoln("\n" + request_json)
				}
				response := RunScan(request)
				if response {
					logger.Infoln("Starting scan fo scan request [" + strconv.Itoa(request.ScanRequest.Id) + "]")
					apiClient.UpdateScanRequest(request.ScanRequest.Id)
					if *debug == true {
						logger.Infoln("Removed UUID from Scan Request [" + strconv.Itoa(request.ScanRequest.Id) + "]")
					}
				}
			}
		}
  }
}
