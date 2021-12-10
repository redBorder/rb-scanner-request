package main

import (
	"flag"
	"runtime"
	"time"
	"encoding/json"
	"io/ioutil"
	"os"
	"fmt"
	"syscall"
	"github.com/Sirupsen/logrus"
	"github.com/x-cray/logrus-prefixed-formatter"
)

var version string = "1.0"
var goVersion = runtime.Version()

var sensors Sensors
var db *Database
var scanner *Scanner
var apiClient *APIClient

// Global logger
var logger = logrus.New()

var (
	debug         *bool       // Debug flag
	URL           *string     // API url
	config        *string     // file with sensor information
	sleepTime     *int        // Time between requests
	insecure      *bool       // If true, skip SSL verification
	certFile      *string     // Path to store de certificate
	dbFile        *string     // File to persist the state
	vuls          *string     // Vulnerabilities scan script path
)

func init(){
	debug = flag.Bool("debug", false, "Show debug info")
	URL = flag.String("url", "", "Protocol and hostname to connect")
	config = flag.String("config", "sensor.json", "config file with sensor information")
	dbFile = flag.String("db", "scanjobs.sql", "Database file to persist the state")
	sleepTime = flag.Int("sleep", 60, "Time between requests in seconds")
	insecure = flag.Bool("no-check-certificate", true, "Dont check if the certificate is valid")
	certFile = flag.String("cert", "/opt/rb/etc/chef/client.pem", "Certificate file")
	versionFlag := flag.Bool("version", false, "Display version")
	vuls = flag.String("vuls", "/opt/rb/bin/rb_scan_vulnerabilities.sh", "Vulnerabilities scan script")

	flag.Parse()

	if *versionFlag {
		fmt.Println("RB-SCANNER-REQUEST VERSION:\t", version)
		os.Exit(0)
	}

	initLogger()
	
	// check for mandatory parameters before continuing
	if *URL == "" {
		logger.Error("url of manager is not specified")
		os.Exit(0)
	  }
  
	logger.Info("parameters used by the service :")
	logger.Info("insecure : ", *insecure)
	logger.Info("URL : ", *URL)
	logger.Info("sleeptime : ", *sleepTime)
	logger.Info("config file : ", *config)
    logger.Info("vulnerabilities script path : ", *vuls)
    logger.Info("Scan jobs database: ", *dbFile)

    VulnerabilitiesScan = *vuls

	readConfigFile(*config)
	readDbFile(*dbFile)

	scanner = NewScanner(ScannerConfig{sqldb: db})

	apiClient = NewAPIClient(
		APIClientConfig{
			URL:        *URL,
			Insecure:   *insecure,
			Logger: logrus.NewEntry(logger),
		},
	)

}

func main(){

	logger.Info("start requesting jobs every ", *sleepTime, " seconds")

	// endless for loop that checks for scans and process them as jobs
	for{
		for i := 0; i < len(sensors.Sensors); i++ {
			logger.Info("request scans for sensor with uuid ", sensors.Sensors[i].Uuid)
			scans := scanRequestForSensor(apiClient, sensors.Sensors[i].Uuid)
			
			// loop over all the scans and insert in database if new scan
			for _, s := range scans {
				db.StoreJob(sensors.Sensors[i].Uuid, s)
			}
		}
		logger.Info("finished processing scans from manager ", *URL)

		// loop over all the local jobs in the db and start if new, later check pid if not finished
		var jobs []Job
		jobs, err := db.LoadJobs()
		if err != nil {
		 	logger.Error(err)
		}

		// loop over all jobs, start if they are new and do not have pid
		// check if they are finished if the job has a pid
        for _, j := range jobs {
		 	if (j.Pid > 0) {
				logger.Info("check if scan is still running with ", j.Pid)
				jobExist, err := PidExists(int32(j.Pid))
				if err != nil {
		 			logger.Info(err)
		 		}
		 		if !jobExist {
					logger.Info("job is finished with pid ", j.Pid)
					if _, err := apiClient.jobFinished(j); err != nil {
						logger.Error("could not send finished status to manager for job with id ", j.Id)
					} else {
						if err := db.setJobStatus(j.Id, "finished"); err != nil {
							logger.Error("error setting finished status in database ", err)
						}
					}
		 		}
		 	} else if j.Status == "new" {
				 pid, err := scanner.StartScan(j)
				 if err != nil {
					logger.Error("job could not be started", err)
				 } else {
					if err := db.InsertJobPid(j.Id, pid); err != nil {
						logger.Error("could not insert pid in database", err)
					} else {
						if err := db.setJobStatus(j.Id, "running"); err != nil {
							logger.Error("could not update status of job in database")
						}
					}
				 }
			 }
		}
		time.Sleep(time.Duration(*sleepTime) * time.Second)
	}
	defer db.Close()
}

func initLogger() {
	loglevel, ok := os.LookupEnv("LOG_LEVEL")
    if !ok {
        loglevel = "debug"
    }
    lloglevel, err := logrus.ParseLevel(loglevel)
    if err != nil || *debug {
        lloglevel = logrus.DebugLevel
    }
	logger = &logrus.Logger{
        Out:   os.Stderr,
        Level: lloglevel,
        Formatter: &prefixed.TextFormatter{
            TimestampFormat : "2006-01-02 15:04:05",
        },
	}
}

func readConfigFile(config string) {
	configFile, err := os.Open(config)
	if err != nil {
		logger.Error(err)
		os.Exit(1)
	}
	logger.Info("Successfully Opened sensor.json")
	defer configFile.Close()

	byteValue, _ := ioutil.ReadAll(configFile)
	json.Unmarshal(byteValue, &sensors)

	for i := 0; i < len(sensors.Sensors); i++ {
		logger.Info("Sensor Name: " + sensors.Sensors[i].Name)
		logger.Info("Sensor uuid: " + sensors.Sensors[i].Uuid)
	}
}

func readDbFile(config string) {
	if len(*dbFile) > 0 {
		logger.Info("read database file")
		db = NewDatabase(DatabaseConfig{dbFile: *dbFile})
		if db == nil {
			logger.Errorln("Error opening database")
			halt()
		}
	}
}

func scanRequestForSensor(apiClient *APIClient, uuid string) []Scan {

  logger.Info("request jobs")
  response, err := apiClient.Jobs(uuid)
  
  if err != nil {
	logger.Error(err.Error())
	return nil

  } else {
	logger.Info("successfully retrieved jobs")
	//logger.Info("response query is ", response.Query)
	logger.Info("response query is ", response.Scans)
	 return response.Scans 
  }
  return nil
}

func halt() {
	logger.Error("Halted")
	select {}
}

// function to check if pid of job is still existing
func PidExists(pid int32) (bool, error) {
	if pid <= 0 {
		return false, nil
	}
	proc, err := os.FindProcess(int(pid))
	if err != nil {
		return false, err
	}
	err = proc.Signal(syscall.Signal(0))
	if err == nil {
		return true, nil
	}
	if err.Error() == "os: process already finished" {
		return false, nil
	}
	errno, ok := err.(syscall.Errno)
	if !ok {
		return false, err
	}
	switch errno {
	case syscall.ESRCH:
		return false, nil
	case syscall.EPERM:
		return true, nil
	}
	return false, err
}