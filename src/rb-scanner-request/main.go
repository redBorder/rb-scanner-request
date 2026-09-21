package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/sirupsen/logrus"
	"github.com/x-cray/logrus-prefixed-formatter"
	"io/ioutil"
	"os"
	"runtime"
	"strconv"
	"syscall"
	"time"
)

var version string = "1.0"
var goVersion = runtime.Version()

var kafkaConfig *KafkaConfig
var sensors Sensors
var db *Database
var scanner *Scanner
var apiClient *APIClient

// Global logger
var logger = logrus.New()

var (
	debug     *bool   // Debug flag
	URL       *string // API url
	config    *string // file with sensor information
	sleepTime *int    // Time between requests
	insecure  *bool   // If true, skip SSL verification
	certFile  *string // Path to store de certificate
	dbFile    *string // File to persist the state
	vuls      *string // Vulnerabilities scan script path
)

var vulnerabilities_path = "/usr/lib/redborder/bin/rb_scan_vulnerabilities.sh"
var networkmap_path = "/usr/lib/redborder/bin/rb_host_discovery.sh"
var topology_path = "/usr/lib/redborder/bin/rb_network_topology.sh"

func initialize() {
	debug = flag.Bool("debug", false, "Show debug info")
	URL = flag.String("url", "", "Protocol and hostname to connect")
	config = flag.String("config", "sensor.json", "config file with sensor information")
	dbFile = flag.String("db", "scanjobs.sql", "Database file to persist the state")
	sleepTime = flag.Int("sleep", 60, "Time between requests in seconds")
	insecure = flag.Bool("no-check-certificate", true, "Dont check if the certificate is valid")
	certFile = flag.String("cert", "/opt/rb/etc/chef/client.pem", "Certificate file")
	versionFlag := flag.Bool("version", false, "Display version")
	vuls = flag.String("vuls", "/usr/lib/redborder/bin/rb_scan_vulnerabilities.sh", "Vulnerabilities scan script")

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
			URL:      *URL,
			Insecure: *insecure,
			Logger:   logrus.NewEntry(logger),
		},
	)

}

func main() {
	initialize()
	defer db.Close()
	logger.Info("start requesting jobs every ", *sleepTime, " seconds")

	// endless for loop that checks for scans and process them as jobs
	for {
		for i := 0; i < len(sensors.Sensors); i++ {
			logger.Info("request scans for sensor with uuid ", sensors.Sensors[i].Uuid)
			scans := scanRequestForSensor(apiClient, sensors.Sensors[i].Uuid)

			// loop over all the scans and insert in database if new scan
			for _, s := range scans {
				if err := db.StoreJob(sensors.Sensors[i].Uuid, s); err != nil {
					logger.Error("could not store scan: ", err)
				}
				logger.Info("scan id: ", strconv.Itoa(s.Scan_id))
				logger.Info("status: ", s.Status)
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
			if j.Status == "completed" || j.Status == "error" {
				setJobFinished(j)
				continue
			}
			if j.Pid > 0 {
				logger.Info("Check if scan is still running with Pid ", j.Pid)
				jobExist, err := PidExists(int32(j.Pid))
				if err != nil {
					logger.Info(err)
				}
				if j.Status == "cancelling" {
					logger.Info("cancelling job with pid ", j.Pid)
					if err := scanner.CancelScan(j.Pid); err != nil {
						logger.Error("could not cancel scan: ", err)
					}
				}
				if !jobExist && err == nil {
					logger.Info("Job doesn't exist anymore ", j.Pid)
					logger.Info("status ", j.Status)
					// Recover jobs interrupted by an agent restart without claiming success.
					status := "error"
					if j.Status == "cancelling" {
						status = "completed"
					}
					db.config.sqldb.Exec("UPDATE Scanjobs SET Status = ? WHERE Id = ? AND Status IN ('running', 'cancelling')", status, j.Id)
				}
			} else if j.Status == "new" {
				_, err := json.MarshalIndent(j, "", "  ")

				var scriptPath string

				switch j.ProfileType {
				case 0:
					scriptPath = *vuls
				case 1:
					scriptPath = networkmap_path
				case 2:
					scriptPath = topology_path
				default:
					logger.Errorf("Unsupported profile type %d", j.ProfileType)
					db.setJobStatus(j.Id, "error")
					continue
				}

				pid, err := scanner.StartScan(j, sensors, scriptPath)
				if err != nil {
					logger.Error("job could not be started", err)
					db.setJobStatus(j.Id, "error")
				} else {
					logger.Info("started pid ", pid)
				}
			} else if j.Status == "cancelling" {
				logger.Info("New job is actually canceled -> lets finish its")
				setJobFinished(j)
			}
		}
		time.Sleep(time.Duration(*sleepTime) * time.Second)
	}
}
func setJobFinished(j Job) {
	logger.Info("job is finished with pid ", j.Pid)
	if _, err := apiClient.jobFinished(j); err != nil {
		logger.Error("could not send finished status to manager for job with id ", j.Id)
	} else {
		status := "finished"
		if j.Status == "error" {
			status = "failed"
		}
		if err := db.setJobStatus(j.Id, status); err != nil {
			logger.Error("error setting finished status in database ", err)
		}
	}
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
			TimestampFormat: "2006-01-02 15:04:05",
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
	json.Unmarshal(byteValue, &kafkaConfig)
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
	} else {
		logger.Info("successfully retrieved jobs")
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
