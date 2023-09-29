package main

import (
  "os/exec"
  "github.com/Sirupsen/logrus"
  "strconv"
  "encoding/json"
)

// Database handles the connection with a SQL Database
type Scanner struct {
	config ScannerConfig
}

// NewDatabase creates a new instance of a database
func NewScanner(config ScannerConfig) *Scanner {
	scan := &Scanner{
		config: config,
	}

	if scan.config.Logger == nil {
		scan.config.Logger = logrus.New()
	}

	return scan
}

func Enrichment(j Job, sensors Sensors) (enrichSensor string) {
   logger := db.config.Logger
   for i := 0; i < len(sensors.Sensors); i++ {
        if j.Uuid == sensors.Sensors[i].Uuid {
             json_struct, err := json.Marshal(sensors.Sensors[i])
             if err != nil {
                logger.Error("malformed namespace info in config file")
             }
             response := string(json_struct)
             return response
        }
   }
   return "{}"
}

func (scan *Scanner) StartScan(j Job, sensors Sensors) (pid int, err error) {
    enrich := Enrichment(j, sensors)
    broker := kafkaConfig.Broker
    logger := db.config.Logger
    logger.Info("Enrichment: ", enrich)
    logger.Info("start scan for id ", j.Id)
    logger.Info("kafka ", broker)
    logger.Info("ports ", j.Ports)
    logger.Info("target ", j.Target)
    logger.Info("job type ", j.JobType)
    if j.JobType == 0 {
      cmd := exec.Command(VulnerabilitieScript,"-t",j.Target,"-p",j.Ports,"-s",strconv.Itoa(j.Jobid),"-k",broker,"-d", "-e", enrich)
    } else {
      cmd := exec.Command(HostDiscoveryScript,"-t",j.Target,"-s",strconv.Itoa(j.Jobid),"-k",broker,"-d", "-e", enrich)
    }
    err = cmd.Start()
    if err != nil {
		return 0, err
	} else {
		logger.Info("started new job with pid ", cmd.Process.Pid)
		go cmd.Wait()
		return cmd.Process.Pid, nil
	}
}

func (scan *Scanner) CancelScan(job_pid int)(err error) {
   job_pid_s := strconv.Itoa(job_pid)
   logger.Warning("DANGEROUSLY KILLING SCAN WITH PKILL")
   Kill := "/usr/bin/pkill"
   cmd := exec.Command(Kill, "-P", job_pid_s)
   err = cmd.Start()
   if err == nil {
     logger.Info("killing job with pid ", job_pid_s)
     go cmd.Wait()
   } else {
	   logger.Error("Error killing to cancel process: ", err)
   }
   return err
}