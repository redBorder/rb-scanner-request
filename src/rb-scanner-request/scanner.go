package main

import (
  "os/exec"
  "github.com/Sirupsen/logrus"
  "strconv"
  "encoding/json"
)

var kafkaConfig *KafkaConfig

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
	logger := db.config.Logger
    logger.Info("Enrichment: ", enrich)
	logger.Info("start scan for id ", j.Id)
	broker := kafkaConfig.Broker
	cmd := exec.Command(VulnerabilitiesScan,"-t",j.Target,"-p",j.Ports,"-s",strconv.Itoa(j.Jobid),"-e",enrich, "-k", broker)
	err = cmd.Start()
	if err != nil {
		return 0, err
	} else {
		logger.Info("started new job with pid ", cmd.Process.Pid)
		go cmd.Wait()
		return cmd.Process.Pid, nil
	}
}
