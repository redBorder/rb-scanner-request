package main

import (
  "os/exec"
  "github.com/sirupsen/logrus"
  "strconv"
  "encoding/json"
  "os"
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
             // the enrichment ends up in Kafka, so it must not carry the SNMP credentials
             sensor := sensors.Sensors[i]
             sensor.SNMP = nil
             json_struct, err := json.Marshal(sensor)
             if err != nil {
                logger.Error("malformed namespace info in config file")
             }
             response := string(json_struct)
             return response
        }
   }
   return "{}"
}

// SNMPEnv returns the RB_SNMP_* variables for the sensor of the job, or nil if it has no SNMP settings
func SNMPEnv(j Job, sensors Sensors) []string {
   for _, sensor := range sensors.Sensors {
        if j.Uuid != sensor.Uuid || sensor.SNMP == nil || sensor.SNMP.Version == "" {
             continue
        }
        c := sensor.SNMP
        return []string{
             "RB_SNMP_VERSION=" + c.Version,
             "RB_SNMP_COMMUNITY=" + c.Community,
             "RB_SNMP_SECURITY_LEVEL=" + c.SecurityLevel,
             "RB_SNMP_USERNAME=" + c.Username,
             "RB_SNMP_AUTH_PROTOCOL=" + c.AuthProtocol,
             "RB_SNMP_AUTH_PASSWORD=" + c.AuthPassword,
             "RB_SNMP_PRIV_PROTOCOL=" + c.PrivProtocol,
             "RB_SNMP_PRIV_PASSWORD=" + c.PrivPassword,
        }
   }
   return nil
}

func (scan *Scanner) StartScan(j Job, sensors Sensors, scriptPath string) (pid int, err error) {
    enrich := Enrichment(j, sensors)
    broker := kafkaConfig.Broker
    logger := db.config.Logger
    logger.Info("Enrichment: ", enrich)
    logger.Info("start scan for id ", j.Id)
    logger.Info("kafka ", broker)
    logger.Info("ports ", j.Ports)
    logger.Info("target ", j.Target)
    cmd := exec.Command(scriptPath,"-t",j.Target,"-p",j.Ports,"-s",strconv.Itoa(j.Jobid),"-k",broker,"-d", "-e", enrich)
    // SNMP credentials go through the environment, not the command line, and only to the topology script
    if scriptPath == topology_path {
        if env := SNMPEnv(j, sensors); len(env) > 0 {
            logger.Info("SNMP credentials found for the topology scan")
            cmd.Env = append(os.Environ(), env...)
        }
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