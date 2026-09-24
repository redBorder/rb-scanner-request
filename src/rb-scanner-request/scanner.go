package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/sirupsen/logrus"
	"os"
	"os/exec"
	"strconv"
	"syscall"
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

func (scan *Scanner) StartScan(j Job, sensors Sensors, scriptPath string) (pid int, err error) {
	enrich := Enrichment(j, sensors)
	broker := kafkaConfig.Broker
	logger := db.config.Logger
	logger.Info("Enrichment: ", enrich)
	logger.Info("start scan for id ", j.Id)
	logger.Info("kafka ", broker)
	logger.Info("ports ", j.Ports)
	logger.Info("target ", j.Target)
	cmd := exec.Command(scriptPath, "-t", j.Target, "-p", j.Ports, "-s", strconv.Itoa(j.Jobid), "-k", broker, "-d", "-e", enrich)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	// A topology scan writes its snapshot to stdout for upload; every other
	// profile type only logs there.
	var snapshot *bytes.Buffer
	if j.ProfileType == TopologyProfileType {
		snapshot = &bytes.Buffer{}
		cmd.Stdout = snapshot
	} else {
		cmd.Stdout = os.Stdout
	}
	cmd.Stderr = os.Stderr

	err = cmd.Start()
	if err != nil {
		return 0, err
	} else {
		logger.Info("started new job with pid ", cmd.Process.Pid)
		if _, err = db.config.sqldb.Exec("UPDATE Scanjobs SET Pid = ?, Status = 'running' WHERE Id = ?", cmd.Process.Pid, j.Id); err != nil {
			syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			cmd.Wait()
			return 0, err
		}
		go func() {
			status := "completed"
			if waitErr := cmd.Wait(); waitErr != nil {
				logger.Error("scan process failed: ", waitErr)
				status = "error"
			}
			// Upload before the job is eligible to be reported finished, so a
			// scan never acknowledges success with no topology behind it.
			if status == "completed" && snapshot != nil {
				if uploadErr := uploadTopology(j, snapshot.Bytes()); uploadErr != nil {
					logger.Error("could not upload topology: ", uploadErr)
					status = "error"
				}
			}
			_, saveErr := db.config.sqldb.Exec("UPDATE Scanjobs SET Status = CASE WHEN Status = 'cancelling' THEN 'completed' ELSE ? END WHERE Id = ?", status, j.Id)
			if saveErr != nil {
				logger.Error("could not persist scan outcome: ", saveErr)
			}
		}()
		return cmd.Process.Pid, nil
	}
}

func (scan *Scanner) CancelScan(job_pid int) (err error) {
	if job_pid <= 0 {
		return nil
	}
	// Each scan owns a process group, including its Ruby and Nmap children.
	err = syscall.Kill(-job_pid, syscall.SIGKILL)
	if err == syscall.ESRCH {
		return nil
	}
	return err
}

// uploadTopology is separated so a missing API client is reported as a failed
// scan rather than crashing the agent.
func uploadTopology(j Job, snapshot []byte) error {
	if apiClient == nil {
		return errors.New("no API client available to upload the topology")
	}
	return apiClient.jobTopology(j, snapshot)
}
