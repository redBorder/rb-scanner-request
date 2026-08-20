package main

import (
  "bufio"
  "io"
  "os/exec"
  "sync"
  "github.com/sirupsen/logrus"
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

    stdout, err := cmd.StdoutPipe()
    if err != nil {
        return 0, err
    }
    stderr, err := cmd.StderrPipe()
    if err != nil {
        return 0, err
    }

    err = cmd.Start()
    if err != nil {
		return 0, err
	} else {
		logger.Info("started new job with pid ", cmd.Process.Pid)

		var wg sync.WaitGroup
		wg.Add(2)
		go streamScanOutput(&wg, logger, j.Jobid, "stdout", stdout)
		go streamScanOutput(&wg, logger, j.Jobid, "stderr", stderr)

		// cmd.Wait() closes the pipes once the process exits, so it must
		// not run until both readers above have finished draining them.
		go func() {
			wg.Wait()
			cmd.Wait()
		}()

		return cmd.Process.Pid, nil
	}
}

// streamScanOutput logs each line written by a scan subprocess to stdout/stderr
// through the daemon's own logger, since exec.Cmd otherwise sends unset
// Stdout/Stderr to /dev/null and all scan-script diagnostics are lost.
func streamScanOutput(wg *sync.WaitGroup, logger *logrus.Logger, jobid int, stream string, r io.Reader) {
    defer wg.Done()

    scanner := bufio.NewScanner(r)
    scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
    for scanner.Scan() {
        logger.Infof("[job %d %s] %s", jobid, stream, scanner.Text())
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