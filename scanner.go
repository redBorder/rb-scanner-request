package main

import (
  "os/exec"
  "github.com/Sirupsen/logrus"
  "strconv"
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

func (scan *Scanner) StartScan(j Job) (pid int, err error) {
	logger := db.config.Logger

	logger.Info("start scan for id ", j.Id)
	cmd := exec.Command(VulnerabiliesScan,"-t",j.Target,"-p",j.Ports)
	err = cmd.Start()
	if err != nil {
		return 0, err
	} else {
		logger.Info("started new job with pid ", cmd.Process.Pid)
		go cmd.Wait()
		return cmd.Process.Pid, nil
	}
}