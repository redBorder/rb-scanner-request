package main

import (
  "fmt"
  "os"
  daemon "github.com/sevlyar/go-daemon"
)


func daemonize() {
	// hook, err := logrus_syslog.NewSyslogHook("", "", syslog.LOG_INFO, "rb-register")
	// if err != nil {
	// 	logrus.Error("Unable to connect to local syslog daemon")
	// } else {
	// 	logger.Hooks.Add(hook)
	// }
	cntxt := &daemon.Context{
		PidFileName: *pid,
		PidFilePerm: 0644,
		LogFilePerm: 0640,
		WorkDir:     "./",
		Umask:       027,
		Args:        os.Args,
	}

	d, err := cntxt.Reborn()
	if err != nil {
		logger.Error(err)
	}
	if d != nil {
		logger.Info("Daemon started [PID: %s]", d.Pid)
		return
	}

	defer cntxt.Release()
}

func displayVersion() {
	fmt.Println("RB-SCANNER-REQUEST VERSION:\t", version)
	fmt.Println("GO VERSION:\t\t\t", goVersion)
}
