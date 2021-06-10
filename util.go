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
		LogFileName: *logFile,
		LogFilePerm: 0640,
		WorkDir:     "./",
		Umask:       027,
		Args:        os.Args,
	}

	d, err := cntxt.Reborn()
	if err != nil {
		fmt.Println(err)
	}
	if d != nil {
		fmt.Println ("Daemon started [PID: %d]", d.Pid)
		return
	}

	defer cntxt.Release()
}
