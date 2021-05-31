package main

import (
	"os/exec"
)

func RunScan(scan_type string, options scanOptions){
  var cmd *exec.Cmd

  switch scan_type{
  case "1":
    cmd = exec.Command(HostDiscovery)
  case "2":
    cmd = exec.Command(VulnerabiliesScan)
  }

  cmd.Start()
}
