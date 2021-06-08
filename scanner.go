package main

import (
	"os/exec"
  "os"
  "strconv"
  "fmt"
  "strings"
)

func RunScan(scan Response){
  //var cmd *exec.Cmd

  switch scan.ScanRequest.ScanType{
  case 1:

    fmt.Println(scan.ScanRequest.Target)
    cmd := exec.Command(HostDiscovery, "-t=", FormatTarget(scan.ScanRequest.Target), "-r=", strconv.Itoa(scan.ScanRequest.ScanHistoryId), "-d=", "false")
    cmd.Stdout = os.Stdout
    err := cmd.Start()

    if err != nil {
      fmt.Println(err)
    }

  case 2:
    cmd := exec.Command(VulnerabiliesScan)
    cmd.Start()
  }

  //cmd.Start()
}


func FormatTarget(target []string) (string) {
  target_string := "["
  size := len(target)-1

  for i, rune := range target {
    if i != size {
      target_string = target_string + "\"" + strings.TrimSpace(rune) + "\","
    } else {
      target_string = target_string + "\"" + strings.TrimSpace(rune) + "\"]"
    }
  }
  fmt.Println(target_string)
  return target_string
}
