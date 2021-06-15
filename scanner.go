package main

import (
	"os/exec"
  "os"
  "strconv"
  "fmt"
  "strings"
	"time"
)

func RunScan(scan Response) (bool) {
  //var cmd *exec.Cmd

  switch scan.ScanRequest.ScanType {
  case 1:
    fmt.Println(scan.ScanRequest.Target)
    cmd := exec.Command(HostDiscovery, "-t=", FormatTarget(scan.ScanRequest.Target), "-r=", strconv.Itoa(scan.ScanRequest.ScanHistoryId), "-d=", "false")
    cmd.Stdout = os.Stdout
    err := cmd.Start()

    if err != nil {
      logger.Error(err)
			return false
    } else {
			logger.Infoln("Executed Host Discovery")
			return true
		}
  case 2:
		targets := scan.ScanRequest.Target

		for target := range targets {
	    cmd := exec.Command(VulnerabiliesScan, "-t=", targets[target], "-p=", "all", "-r=", strconv.Itoa(scan.ScanRequest.ScanHistoryId))
			cmd.Stdout = os.Stdout
	    err := cmd.Start()

			if err != nil {
				logger.Error(err)
				return false
			} else {
				logger.Infoln("Executed Vulnerabilies Scan")
				return true
			}
		}
	}
	return false
}

func checkDate(requestDate string) (bool){
	formatTime := "2006-01-02 15:04:05 -0700"
	sysTime := time.Now()
	regDate, _ := time.Parse(formatTime, requestDate)

	fmt.Println(regDate)

	if regDate.Before(sysTime) {
		return true
	} else {
		return false
	}
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

func checkSensor(sensors []string)(bool){
	isInRequest := false
	fmt.Println("sensor taken from config: " + UUID)

	for sensor := range sensors {
		if sensors[sensor] == UUID {
			isInRequest = true
		}
	}
	return isInRequest
}
