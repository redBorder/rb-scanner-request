package main

import (
	"github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAgentAdvertisesTopologyAndChecksAcknowledgement(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			if r.URL.Query().Get("profile_types") != "0,1,2" {
				t.Error("missing capabilities")
			}
			io.WriteString(w, `{"query":true,"scans":[{"scan_id":42,"profile_type":2}]}`)
		} else {
			if r.URL.Path != "/api/v1/sensors/sensor-a/scans/42/fail" {
				t.Error(r.URL.Path)
			}
			io.WriteString(w, `{"query":false,"error":"Unknown scan"}`)
		}
	}))
	defer server.Close()
	client := NewAPIClient(APIClientConfig{URL: server.URL, Logger: logrus.NewEntry(logger)})
	response, err := client.Jobs("sensor-a")
	if err != nil || len(response.Scans) != 1 || response.Scans[0].ProfileType != 2 {
		t.Fatalf("unexpected polling response: %+v, %v", response, err)
	}
	if _, err := client.jobFinished(Job{Jobid: 42, Uuid: "sensor-a", Status: "error"}); err == nil {
		t.Fatal("negative acknowledgement accepted")
	}
	if client.config.HTTPClient.Timeout == 0 {
		t.Fatal("HTTP timeout required")
	}
}

func TestJobsAreDeduplicatedPerSensorIncludingTerminalJobs(t *testing.T) {
	database := NewDatabase(DatabaseConfig{dbFile: filepath.Join(t.TempDir(), "jobs.db")})
	if database == nil {
		t.Fatal("database initialization failed")
	}
	defer database.Close()
	scan := Scan{Scan_id: 42, ProfileType: 2, Status: "running"}
	for _, uuid := range []string{"a", "a", "b"} {
		if err := database.StoreJob(uuid, scan); err != nil {
			t.Fatal(err)
		}
	}
	jobs, err := database.LoadJobs()
	if err != nil || len(jobs) != 2 {
		t.Fatalf("jobs: %+v, %v", jobs, err)
	}
	if err := database.setJobStatus(jobs[0].Id, "failed"); err != nil {
		t.Fatal(err)
	}
	if err := database.StoreJob("a", scan); err != nil {
		t.Fatal(err)
	}
	jobs, err = database.LoadJobs()
	if err != nil || len(jobs) != 1 {
		t.Fatalf("terminal job restarted: %+v, %v", jobs, err)
	}
}

func TestProcessFailureIsPersistedInsteadOfReportedAsSuccess(t *testing.T) {
	directory := t.TempDir()
	db = NewDatabase(DatabaseConfig{dbFile: filepath.Join(directory, "jobs.db")})
	if db == nil {
		t.Fatal("database initialization failed")
	}
	defer db.Close()
	kafkaConfig = &KafkaConfig{Broker: "unused"}
	if err := db.StoreJob("a", Scan{Scan_id: 42, ProfileType: 2}); err != nil {
		t.Fatal(err)
	}
	jobs, err := db.LoadJobs()
	if err != nil || len(jobs) != 1 {
		t.Fatalf("jobs: %+v, %v", jobs, err)
	}
	script := filepath.Join(directory, "fail.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 7\n"), 0700); err != nil {
		t.Fatal(err)
	}
	runner := NewScanner(ScannerConfig{sqldb: db})
	if _, err := runner.StartScan(jobs[0], Sensors{}, script); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		jobs, err = db.LoadJobs()
		if err != nil {
			t.Fatal(err)
		}
		if len(jobs) == 1 && jobs[0].Status == "error" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("failed process was not recorded: %+v", jobs)
}

func TestCancellationStopsScanProcessGroup(t *testing.T) {
	directory := t.TempDir()
	db = NewDatabase(DatabaseConfig{dbFile: filepath.Join(directory, "jobs.db")})
	if db == nil {
		t.Fatal("database initialization failed")
	}
	defer db.Close()
	kafkaConfig = &KafkaConfig{Broker: "unused"}
	if err := db.StoreJob("a", Scan{Scan_id: 43, ProfileType: 2}); err != nil {
		t.Fatal(err)
	}
	jobs, err := db.LoadJobs()
	if err != nil || len(jobs) != 1 {
		t.Fatalf("jobs: %+v, %v", jobs, err)
	}
	script := filepath.Join(directory, "wait.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nsleep 30 &\nwait\n"), 0700); err != nil {
		t.Fatal(err)
	}
	runner := NewScanner(ScannerConfig{sqldb: db})
	pid, err := runner.StartScan(jobs[0], Sensors{}, script)
	if err != nil {
		t.Fatal(err)
	}
	defer runner.CancelScan(pid)
	if err := db.setJobStatus(jobs[0].Id, "cancelling"); err != nil {
		t.Fatal(err)
	}
	if err := runner.CancelScan(pid); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		jobs, err = db.LoadJobs()
		if err != nil {
			t.Fatal(err)
		}
		if len(jobs) == 1 && jobs[0].Status == "completed" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("cancelled process did not complete: %+v", jobs)
}

// startTopologyScan runs a shell script that prints body on stdout as a topology
// scan, against a manager that answers with the given handler.
func startTopologyScan(t *testing.T, body string, handler http.HandlerFunc) (*httptest.Server, *Database) {
	t.Helper()
	directory := t.TempDir()
	db = NewDatabase(DatabaseConfig{dbFile: filepath.Join(directory, "jobs.db")})
	if db == nil {
		t.Fatal("database initialization failed")
	}
	kafkaConfig = &KafkaConfig{Broker: "unused"}

	server := httptest.NewServer(handler)
	apiClient = NewAPIClient(APIClientConfig{
		URL: server.URL, Auth_token: "secret", Logger: logrus.NewEntry(logger),
	})

	if err := db.StoreJob("a", Scan{Scan_id: 42, ProfileType: TopologyProfileType}); err != nil {
		t.Fatal(err)
	}
	jobs, err := db.LoadJobs()
	if err != nil || len(jobs) != 1 {
		t.Fatalf("jobs: %+v, %v", jobs, err)
	}

	script := filepath.Join(directory, "topology.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s' '"+body+"'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := NewScanner(ScannerConfig{sqldb: db}).StartScan(jobs[0], Sensors{}, script); err != nil {
		t.Fatal(err)
	}
	return server, db
}

func waitForStatus(t *testing.T, want string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		jobs, err := db.LoadJobs()
		if err != nil {
			t.Fatal(err)
		}
		if len(jobs) == 1 && jobs[0].Status == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("job never reached status %s", want)
}

func TestTopologySnapshotIsUploadedWithATokenBeforeTheScanIsFinished(t *testing.T) {
	body := `{"topology_json":"{\"schema_version\":1}","scan_id":"42"}`
	received := make(chan string, 1)

	server, database := startTopologyScan(t, body, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" || r.URL.Path != "/api/v1/sensors/a/scans/42/topology" {
			t.Error("unexpected request: ", r.Method, " ", r.URL.Path)
		}
		if r.URL.Query().Get("auth_token") != "secret" {
			t.Error("topology uploaded without an auth token")
		}
		payload, _ := ioutil.ReadAll(r.Body)
		received <- string(payload)
		io.WriteString(w, `{"query":true}`)
	})
	defer server.Close()
	defer database.Close()
	defer func() { apiClient = nil }()

	select {
	case payload := <-received:
		if payload != body {
			t.Fatalf("snapshot altered in flight: %s", payload)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("topology was never uploaded")
	}
	waitForStatus(t, "completed")
}

func TestRejectedTopologyUploadFailsTheScanInsteadOfReportingSuccess(t *testing.T) {
	server, database := startTopologyScan(t, `{"topology_json":"{}"}`, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		io.WriteString(w, `{"query":false,"error":"Unsupported topology snapshot"}`)
	})
	defer server.Close()
	defer database.Close()
	defer func() { apiClient = nil }()

	// main.setJobFinished turns "error" into the /fail callback, so a snapshot the
	// manager refused can never be acknowledged as a successful scan.
	waitForStatus(t, "error")
}
