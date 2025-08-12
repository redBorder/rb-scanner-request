package main

import (
	"database/sql"

	"github.com/sirupsen/logrus"
	_ "github.com/mattn/go-sqlite3"
)

const (
	sqlCreateTable = `
		CREATE TABLE IF NOT EXISTS Scanjobs (
			Id INTEGER PRIMARY KEY AUTOINCREMENT,
			Jobid INTEGER,
			Target varchar(255),
			Ports varchar(255),
			Status varchar(255),
			Pid INTEGER DEFAULT 0,
			Uuid varchar(255),
			ProfileType INTEGER DEFAULT 0
		)`

	sqlInsertEntry = "INSERT INTO Scanjobs (Jobid, Target, Ports, Status, Uuid, ProfileType) VALUES (?, ?, ?, ?, ?, ?)"

	sqlUpdatePid          = "UPDATE Scanjobs SET Pid = ? WHERE Id = ?"
	sqlUpdateStatus       = "UPDATE Scanjobs SET Status = ? WHERE Id = ?"
	sqlSelectNonFinished  = "SELECT * FROM Scanjobs WHERE status != \"finished\""
	sqlSelectScanJob      = "SELECT * FROM Scanjobs WHERE Id = $1"
	sqlUpdateToCancelling = "UPDATE Scanjobs SET Status = \"cancelling\" WHERE Jobid = ?"
)

type Database struct {
	config DatabaseConfig
}

func NewDatabase(config DatabaseConfig) *Database {
	db := &Database{config: config}
	if db.config.Logger == nil {
		db.config.Logger = logrus.New()
	}
	logger := db.config.Logger

	if db.config.dbFile == "" {
		return nil
	}

	var err error
	db.config.sqldb, err = sql.Open("sqlite3", db.config.dbFile+"?mode=rwc")
	if err != nil {
		logger.Fatal(err)
	}

	if err := db.config.sqldb.Ping(); err != nil {
		logger.Error("Ping failed: ", err)
		return nil
	}

	if _, err := db.config.sqldb.Begin(); err != nil {
		logger.Error("Begin transaction failed: ", err)
		return nil
	}

	if _, err := db.config.sqldb.Exec(sqlCreateTable); err != nil {
		logger.Error("Create table failed: ", err)
		return nil
	}

	return db
}

func (db *Database) LoadJobs() ([]Job, error) {
	logger := db.config.Logger
	logger.Info("Retrieving all non-finished jobs..")

	rows, err := db.config.sqldb.Query(sqlSelectNonFinished)
	if err != nil {
		logger.Error("Error retrieving jobs: ", err)
		return nil, err
	}
	defer rows.Close()

	var jobs []Job
	for rows.Next() {
		var j Job
		if err := rows.Scan(&j.Id, &j.Jobid, &j.Target, &j.Ports, &j.Status, &j.Pid, &j.Uuid, &j.ProfileType); err != nil {
			return jobs, err
		}
		jobs = append(jobs, j)
	}

	if err := rows.Err(); err != nil {
		return jobs, err
	}

	logger.Infof("Found %d non-finished jobs in the database", len(jobs))
	logger.Infof("Jobs:\n%+v", jobs)
	return jobs, nil
}

func (db *Database) StoreJob(uuid string, s Scan) error {
	logger := db.config.Logger
	logger.Info("Check if scan is already in database")

	var count int
	err := db.config.sqldb.QueryRow(
		"SELECT COUNT(*) FROM Scanjobs WHERE JobId = ? AND Status != ?", s.Scan_id, "finished",
	).Scan(&count)
	if err != nil {
		logger.Error("Error checking existing scan: ", err)
		return err
	}

	isStored := count > 0
	isCancelling := s.Status == "cancelling"
	logger.Infof("Scan status is 'cancelling'? %v (value: %v)", isCancelling, s.Status)

	switch {
	case !isStored && !isCancelling:
		logger.Infof("Storing new scan with id %d and status: new", s.Scan_id)
		res, err := db.config.sqldb.Exec(sqlInsertEntry, s.Scan_id, s.Target_addr, s.Target_port, "new", uuid, s.ProfileType)
		if err != nil {
			logger.Error("Error inserting new scan: ", err)
			return err
		}
		rows, _ := res.RowsAffected()
		logger.Infof("Rows affected: %d", rows)

	case !isStored && isCancelling:
		logger.Infof("Storing scan with status 'cancelling' for future finalization. ID: %d", s.Scan_id)
		res, err := db.config.sqldb.Exec(sqlInsertEntry, s.Scan_id, s.Target_addr, s.Target_port, "cancelling", uuid, s.ProfileType)
		if err != nil {
			logger.Error("Error inserting cancelling scan: ", err)
			return err
		}
		rows, _ := res.RowsAffected()
		logger.Infof("Rows affected: %d", rows)

	case isStored && isCancelling:
		logger.Infof("Updating status to 'cancelling' for existing scan ID %d", s.Scan_id)
		_, err := db.config.sqldb.Exec(sqlUpdateToCancelling, s.Scan_id)
		if err != nil {
			logger.Error("Error updating status to cancelling: ", err)
			return err
		}

	default:
		logger.Infof("Scan with id %d already exists. No action taken.", s.Scan_id)
	}

	return nil
}

func (db *Database) InsertJobPid(id int, pid int) error {
	logger := db.config.Logger
	logger.Infof("Insert pid %d into job id %d", pid, id)
	if _, err := db.config.sqldb.Exec(sqlUpdatePid, pid, id); err != nil {
		logger.Error("Error updating pid: ", err)
		return err
	}
	return nil
}

func (db *Database) setJobStatus(id int, status string) error {
	logger := db.config.Logger
	logger.Infof("Set job id %d to status %s", id, status)
	if _, err := db.config.sqldb.Exec(sqlUpdateStatus, status, id); err != nil {
		logger.Error("Error updating status: ", err)
		return err
	}
	return nil
}

func (db *Database) Close() {
	if db.config.sqldb != nil {
		db.config.sqldb.Close()
	}
}
