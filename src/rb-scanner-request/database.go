// Copyright (C) 2016 Eneo Tecnologia S.L.
// Diego Fernández Barrera <bigomby@gmail.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"database/sql"

	"github.com/sirupsen/logrus"
	_ "github.com/mattn/go-sqlite3"
)

const (
	sqlCreateTable           = "CREATE TABLE IF NOT EXISTS Scanjobs (Id INTEGER PRIMARY KEY AUTOINCREMENT, Jobid INTEGER, Target varchar(255), Ports varchar(255), Status varchar(255), Pid INTEGER DEFAULT 0, Uuid varchar(255), ProfileType INTEGER DEFAULT 0)"
	sqlInsertEntry           = "INSERT INTO Scanjobs (Jobid, Target, Ports, Status, Uuid) values (?, ?, ?, ?, ?)"
	sqlUpdatePid             = "UPDATE Scanjobs SET Pid = ? WHERE Id = ?"
	sqlUpdateStatus          = "UPDATE Scanjobs SET Status = ? WHERE Id = ?"
	// sqlSelectFinishedJob	 = "SELECT * FROM Scanjobs WHERE Jobid = ? Status == \"finished\""
	sqlSelectNonFinishedJobs = "SELECT * FROM Scanjobs WHERE status != \"finished\""
	sqlSelectScanJob         = "SELECT * FROM Scanjobs WHERE Id = $1"
	sqlUpdateToCancelling    = "UPDATE Scanjobs SET Status = \"cancelling\" WHERE Jobid = ?"
)

// Database handles the connection with a SQL Database
type Database struct {
	config DatabaseConfig
}

// NewDatabase creates a new instance of a database
func NewDatabase(config DatabaseConfig) *Database {
	db := &Database{
		config: config,
	}

	if db.config.Logger == nil {
		db.config.Logger = logrus.New()
	}
	logger := db.config.Logger

	if len(db.config.dbFile) <= 0 {
		return nil
	}

	var err error
	db.config.sqldb, err = sql.Open("sqlite3", db.config.dbFile + "?mode=rwc")
	if err != nil {
		logger.Fatal(err)
	}

	// Ping db to check if db is available
	if err := db.config.sqldb.Ping(); err != nil {
		logger.Error(err)
		return nil
	}

	// Init connection with db
	if _, err := db.config.sqldb.Begin(); err != nil {
		logger.Error(err)
		return nil
	}

	// Create table if no exists
	if _, err := db.config.sqldb.Exec(sqlCreateTable); err != nil {
		logger.Error(err)
		return nil
	}

	return db
}

// function to retrieve all non-finished jobs
func (db *Database) LoadJobs() (jobs []Job, err error) {
	logger := db.config.Logger
	logger.Info ("Retrieving all non-finished jobs..")
	// get all non finished (new, running) jobs from the db an process them to return
	rows, err := db.config.sqldb.Query(sqlSelectNonFinishedJobs)
    if err != nil {
		logger.Info ("Retrieving all non-finished jos: ERROR")
        return nil, err
    }
    defer rows.Close()

    // Loop through results of the query
    for rows.Next() {
        var j Job
        if err := rows.Scan(&j.Id, &j.Jobid, &j.Target, &j.Ports, &j.Status, &j.Pid, &j.Uuid, &j.ProfileType); err != nil {
            return jobs, err
        }
        jobs = append(jobs, j)
    }
	logger.Info ("Jobs were retrieved from database")
    if err = rows.Err(); err != nil {
        return jobs, err
    }
    return jobs, nil
}

func (db *Database) StoreJob(uuid string, s Scan) (err error) {
	logger := db.config.Logger

	logger.Info ("check if scan is already in database")

	var scan_id int	//0:false, rest:true
	//TODO: make this query row more explicit
	db.config.sqldb.QueryRow("SELECT COUNT(*) FROM Scanjobs WHERE JobId = ? AND Status != ?", s.Scan_id, "finished").Scan(&scan_id)
	
	var isAlreadyStored = scan_id > 0
	var isStatusCancelling = s.Status == "cancelling"
	logger.Info ("is Status cancelling? ", s.Status == "cancelling", isStatusCancelling)

	if !isAlreadyStored && !isStatusCancelling {
		logger.Info("Storing new scan with id ", s.Scan_id, " and status: ", s.Status)
		if _, err = db.config.sqldb.Exec(sqlInsertEntry, s.Scan_id, s.Target_addr, s.Target_port, "new", uuid); err != nil {
			return err
		}
	} else if !isAlreadyStored {	// and status = cancelling
		logger.Info("Scan is going to be be stored with cancel in order to set it to finished later")
		if _, err = db.config.sqldb.Exec(sqlInsertEntry, s.Scan_id, s.Target_addr, s.Target_port, "cancelling", uuid); err != nil {
			return err
		}
	} else if isStatusCancelling {	// and already stored
		logger.Info("Scan has cancelling status. Updating to jobs database.")
		if _, err = db.config.sqldb.Exec(sqlUpdateToCancelling, s.Scan_id); err != nil {
			return err
		}
	}
	// } else {	//already stored but status is not cancelling
	logger.Info("Scan already exists in database. No update to sql database.")
	return nil
}

func (db *Database) InsertJobPid(id int, pid int) (err error) {
	logger := db.config.Logger
	logger.Info("insert pid into db ", pid)
	logger.Info("id is ", id)

	if _, err = db.config.sqldb.Exec(sqlUpdatePid, pid, id); err != nil {
		return err
	}
	logger.Info("pid inserted in database ", pid)
	return nil
}

func (db *Database) setJobStatus(id int, status string) (err error) {
	logger := db.config.Logger
	logger.Info("set status for job with id ", id, " to ", status)
	if _, err = db.config.sqldb.Exec(sqlUpdateStatus, status, id); err != nil {
		return err
	}
	return nil
}

// Close closes the connection with the database
func (db *Database) Close() {
	db.config.sqldb.Close()
}