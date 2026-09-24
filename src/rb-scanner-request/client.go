// Copyright (C) 2016 Eneo Tecnologia S.L.
//
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
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// APIClient is an object that can communicate with the redborder API to get
// scanner information.
type APIClient struct {
	status   string // Current status of the registrtation
	cert     string // Client certificate
	nodename string // Name of the node received along with the cert

	config APIClientConfig
}

func NewAPIClient(config APIClientConfig) *APIClient {
	c := &APIClient{
		config: config,
		status: "scanning",
	}

	// Check if the configuration is ok
	if len(c.config.URL) == 0 {
		logger.Error("Url is not provided")
		return nil
	}

	if c.config.HTTPClient == nil {
		if c.config.Insecure {
			c.config.HTTPClient = &http.Client{Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}, Timeout: 30 * time.Second}
		} else {
			c.config.HTTPClient = &http.Client{Timeout: 30 * time.Second}
		}
	}

	return c
}

func (c *APIClient) Jobs(uuid string) (response ScanResponse, err error) {
	res := ScanResponse{}

	api_url_request := c.config.URL + "/api/v1/sensors/" + uuid + "/scans?profile_types=0,1,2"
	c.config.Logger.Info("request url is ", api_url_request)

	httpReq, err := http.NewRequest("GET", api_url_request, nil)
	if err != nil {
		return res, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	rawResponse, err := c.config.HTTPClient.Do(httpReq)
	if err != nil {
		return res, err
	}
	defer rawResponse.Body.Close()
	if rawResponse.StatusCode >= 400 {
		return res, errors.New("Got status code: " + rawResponse.Status)
	}

	bufferResponse, err := ioutil.ReadAll(rawResponse.Body)
	if err != nil {
		return res, err
	}

	err = json.Unmarshal(bufferResponse, &res)
	if err != nil {
		c.config.Logger.Error(err)
	}

	return res, err
}

func (c *APIClient) jobFinished(j Job) (response ScanResponse, err error) {
	action := "finish"
	if j.Status == "error" {
		action = "fail"
	}
	res := ScanResponse{}

	c.config.Logger.Info("sending status finished to manager for uuid ", j.Uuid, " job ", strconv.Itoa(j.Jobid))
	api_url_request := c.config.URL + "/api/v1/sensors/" + j.Uuid + "/scans/" + strconv.Itoa(j.Jobid) + "/" + action
	c.config.Logger.Info("api url is : ", api_url_request)
	httpReq, err := http.NewRequest("PUT", api_url_request, nil)
	if err != nil {
		return res, err
	}
	rawResponse, err := c.config.HTTPClient.Do(httpReq)
	if err != nil {
		return res, err
	}
	defer rawResponse.Body.Close()
	if rawResponse.StatusCode >= 400 {
		return res, errors.New("Got status code: " + rawResponse.Status)
	}

	bufferResponse, err := ioutil.ReadAll(rawResponse.Body)
	if err != nil {
		return res, err
	}
	err = json.Unmarshal(bufferResponse, &res)
	if err != nil {
		c.config.Logger.Error(err)
	}

	if err == nil && !res.Query {
		err = errors.New("Manager rejected scan completion")
	}
	return res, err
}

// jobTopology hands a finished network topology snapshot to the manager, which
// turns it into an inventory topology. Unlike the status callbacks this endpoint
// authenticates, because it creates devices, interfaces and addresses.
//
// The URL is never logged: it carries the auth token.
func (c *APIClient) jobTopology(j Job, snapshot []byte) error {
	if len(c.config.Auth_token) == 0 {
		return errors.New("no auth_token configured, cannot upload topology")
	}
	if len(snapshot) == 0 {
		return errors.New("topology scan produced no snapshot")
	}

	c.config.Logger.Info("uploading topology for uuid ", j.Uuid, " job ", strconv.Itoa(j.Jobid))
	api_url_request := c.config.URL + "/api/v1/sensors/" + j.Uuid + "/scans/" +
		strconv.Itoa(j.Jobid) + "/topology?auth_token=" + url.QueryEscape(c.config.Auth_token)

	httpReq, err := http.NewRequest("PUT", api_url_request, bytes.NewReader(snapshot))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	rawResponse, err := c.config.HTTPClient.Do(httpReq)
	if err != nil {
		return err
	}
	defer rawResponse.Body.Close()

	bufferResponse, err := ioutil.ReadAll(rawResponse.Body)
	if err != nil {
		return err
	}
	if rawResponse.StatusCode >= 400 {
		return errors.New("manager rejected topology with " + rawResponse.Status + ": " + string(bufferResponse))
	}

	res := ScanResponse{}
	if err = json.Unmarshal(bufferResponse, &res); err != nil {
		return err
	}
	if !res.Query {
		return errors.New("manager did not accept the topology snapshot")
	}
	return nil
}

// func (c *APIClient) updatejob(scan_request_id int){

//   json_parameter, _ := json.Marshal(SensorRequestJson{job_id: scan_request_id, sensor_uuid: c.config.Hash })
//   api_url_request := c.config.URL + "/api/v1/scanner/job"

//   req, err := http.NewRequest(http.MethodPost, api_url_request, bytes.NewBuffer([]byte(json_parameter)))
//   if err != nil {
//     c.config.Logger.Error(err)
//   }
//   req.Header.Set("Content-Type", "application/json")

//   rawResponse, err := c.config.HTTPClient.Do(req)
//   if err != nil {
// 		c.config.Logger.Error(err)
//   }

//   defer rawResponse.Body.Close()
// }
