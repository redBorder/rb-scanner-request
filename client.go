package main

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io/ioutil"
	"net/http"
  "fmt"
  "encoding/json"
	//"github.com/sirupsen/logrus"
)

// APIClient is an objet that can communicate with the API to perform a
// registration. It has the necessary methods to interact with the API.
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
		logger.Warnf("Url not provided")
		return nil
	}
	if len(c.config.Hash) == 0 {
		logger.Warnf("Hash not provided")
		return nil
	}
  if len(c.config.Auth_token) == 0 {
		logger.Warnf("Auth token not provided")
		return nil
	}

	if c.config.HTTPClient == nil {
		if c.config.Insecure {
			c.config.HTTPClient = &http.Client{Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}}
		} else {
			c.config.HTTPClient = &http.Client{}
		}
	}

	return c
}

func (c *APIClient) GetScanRequest() (response Response, err error, jsonRequest string){
  res := Response{}
  apiAction := "scanner_request?"
  api_url_request := c.config.URL + apiAction + "auth_token=" + c.config.Auth_token

  //bufferReq := bytes.NewBuffer(marshalledReq)
	httpReq, err := http.NewRequest("GET", api_url_request, nil)
	httpReq.Header.Set("Content-Type", "application/json")

	rawResponse, err := c.config.HTTPClient.Do(httpReq)

  defer rawResponse.Body.Close()
	if rawResponse.StatusCode >= 400 {
		return res, errors.New("Got status code: " + rawResponse.Status), ""
	}

  bufferResponse, err := ioutil.ReadAll(rawResponse.Body)

  err = json.Unmarshal(bufferResponse, &res)
  bodyString := string(bufferResponse)
	//
  fmt.Println(bodyString)

  return res, err, bodyString
}


func (c *APIClient) UpdateScanRequest(scan_request_id int){

	json_parameter, _ := json.Marshal(SensorRequestJson{Scan_request_id: scan_request_id, Sensor_uuid: c.config.Hash })

	api_action := "remove_sensor?"
  api_url_request := c.config.URL + api_action + "auth_token=" + c.config.Auth_token


	req, err := http.NewRequest(http.MethodPost, api_url_request, bytes.NewBuffer([]byte(json_parameter)))
	if err != nil {
		c.config.Logger.Error(err)
	}
	req.Header.Set("Content-Type", "application/json")

	rawResponse, err := c.config.HTTPClient.Do(req)
  if err != nil {
		c.config.Logger.Error(err)
  }

	defer rawResponse.Body.Close()
}
