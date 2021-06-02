package main

import (
	//"bytes"
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
		//logger.Warnf("Url not provided")
		return nil
	}
	if len(c.config.Hash) == 0 {
		///logger.Warnf("Hash not provided")
		return nil
	}
  if len(c.config.Auth_token) == 0 {
		//logger.Warnf("Auth token not provided")
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

func (c *APIClient) GetScanRequest() (response Response, err error){

  res := Response{}
  apiAction := "scanner_request?"
  api_url_request := c.config.URL + apiAction + "auth_token=" + c.config.Auth_token

  //bufferReq := bytes.NewBuffer(marshalledReq)
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
  // fmt.Println(res)

  //bodyBytes, err := ioutil.ReadAll(rawResponse.Body)
  bodyString := string(bufferResponse)

  fmt.Println(bodyString)

  return res, err
}

func (c *APIClient) UpdateScanRequest(scan_history_id string, sensor string){
  api_action := "update_request?"
  api_url_request := c.config.URL + api_action + "auth_token=" + c.config.Auth_token

  httpReq, err := http.NewRequest("GET", api_url_request, nil)
  if err != nil {
  }
  httpReq.Header.Set("Content-Type", "application/json")

  rawResponse, err := c.config.HTTPClient.Do(httpReq)
  if err != nil {
  }
  defer rawResponse.Body.Close()
}

// func (c *APIClient) UpdateScanRequest() (response string, err error){
//
// }
