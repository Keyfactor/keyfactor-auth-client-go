// Copyright 2024 Keyfactor
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth_providers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

func (c *CommandAuthConfig) ValidateAuthConfig() error {
	if c.CommandHostName == "" {
		if hostName, ok := os.LookupEnv(EnvKeyfactorHostName); ok {
			c.CommandHostName = hostName
		} else {
			return fmt.Errorf("command_host_name or environment variable %s is required", EnvKeyfactorHostName)
		}
	}
	if c.CommandPort == "" {
		if port, ok := os.LookupEnv(EnvKeyfactorPort); ok {
			c.CommandPort = port
		} else {
			c.CommandPort = DefaultCommandPort
		}
	}
	if c.CommandAPIPath == "" {
		if apiPath, ok := os.LookupEnv(EnvKeyfactorAPIPath); ok {
			c.CommandAPIPath = apiPath
		} else {
			c.CommandAPIPath = DefaultCommandAPIPath
		}
	}
	return nil
}

func (c *CommandAuthConfig) Authenticate() error {
	// call /Status/Endpoints API to validate credentials

	//create headers for request
	headers := map[string]string{
		"Content-Type":               "application/json",
		"Accept":                     "application/json",
		"Authorization":              c.AuthHeader,
		"x-keyfactor-api-version":    DefaultAPIVersion,
		"x-keyfactor-requested-with": DefaultAPIClientName,
	}

	endPoint := fmt.Sprintf(
		"https://%s/%s/Status/Endpoints",
		c.CommandHostName,
		//c.CommandPort,
		c.CommandAPIPath,
	)

	// create request object
	req, rErr := http.NewRequest("GET", endPoint, nil)
	if rErr != nil {
		return rErr
	}
	// Set headers from the map
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	c.HttpClient.Timeout = 60 * time.Second

	cResp, cErr := c.HttpClient.Do(req)
	if cErr != nil {
		return cErr
	} else if cResp == nil {
		return fmt.Errorf("failed to authenticate, no response received from Keyfactor Command")
	}

	defer cResp.Body.Close()

	// check if body is empty
	if cResp.Body == nil {
		return fmt.Errorf("failed to authenticate, empty response body received from Keyfactor Command")
	}

	cRespBody, ioErr := io.ReadAll(cResp.Body)
	if ioErr != nil {
		return ioErr
	}

	if cResp.StatusCode != 200 {
		//convert body to string
		return fmt.Errorf(
			"failed to authenticate, received status code %d from Keyfactor Command: %s",
			cResp.StatusCode,
			string(cRespBody),
		)
	}

	productVersion := cResp.Header.Get("x-keyfactor-product-version")
	if productVersion != "" {
		c.CommandVersion = productVersion
	} else {
		c.CommandVersion = DefaultProductVersion
	}

	//decode response to json
	var response []string
	if err := json.Unmarshal(cRespBody, &response); err != nil {
		return err
	}

	return nil

}
