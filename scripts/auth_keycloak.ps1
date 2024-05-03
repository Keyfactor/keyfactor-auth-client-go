# Copyright 2024 Keyfactor
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

function CheckVars {
    # Check hostname
    if (!$env:KEYFACTOR_AUTH_HOSTNAME) {
        # Check if KEYFACTOR_HOSTNAME is set
        if (!$env:KEYFACTOR_HOSTNAME) {
            Write-Host "KEYFACTOR_HOSTNAME is not set"
            # prompt for hostname until it is set
            while (!$env:KEYFACTOR_HOSTNAME) {
                $env:KEYFACTOR_AUTH_HOSTNAME = Read-Host "Enter auth hostname"
            }
        } else {
            Write-Host "Setting auth hostname to $env:KEYFACTOR_HOSTNAME"
            $env:KEYFACTOR_AUTH_HOSTNAME = $env:KEYFACTOR_HOSTNAME
        }
    }

    if (!$env:KEYFACTOR_CLIENT_ID) {
        Write-Host "KEYFACTOR_CLIENT_ID is not set"
        # prompt for client_id until it is set
        while (!$env:KEYFACTOR_CLIENT_ID) {
            $env:KEYFACTOR_CLIENT_ID = Read-Host "Enter client_id"
        }
    }

    if (!$env:KEYFACTOR_CLIENT_SECRET) {
        Write-Host "KEYFACTOR_CLIENT_SECRET is not set"
        while (!$env:KEYFACTOR_CLIENT_SECRET) {
            #prompt for sensitive client_secret until it is set
            $env:KEYFACTOR_CLIENT_SECRET = Read-Host "Enter client_secret"
        }
    }
}

function AuthClientCredentials {
    CheckVars
    $client_id = $env:KEYFACTOR_CLIENT_ID
    $client_secret = $env:KEYFACTOR_CLIENT_SECRET
    $grant_type = "client_credentials"
    $auth_url = "https://$env:KEYFACTOR_AUTH_HOSTNAME:$($env:KEYFACTOR_AUTH_PORT -replace '^$', '8444')/realms/$($env:KEYFACTOR_AUTH_REALM -replace '^$', 'Keyfactor')/protocol/openid-connect/token"

    $response = Invoke-RestMethod -Uri $auth_url -Method POST -Body @{
    "grant_type" = $grant_type
    "client_id" = $client_id
    "client_secret" = $client_secret
    } -ContentType 'application/x-www-form-urlencoded'

    $env:KEYFACTOR_ACCESS_TOKEN = $response.access_token
}

AuthClientCredentials