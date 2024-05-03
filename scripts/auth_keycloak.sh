#!/usr/bin/env bash

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

# Input vars
function checkVars() {
  # Check hostname
  if [ -z "$KEYFACTOR_AUTH_HOSTNAME" ]; then
    # Check if KEYFACTOR_HOSTNAME is set
    if [ -z "$KEYFACTOR_HOSTNAME" ]; then
      echo "KEYFACTOR_HOSTNAME is not set"
      # prompt for hostname until it is set
      while [ -z "$KEYFACTOR_HOSTNAME" ]; do
        read -p "Enter auth hostname: " KEYFACTOR_AUTH_HOSTNAME
      done
    else
      echo "Setting auth hostname to $KEYFACTOR_HOSTNAME"
      KEYFACTOR_AUTH_HOSTNAME="$KEYFACTOR_HOSTNAME"
    fi
  fi

  if [ -z "$KEYFACTOR_CLIENT_ID" ]; then
    echo "KEYFACTOR_CLIENT_ID is not set"
    # prompt for client_id until it is set
    while [ -z "$KEYFACTOR_CLIENT_ID" ]; do
      read -p "Enter client_id: " KEYFACTOR_CLIENT_ID
    done
  fi

  if [ -z "$KEYFACTOR_CLIENT_SECRET" ]; then
    echo "KEYFACTOR_CLIENT_SECRET is not set"
    while [ -z "$KEYFACTOR_CLIENT_SECRET" ]; do
      #prompt for sensitive client_secret until it is set
      read -s -p "Enter client_secret: " KEYFACTOR_CLIENT_SECRET
    done
  fi
}

function authClientCredentials(){
  checkVars
  client_id="${KEYFACTOR_CLIENT_ID}"
  client_secret="${KEYFACTOR_CLIENT_SECRET}"
  grant_type="client_credentials"
  auth_url="https://$KEYFACTOR_AUTH_HOSTNAME:${KEYFACTOR_AUTH_PORT:-8444}/realms/${KEYFFACTOR_AUTH_REALM:-Keyfactor}/protocol/openid-connect/token"

  curl -X POST $auth_url \
      --header 'Content-Type: application/x-www-form-urlencoded' \
      --data-urlencode "grant_type=$grant_type" \
      --data-urlencode "client_id=$client_id" \
      --data-urlencode "client_secret=$client_secret" > keyfactor_auth.json

  export KEYFACTOR_ACCESS_TOKEN=$(cat keyfactor_auth.json | jq -r '.access_token')

}

authClientCredentials