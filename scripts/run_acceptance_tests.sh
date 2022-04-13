#!/bin/bash
set -uex

export VAULT_ACC=1
export TEST_GRAFANA_CLOUD_ORGANISATION="SET AN ORGANISATION"
export TEST_GRAFANA_CLOUD_API_KEY="SET A KEY"
export TEST_GRAFANA_CLOUD_URL="https://grafana.com/api/"

go test -v -run TestAcceptanceUserToken
go test -v -run TestAccUserToken