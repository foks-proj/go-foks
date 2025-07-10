#!/bin/bash

set -euox pipefail

. ./env.sh

ssh ${ROOT_PROD_SSH} "sudo service foks-$1 restart" 
ssh ${PROD_SSH} "journalctl -u foks-$1 -f -n 100"
