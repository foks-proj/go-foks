#!/bin/sh
# Copyright (c) 2025 ne43, Inc.
# Licensed under the MIT License. See LICENSE in the project root for details.


. ./env.sh 
cd ${SRCDIR} 

# as needed by `go install`
export GOBIN=${BINDIR} 

# as needed by `scripts/pm2.sh`
export PM2=${TOPDIR}/node_modules/.bin/pm2 

# run `air` via `go tool`
go tool air
