#!/bin/sh
# Copyright (c) 2025 ne43, Inc.
# Licensed under the MIT License. See LICENSE in the project root for details.


echo "running pm2 from ${PM2}; args: $*"
${PM2} $*
