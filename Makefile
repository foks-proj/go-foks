# Copyright (c) 2025 ne43, Inc.
# Licensed under the MIT License. See LICENSE in the project root for details.


include make/client.mk
include make/server.mk

.PHONY: test-compile
test-compile: client-test-compile server-test-compile