#!/bin/bash
# Copyright (c) 2025 ne43, Inc.
# Licensed under the MIT License. See LICENSE in the project root for details.


run() {

  date
  
  # running GO tests with a yubikey is slow for 2 reasons:
  #  1. Only one thread can use the yubikey at a time, so there shouldn't be any parallelism
  #  2. The yubikey is so slow. Like so slow. So everyone now and then run test with the yubikey
  #     but by-in-large, ok to use our mocked-out yubikey (which you get by default).
  #
  # Also, eventual CI won't have have a yubikey, so we need to be able to run tests without it.
  #
  yubi=false
  
  # check if there is exactly one argument and it's --yubi-destructive
  if [ "$#" -eq 1 ] && [ "$1" == "--yubi-destructive" ]; then
      yubi=true
      shift
  fi

  go tool golangci-lint run 
  if [ $? -ne 0 ]; then
      echo "golangci-lint failed"
      exit 1
  fi
  echo "ok      golangci-lint passed"
  
  if [ "$yubi" = true ]; then
      export USE_REAL_YUBIKEY=1
      go test -p 1 ./... -count=1 
  else
      go test ./... -count=1
  fi
  
  date

}

run > >(tee ci.out) 2> >(tee ci.err >&2)