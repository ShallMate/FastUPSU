#!/usr/bin/env bash
set -euo pipefail

sudo apt-get update
sudo apt-get install -y \
  build-essential cmake ninja-build git pkg-config autoconf automake libtool \
  libssl-dev libboost-all-dev libgmp-dev libntl-dev zlib1g-dev
