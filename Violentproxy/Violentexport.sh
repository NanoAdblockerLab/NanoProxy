#!/bin/bash

# This is a quick certificate export script for Bash on Ubuntu on Windows
# It may not always work, please review the following code so you won't suffer data loss

rm -rf /mnt/c/Violentcert

set -e

mkdir /mnt/c/Violentcert
mv /root/Violent* /mnt/c/Violentcert
