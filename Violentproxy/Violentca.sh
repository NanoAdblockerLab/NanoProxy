#!/bin/bash -e

# Create a certificate authority

openssl genrsa -out /root/Violentca.pem 4096
openssl req -x509 -new -nodes -key /root/Violentca.pem -days 365 -out /root/Violentca.crt -subj "/O=Violentca"
