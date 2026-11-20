#!/bin/sh
# Internal PKI bootstrap
openssl req -x509 -newkey rsa:2048 -keyout payflow.key -out payflow.crt -days 825 -nodes
openssl ecparam -name prime256v1 -genkey -out device-ca.key
