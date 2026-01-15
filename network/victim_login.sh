#!/bin/sh

# Simple victim login script
while true
do
    printf "\nSENDING LOGIN REQUEST\n"
    curl -s -L --cacert website.crt -X POST \
        -d "username=victim&password=secret" \
        http://website.ocs/login
    sleep 5
done
