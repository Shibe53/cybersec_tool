#!/bin/sh

# Simple victim login script
apk add curl
while true; do
    echo "SENDING LOGIN REQUEST"
    curl -s -X POST \
        -d "username=victim&password=secret" \
        http://website.ocs/login
    sleep 5
done