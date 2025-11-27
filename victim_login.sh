#!/bin/sh

# Simple victim login script
while true; do
    echo "SENDING LOGIN REQUEST"
    curl -s -X POST -d "username=victim&password=secret" http://172.18.0.30/login
    sleep 5
done
