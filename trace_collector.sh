#! /bin/bash

sudo tcpdump -ni "$1" "port $2" -s 0 -w "$3"
