#!/bin/sh
MY_IP="192.168.22.135"
MY_PORT="8000"
TG_IP="45.76.100.53"
TG_PORT="80"
make
rmmod mynat.ko
insmod mynat.ko

ping -c 10 45.76.100.53 >/dev/null 2>&1 &
