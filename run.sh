#!/bin/sh
MY_IP="192.168.22.135"
MY_PORT="8000"
TG_IP="45.76.100.53"
TG_PORT="80"
make
rmmod mynat.ko
insmod mynat.ko my_ip=$MY_IP my_port=$MY_PORT tg_ip=$TG_IP tg_port=$TG_PORT

ping -c 10 $TG_IP >/dev/null 2>&1 &
