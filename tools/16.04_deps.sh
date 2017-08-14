#! /usr/bin/env bash
set -e

apt-get update -qq
apt-get upgrade -yqq
apt-get install python{,3}-pip python{,3}-dev build-essential python{,3}-virtualenv -yqq
if [ -f /.dockerenv ]; then
    apt-get -yqq autoremove
    apt-get -yqq clean
    rm -rf /var/lib/apt/lists/* /var/cache/* /tmp/* /usr/share/locale/* /usr/share/man /usr/share/doc /lib/xtables/libip6*
fi
