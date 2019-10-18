#! /usr/bin/env bash
set -e

sed -i 's/deb.debian.org/httpredir.debian.org/g' /etc/apt/sources.list

apt-get update -qq
apt-get upgrade -yqq
apt-get install python3-pip python3-dev build-essential python3-virtualenv -yqq
if [ -f /.dockerenv ]; then
    apt-get -yqq autoremove
    apt-get -yqq clean
    rm -rf /var/lib/apt/lists/* /var/cache/* /tmp/* /usr/share/locale/* /usr/share/man /usr/share/doc /lib/xtables/libip6*
fi
