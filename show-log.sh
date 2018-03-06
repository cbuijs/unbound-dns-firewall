#!/bin/bash

multitail -F multitail.conf -p l -D -e "DNS-FIREWALL" -kS "(DNS-FIREWALL.*)" -cS "DNS-FIREWALL" -f /var/log/syslog

