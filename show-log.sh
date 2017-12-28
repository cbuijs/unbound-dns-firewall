#!/bin/bash

multitail -p l -D -e "DNS-FIREWALL" -kS "(DNS-FIREWALL.*)" -cS "DNS-FIREWALL" -f /var/log/syslog

