#!/usr/bin/python
# -*- coding: utf-8 -*-

'''
=================================================================================
dns-firewall.py: v1.06 Copyright (C) 2017 Chris Buijs <cbuijs@chrisbuijs.com>
=================================================================================

Based on dns_filter.py by Oliver Hitz <oliver@net-track.ch>

DNS filtering extension for the unbound DNS resolver.

At start, it reads the following files:

- domain.blacklist  : contains a domain per line to block.
- regex.blacklist   : contains a regex per line to match a domain to block.
- domain.whitelist  : contains a domain per line to pass through.
- regex.whitelist   : contains a regex per line to match a domain to pass through.

For every query sent to unbound, the extension checks if the name is in the
lists and matches. If it is in the whitelist, processing continues
as usual (i.e. unbound will resolve it). If it is in the blacklist, unbound
stops resolution and returns the IP address configured in intercept_address,
or NXDOMAIN response if left empty.

Note: The whitelist has precedence over blacklist.

The whitelist and blacklist domain matching is done with every requested domain
and includes it subdomains.

The regex versions will match whatever is defined. It will match sequentially
and stops processing after the first hit.

Install and configure:

- Copy dns-firewall.py to unbound directory. 
- If needed, change "intercept_address" below.
- Change unbound.conf as follows:

  server:
    module-config: "python validator iterator"

  python:
    python-script: "/unbound/directory/dns-firewall.py"

- Create the above lists as desired (filenames can be modified below).
- Restart unbound.

=================================================================================
'''

import re

blacklist = set()
whitelist = set()
rblacklist = set()
rwhitelist = set()

# IP Address to redirect to, leave empty to generate NXDOMAIN
intercept_address = '192.168.1.250'

blacklist_file = '/etc/unbound/domain.blacklist'
whitelist_file = '/etc/unbound/domain.whitelist'
rblacklist_file = '/etc/unbound/regex.blacklist'
rwhitelist_file = '/etc/unbound/regex.whitelist'


def check_name(name, xlist, bw):
    #log_info('DNS_FIREWALL: Checking \"' + name + '\" against domain '+ bw + 'list')
    fullname = name
    while True:
        #log_info('DNS-FIREWALL: Checking name \"' + name + '\"')
        if name in xlist:
	    log_info('DNS-FIREWALL: \"' + fullname + '\" matched against ' + bw + 'list-entry \"' + name + '\"')
            return True
        elif name.find('.') == -1:
            return False
        else:
            name = name[name.find('.') + 1:]
    return False


def check_regex(name, xlist, bw):
    #log_info('DNS_FIREWALL: Checking \"' + name + '\" against regex '+ bw + 'list')
    for regex in xlist:
        #log_info('DNS-FIREWALL: Checking regex \"' + regex + '\"')
        if re.match(regex, name, re.I | re.M):
	    log_info('DNS-FIREWALL: \"' + name + '\" matched against ' + bw + '-regex \"' + regex + '\"')
            return True
    return False


def read_list(name, xlist):
    log_info('DNS-FIREWALL: Reading file/list \"' + name + '\"')
    try:
        with open(name, 'r') as f:
            for line in f:
	        if not line.startswith("#") and not len(line.strip()) == 0:
                    xlist.add(line.rstrip())
        return True
    except IOError:
        log_info('DNS-FIREWALL: Unable to open file ' + name)
    return False


def init(id, cfg):
    log_info('DNS-FIREWALL: Initializing')
    read_list(whitelist_file, whitelist)
    read_list(blacklist_file, blacklist)
    read_list(rwhitelist_file, rwhitelist)
    read_list(rblacklist_file, rblacklist)
    if len(intercept_address) == 0:
        log_info('DNS_FIREWALL: Using NXDOMAIN response for matched queries')
    else:
        log_info('DNS_FIREWALL: Using \"' + intercept_address + '\" as response for matched queries')
    return True


def deinit(id):
    return True


def inform_super(
    id,
    qstate,
    superqstate,
    qdata,
    ):
    return True


def operate(
    id,
    event,
    qstate,
    qdata,
    ):

    if event == MODULE_EVENT_NEW or event == MODULE_EVENT_PASS:

        # Check if whitelisted.

        name = qstate.qinfo.qname_str.rstrip('.')

        log_info('DNS_FIREWALL: Checking \"' + name + '\"')

        #log_info('DNS_FIREWALL: Checking \"' + name + '\" against whitelists')
        if check_name(name, whitelist, 'white') or check_regex(name, rwhitelist, 'white'):
            log_info('DNS_FIREWALL: \"' + name + '\" is whitelisted, PASSTHRU')
            qstate.ext_state[id] = MODULE_WAIT_MODULE
            return True

        #log_info('DNS_FIREWALL: Checking \"' + name + '\" against blacklists')
        if check_name(name, blacklist, 'black') or check_regex(name, rblacklist, 'black'):
            msg = DNSMessage(qstate.qinfo.qname_str, RR_TYPE_A,
                             RR_CLASS_IN, PKT_QR | PKT_RA | PKT_AA)

            if len(intercept_address) == 0:
                log_info('DNS_FIREWALL: Blocked \"' + name + '\", generated NXDOMAIN')
                qstate.return_rcode = RCODE_NXDOMAIN
            else:
                if qstate.qinfo.qtype == RR_TYPE_A or qstate.qinfo.qtype \
                    == RR_TYPE_ANY:
                    msg.answer.append('%s 10 IN A %s'
                                      % (qstate.qinfo.qname_str,
                                      intercept_address))
                qstate.return_rcode = RCODE_NOERROR
                log_info('DNS_FIREWALL: Blocked, \"' + name + '\", REDIRECTED to ' + intercept_address)
            
            if not msg.set_return_msg(qstate):
                qstate.ext_state[id] = MODULE_ERROR
                return False

            qstate.return_msg.rep.security = 2

            qstate.ext_state[id] = MODULE_FINISHED
            return True
        else:
            qstate.ext_state[id] = MODULE_WAIT_MODULE
            return True

    if event == MODULE_EVENT_MODDONE:

        # log_info('pythonmod: iterator module done')
        qstate.ext_state[id] = MODULE_FINISHED
        return True

    log_err('pythonmod: bad event')
    qstate.ext_state[id] = MODULE_ERROR
    return False

