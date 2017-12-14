#!/usr/bin/python
# -*- coding: utf-8 -*-

'''
=================================================================================
 dns-firewall.py: v2.3 Copyright (C) 2017 Chris Buijs <cbuijs@chrisbuijs.com>
=================================================================================

Based on dns_filter.py by Oliver Hitz <oliver@net-track.ch> and the python
examples providen by UNBOUND/NLNetLabs/Wijngaards/Wouters.

DNS filtering extension for the unbound DNS resolver.

At start, it reads the following files:

- domain.blacklist  : contains a domain or IP per line to block.
- regex.blacklist   : contains a regex per line to match a domain or IP to block.
- domain.whitelist  : contains a domain or IP per line to pass through.
- regex.whitelist   : contains a regex per line to match a domain or IP to pass through.

Note: IP's will only be checked against responses. Also, IPv6 addresses in fully written
out, no shortcuts, all nibbles padded with zeroes and lower-case.
(example: 2001:cafe:0002:0bad:ba1d:babe:0123:beef).

For every query sent to unbound, the extension checks if the name is in the
lists and matches. If it is in the whitelist, processing continues
as usual (i.e. unbound will resolve it). If it is in the blacklist, unbound
stops resolution and returns the IP address configured in intercept_address,
or REFUSED reply if left empty.

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

TODO:

- Better documentation
- Feature to configure if whitelist or blacklist has precedence (now whitelist has)
- Support/Finish CIDR/Ranges for IP entries
- Cleanup RESPONSE/MODDONE section
- Backburner / Idea : Load native RPZ zones in BIND format (or converter?)

=================================================================================
'''

# Use regexes
import re

blacklist = set()  # Domains blacklist
whitelist = set()  # Domains whitelist
cblacklist = set() # IP blacklist
cwhitelist = set() # IP whitelist
rblacklist = set() # Regex blacklist
rwhitelist = set() # Regex whitelist

# IP Address to redirect to, leave empty to generate REFUSED
intercept_address = '192.168.1.250'

# List-files. Use one domain, IP or CIDR subnet per line
blacklist_file = '/etc/unbound/domain.blacklist' # Domain/IP blacklist-file
whitelist_file = '/etc/unbound/domain.whitelist' # Domain/IP whitelist-file
rblacklist_file = '/etc/unbound/regex.blacklist' # Regex blacklist-file
rwhitelist_file = '/etc/unbound/regex.whitelist' # Regex whitelist-file

# Check answers/responses as well
checkresponse = True

# Debugging, Levels: 0=Standard, 1=Show extra query info, 2=Show all info/processing
# The higher levels include the lower level informations
debug = 1

# Regex to match IPv4/IPv6 Addresses/Subnets (CIDR)
ipregex = re.compile('^(([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})*|([0-9a-f]{1,4}|:)(:([0-9a-f]{0,4})){1,7}(/[0-9]{1,3})*)$', re.I | re.M)

def check_name(name, xlist, bw, type, rrtype='ALL'):
    if (debug >= 2): log_info('DNS-FIREWALL: Checking ' + type + ' \"' + name + '\" (RR:' + rrtype + ') against domain '+ bw + 'list')

    if checkresponse and (type == 'RESPONSE') and ipregex.match(name):
        if (bw == 'black'):
            found = check_ip(name,cblacklist)
        else:
            found = check_ip(name,cwhitelist)

        if found:
            if (debug >= 1): log_info('DNS-FIREWALL: ' + type + ' \"' + name + '\" matched against ' + bw + 'list-entry \"' + str(found) + '\"')
            return True
    else:
        fullname = name
        while True:
            if (debug >= 2): log_info('DNS-FIREWALL: Checking sub-name \"' + name + '\"')
            if name in xlist:
                if (debug >= 1): log_info('DNS-FIREWALL: ' + type + ' \"' + fullname + '\" matched against ' + bw + 'list-entry \"' + name + '\"')
                return True
            elif name.find('.') == -1:
                return False
            else:
                name = name[name.find('.') + 1:]

    return False


def check_ip(ip, xlist):
    # To be done.
    # Returns False when IP (eg: 10.1.2.3) is NOT found in CIDR (eg: 10.0.0.0/8) list "xlist"
    # Returns the CIDR network the IP matches against
    return False


def check_regex(name, xlist, bw, type, rrtype='ALL'):
    if (debug >= 2): log_info('DNS-FIREWALL: Checking ' + type + ' \"' + name + '\" (RR:' + rrtype + ') against regex '+ bw + 'list')
    for regex in xlist:
        if (debug >= 2): log_info('DNS-FIREWALL: Checking ' + name + ' against regex \"' + regex + '\"')
        if re.match(regex, name, re.I | re.M):
            if (debug >= 1): log_info('DNS-FIREWALL: ' + type + ' \"' + name + '\" matched against ' + bw + '-regex \"' + regex + '\"')
            return True
    return False


def read_list(name, xlist, ip):
    if (ip):
        log_info('DNS-FIREWALL: Reading IP entries from file/list \"' + name + '\"')
    else:
        log_info('DNS-FIREWALL: Reading Non-IP entries from file/list \"' + name + '\"')

    try:
        with open(name, 'r') as f:
            for line in f:
                entry = line.strip()
                if not entry.startswith("#") and not len(entry.strip()) == 0:
                    if ip:
                        if ipregex.match(entry): # Check if IP-Address
                            if line.find('/') == -1: # Check if Single IP or CIDR already
                                if line.find(':') == -1:
                                    entry = entry + '/32' # Single IPv4 Address
                                else:
                                    entry = entry + '/128' # Single IPv6 Address
                            xlist.add(entry)
                    else:
                        if not ipregex.match(entry): # Check if IP-Address
                            xlist.add(entry)
        return True
    except IOError:
        log_info('DNS-FIREWALL: Unable to open file ' + name)
    return False


def decodedata(rawdata):
    text = ''
    for ch in rawdata:
        if ( ch >= '0' and ch <= '9' ) or ( ch >= 'a' and ch <= 'z') or ( ch >= 'A' and ch <= 'Z' ) or ( ch == '-' ):
            text += '%c' % ch
        else:
            text += '.'
    return text.strip('.')


def init(id, cfg):
    log_info('DNS-FIREWALL: Initializing')
    read_list(whitelist_file, whitelist, False)
    read_list(blacklist_file, blacklist, False)

    if checkresponse:
        read_list(whitelist_file, cwhitelist, True)
        read_list(blacklist_file, cblacklist, True)

    read_list(rwhitelist_file, rwhitelist, False)
    read_list(rblacklist_file, rblacklist, False)

    if len(intercept_address) == 0:
        log_info('DNS-FIREWALL: Using REFUSED for matched queries')
    else:
        log_info('DNS-FIREWALL: Using \"' + intercept_address + '\" for matched queries')
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

        name = qstate.qinfo.qname_str.rstrip('.')

        if check_name(name, whitelist, 'white', 'QUERY') or check_regex(name, rwhitelist, 'white', 'QUERY'):
            log_info('DNS-FIREWALL: \"' + name + '\" (' + qstate.qinfo.qtype_str + ') is whitelisted, PASSTHRU')
            qstate.ext_state[id] = MODULE_WAIT_MODULE
            return True

        if check_name(name, blacklist, 'black', 'QUERY') or check_regex(name, rblacklist, 'black', 'QUERY'):
            msg = DNSMessage(qstate.qinfo.qname_str, RR_TYPE_A, RR_CLASS_IN, PKT_QR | PKT_RA | PKT_AA)

            if len(intercept_address) == 0:
                log_info('DNS-FIREWALL: Blocked QUERY \"' + name + '\" (' + qstate.qinfo.qtype_str + '), generated REFUSED')
                invalidateQueryInCache(qstate, qstate.return_msg.qinfo)
                qstate.return_rcode = RCODE_REFUSED
            else:
                if qstate.qinfo.qtype == RR_TYPE_A or qstate.qinfo.qtype == RR_TYPE_CNAME or qstate.qinfo.qtype == RR_TYPE_PTR or qstate.qinfo.qtype == RR_TYPE_ANY:

                    redirect = 'dns-firewall.redirected/' + intercept_address
                    if qstate.qinfo.qtype == RR_TYPE_CNAME:
                        msg.answer.append('%s 10 IN CNAME %s' % (qstate.qinfo.qname_str, 'dns-firewall.redirected.'))
                        msg.answer.append('%s 10 IN A %s' % ('dns-firewall.redirected.', intercept_address))
                    elif qstate.qinfo.qtype == RR_TYPE_PTR:
                        msg.answer.append('%s 10 IN PTR %s' % (qstate.qinfo.qname_str, 'dns-firewall.redirected.'))
                        msg.answer.append('%s 10 IN A %s' % ('dns-firewall.redirected.', intercept_address))
                    else:
                        redirect = intercept_address
                        msg.answer.append('%s 10 IN A %s' % (qstate.qinfo.qname_str, intercept_address))

                    log_info('DNS-FIREWALL: Blocked QUERY \"' + name + '\" (' + qstate.qinfo.qtype_str + '), REDIRECTED to ' + redirect)

                    qstate.return_rcode = RCODE_NOERROR
                else:
                    log_info('DNS-FIREWALL: Blocked QUERY \"' + name + '\" (' + qstate.qinfo.qtype_str + '), generated REFUSED (Not an A, CNAME, PTR or ANY record)')
                    qstate.return_rcode = RCODE_REFUSED


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

        if checkresponse:
            msg = qstate.return_msg
            if msg:
                qname = msg.qinfo.qname_str.rstrip(".")
                if not check_name(qname, whitelist, 'white', 'QUERY-RESPONSE') and not check_regex(qname, rwhitelist, 'white', 'QUERY-RESPONSE'):
                    rep = msg.rep
                    for i in range(0,rep.an_numrrsets):
                        rk = rep.rrsets[i].rk
                        data = rep.rrsets[i].entry.data
                        type = ntohs(rk.type)
                        for j in range(0,data.count):
                            answer = data.rr_data[j]
                            rawdata = answer[2:]

                            if type == 1:
                                types = "A"
                                name = "%d.%d.%d.%d"%(ord(answer[2]),ord(answer[3]),ord(answer[4]),ord(answer[5]))
                            elif type == 2:
                                types = "NS"
                                name = decodedata(rawdata)
                            elif type == 5:
                                types = "CNAME"
                                name = decodedata(rawdata)
                            elif type == 12:
                                types = "PTR"
                                name = decodedata(rawdata)
                            elif type == 15:
                                types = "MX"
                            	rawdata = answer[4:]
                                name = decodedata(rawdata)
                            elif type == 28:
                                types = "AAAA"
                                name = "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x"%(ord(answer[2]),ord(answer[3]),ord(answer[4]),ord(answer[5]),ord(answer[6]),ord(answer[7]),ord(answer[8]),ord(answer[9]),ord(answer[10]),ord(answer[11]),ord(answer[12]),ord(answer[13]),ord(answer[14]),ord(answer[15]),ord(answer[16]),ord(answer[17]))
                            elif type == 33:
                                types = "SRV"
                            	rawdata = answer[6:]
                                name = decodedata(rawdata)
                            else:
                                if (debug >=2): log_info('DNS-FIREWALL: DNS record-type/num ' + type + ' skipped')
                                types = False

                            if types:
                                if (debug >= 2): log_info('DNS-FIREWALL: Checking RESPONSE \"' + name + '\" (' + types + ') against blacklists')
                                if check_name(name, blacklist, 'black', 'RESPONSE', types) or check_regex(name, rblacklist, 'black', 'RESPONSE', types):
                                    log_info('DNS-FIREWALL: Blocked RESPONSE \"' + qname + '\" -> \"' + name + '\" (' + types + '), generated REFUSED')
                                    invalidateQueryInCache(qstate, qstate.return_msg.qinfo)
                                    qstate.return_rcode = RCODE_REFUSED
                                    qstate.return_msg.rep.security = 2
                                    qstate.ext_state[id] = MODULE_FINISHED
                                    return True
                else:
                    if (debug >= 2): log_info('DNS-FIREWALL: Skipping RESPONSE check for \"' + qname + '\", already whitelisted in QUERY')

        qstate.ext_state[id] = MODULE_FINISHED
        return True

    log_err('pythonmod: bad event')
    qstate.ext_state[id] = MODULE_ERROR
    return False

