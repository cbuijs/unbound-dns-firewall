#!/usr/bin/env pypy
# -*- coding: utf-8 -*-

'''
=================================================================================
 dns-firewall.py: v3.2 Copyright (C) 2017 Chris Buijs <cbuijs@chrisbuijs.com>
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

- Better Documentation / Remarks / Comments
- Feature to configure if whitelist or blacklist has precedence (now whitelist has)

=================================================================================
'''

# make sure modules can be found
import sys, commands
sys.path.append("/usr/local/lib/python2.7/dist-packages/")

# Use regexes
import re

# Use module pysubnettree
import SubnetTree

# Use expiringdictionary for cache
from expiringdict import ExpiringDict

# Lists
blacklist = dict() # Domains blacklist
whitelist = dict() # Domains whitelist
cblacklist = SubnetTree.SubnetTree() # IP blacklist
cwhitelist = SubnetTree.SubnetTree() # IP whitelist
rblacklist = set() # Regex blacklist
rwhitelist = set() # Regex whitelist

# IP Address to redirect to, leave empty to generate REFUSED
intercept_address = '192.168.1.250'

# List-files. Use one domain, IP or CIDR subnet per line
blacklist_file = '/etc/unbound/domain.blacklist' # Domain/IP blacklist-file
whitelist_file = '/etc/unbound/domain.whitelist' # Domain/IP whitelist-file
rblacklist_file = '/etc/unbound/regex.blacklist' # Regex blacklist-file
rwhitelist_file = '/etc/unbound/regex.whitelist' # Regex whitelist-file

# Cache
cachesize = 5000
cachettl = 3600
blackcache = ExpiringDict(max_len=cachesize, max_age_seconds=cachettl)
whitecache = ExpiringDict(max_len=cachesize, max_age_seconds=cachettl)

# Check answers/responses as well
checkresponse = True

# Debugging, Levels: 0=Standard, 1=Show extra query info, 2=Show all info/processing, 3=Everything/Loud!
# The higher levels include the lower level informations
debug = 2

# Regex to match IPv4/IPv6 Addresses/Subnets (CIDR)
ipregex = re.compile('^(([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})*|([0-9a-f]{1,4}|:)(:([0-9a-f]{0,4})){1,7}(/[0-9]{1,3})*)$', re.I)

#################################################################

# Check against domain lists
def check_name(name, bw, type, rrtype='ALL'):
    if (type == 'RESPONSE') and not checkresponse:
        if (debug >= 2): log_info('DNS-FIREWALL: NOT checking ' + type + ' \"' + name + '\" (RR:' + rrtype + ') against '+ bw + '-list')
        return False

    if not check_cache('white', name):
        if not check_cache(bw, name):
            # Check for IP's
            if (type == 'RESPONSE') and rrtype in ('A', 'AAAA'):
                if (debug >= 2): log_info('DNS-FIREWALL: Checking ' + type + ' \"' + name + '\" (RR:' + rrtype + ') against CIDR '+ bw + '-list')
                cidr = check_ip(name,bw)
                if cidr:
                    if (debug >= 1): log_info('DNS-FIREWALL: ' + type + ' \"' + name + '\" matched against CIDR ' + bw + '-list \"' + cidr + '\"')
                    add_cache(bw, name)
                    return True
                else:
                    return False

            else:
                # Check against domains
                if (debug >= 2): log_info('DNS-FIREWALL: Checking ' + type + ' \"' + name + '\" (RR:' + rrtype + ') against domain '+ bw + '-list')
                testname = name.lower()
                while True:
                    if (bw == 'black'):
                         found = (testname in blacklist)
                    else:
                         found = (testname in whitelist)
                    if found:
                        if (debug >= 1): log_info('DNS-FIREWALL: ' + type + ' \"' + name + '\" matched against ' + bw + '-list-entry \"' + testname + '\"')
                        add_cache(bw, name)
                        return True
                    elif testname.find('.') == -1:
                        break
                    else:
                        testname = testname[testname.find('.') + 1:]
                        if (debug >= 2): log_info('DNS-FIREWALL: Checking for ' + bw + '-listed parent domain \"' + testname + '\"')

            # Match against Regex-es
            if check_regex(name, bw, type, rrtype):
                add_cache(bw, name)
                return True

        else:
            return True

    else:
        if (bw == 'white'):
            return True

    if (bw == 'black') and (debug >= 1): log_info('DNS-FIREWALL: NEUTRAL ' + type + ' \"' + name + '\"')
        
    return False


# Check cache
def check_cache(bw, name):
    if (bw == 'black'):
        if name in blackcache:
            log_info('DNS-FIREWALL: Found \"' + name + '\" in black-CACHE')
            return True
    else:
        if name in whitecache:
            log_info('DNS-FIREWALL: Found \"' + name + '\" in white-CACHE')
            return True

    return False


# Add to cache
def add_cache(bw, name):
    if (bw == 'black'):
       log_info('DNS-FIREWALL: Added \"' + name + '\" to black-CACHE')
       blackcache[name] = True
    else:
       log_info('DNS-FIREWALL: Added \"' + name + '\" to white-CACHE')
       whitecache[name] = True

    return True


# Check against IP lists (called from check_name)
def check_ip(ip, bw):
    if (bw == 'black'):
	if ip in cblacklist:
            return cblacklist[ip]
    else:
        if ip in cwhitelist:
            return cwhitelist[ip]

    return False


# Check against REGEX lists (called from check_name)
def check_regex(name, bw, type, rrtype='ALL'):
    if (bw == 'black'):
        rlist = rblacklist
    else:
        rlist = rwhitelist

    if (debug >= 2): log_info('DNS-FIREWALL: Checking ' + type + ' \"' + name + '\" (RR:' + rrtype + ') against regex '+ bw + '-list')
    for regex in rlist:
        if (debug >= 3): log_info('DNS-FIREWALL: Checking ' + name + ' against regex \"' + regex + '\"')
        if re.search(regex, name, re.I):
            if (debug >= 1): log_info('DNS-FIREWALL: ' + type + ' \"' + name + '\" matched against ' + bw + '-regex \"' + regex +'\"')
            return True

    return False


# Read file-lists and process
def read_list(name, xlist, ip=False, regex=False):
    if ip:
        listtype = 'IP/CIDR'
    elif regex:
        listtype = 'REGEX'
    else:
        listtype = 'DOMAIN'

    if (len(name) > 0):
        try:
            with open(name, 'r') as f:
                count = 0
                for line in f:
                    entry = line.strip()
                    if not entry.startswith("#") and not len(entry.strip()) == 0:
                        # Are we processing IP's
                        if ip:
                            if ipregex.match(entry): # Check if IP-Address
                                if line.find('/') == -1: # Check if Single IP or CIDR already
                                    if line.find(':') == -1:
                                        entry = entry + '/32' # Single IPv4 Address
                                    else:
                                        entry = entry + '/128' # Single IPv6 Address

                                xlist[entry] = entry
                                count += 1
                        else:
                            # Only domains/regexes
                            if not ipregex.match(entry): # Check if IP-Address
                                #xlist.add(entry.lower())
                                if regex:
                                    xlist.add(entry)
                                else:
                                    xlist[entry.lower()] = True
                                count += 1

                log_info('DNS-FIREWALL: Fetched ' + str(count) + ' ' + listtype + ' entries from file/list \"' + name + '\"')

            return True

        except IOError:
            log_info('DNS-FIREWALL: Unable to open file ' + name)

        return False
    else:
        return True


# Decode names/strings from response message
def decodedata(rawdata,start):
    text = ''
    remain = ord(rawdata[2])
    for c in rawdata[3+start:]:
       if remain == 0:
           text += '.'
           remain = ord(c)
           continue
       remain -= 1
       text += c.lower()
    return text.strip('.')


# Initialization
def init(id, cfg):
    log_info('DNS-FIREWALL: Initializing')

    # Read domains
    read_list(whitelist_file, whitelist, False, False)
    read_list(blacklist_file, blacklist, False, False)

    # Redirect entry, we don't want to expose it
    blacklist['dns-firewall.redirected'] = True

    # Read IP's, only needed if we check responses
    if checkresponse:
        read_list(whitelist_file, cwhitelist, True, False)
        read_list(blacklist_file, cblacklist, True, False)

    # Read REGEX-es
    read_list(rwhitelist_file, rwhitelist, False, True)
    read_list(rblacklist_file, rblacklist, False, True)

    if len(intercept_address) == 0:
        log_info('DNS-FIREWALL: Using REFUSED for matched queries/responses')
    else:
        log_info('DNS-FIREWALL: Using REDIRECT to \"' + intercept_address + '\" for matched queries/responses')
    return True


def deinit(id):
    return True


def inform_super(id, qstate, superqstate, qdata):
    return True


# Main beef
def operate(id, event, qstate, qdata):

    # New query or new query passed by other module
    if event == MODULE_EVENT_NEW or event == MODULE_EVENT_PASS:

        # Get query name
        name = qstate.qinfo.qname_str.rstrip('.').lower()
        if name:
            # Check if whitelisted, if so, end module and DNS resolution continues as normal (no filtering)
            if check_name(name, 'white', 'QUERY'):
                if (debug >= 1): log_info('DNS-FIREWALL: Found QUERY \"' + name + '\" (' + qstate.qinfo.qtype_str + ') in whitelist, PASSTHRU')
                qstate.ext_state[id] = MODULE_WAIT_MODULE
                return True

            # Check if blacklisted, if so, genrate response accordingly
            if check_name(name, 'black', 'QUERY'):
                if (debug >= 1): log_info('DNS-FIREWALL: Found QUERY \"' + name + '\" (' + qstate.qinfo.qtype_str + ') in blacklist')

                msg = DNSMessage(qstate.qinfo.qname_str, RR_TYPE_A, RR_CLASS_IN, PKT_QR | PKT_RA | PKT_AA)
                msg.answer = []

                # If intercept_address is empty, generate return-code REFUSED, otherwise generate answer to redirect
                if len(intercept_address) == 0:
                    log_info('DNS-FIREWALL: Blocked QUERY \"' + name + '\" (' + qstate.qinfo.qtype_str + '), generated REFUSED')
                    invalidateQueryInCache(qstate, qstate.return_msg.qinfo)
                    qstate.return_rcode = RCODE_REFUSED
                else:
                    # Can only redirect for A, CNAME and ANY record-types, if not one of those, a REFUSE is generated
                    qtype = qstate.qinfo.qtype_str.upper()
                    if qtype in ('A', 'CNAME', 'PTR' , 'ANY'):
                        if qtype in ('CNAME', 'PTR'):
                            fqname = 'dns-firewall.redirected.'
                            redirect = fqname.strip('.') + '/' + intercept_address
                            msg.answer.append('%s 10 IN %s %s' % (qstate.qinfo.qname_str, qtype, fqname))
                        else:
                            fqname = name
                            redirect = intercept_address

                        msg.answer.append('%s 10 IN A %s' % (fqname, intercept_address))

                        log_info('DNS-FIREWALL: Blocked QUERY \"' + name + '\" (' + qstate.qinfo.qtype_str + '), REDIRECTED to ' + redirect)

                        qstate.return_rcode = RCODE_NOERROR
                    else:
                        log_info('DNS-FIREWALL: Blocked QUERY \"' + name + '\" (' + qstate.qinfo.qtype_str + '), generated REFUSED (Not an A, CNAME, PTR or ANY record)')
                        qstate.return_rcode = RCODE_REFUSED

                # Check if message is okay, if not end with error
                if not msg.set_return_msg(qstate):
                    qstate.ext_state[id] = MODULE_ERROR
                    return False

                # Allow response modification (Security setting)
                qstate.return_msg.rep.security = 2

                # All done
                qstate.ext_state[id] = MODULE_FINISHED
                return True

        # Not blacklisted, Nothing to do, all done
        qstate.ext_state[id] = MODULE_WAIT_MODULE
        return True

    if event == MODULE_EVENT_MODDONE:

        # Are we filtering on responses
        if checkresponse:
            # Do we have a message
            msg = qstate.return_msg
            if msg:
                # Get query-name
                qname = msg.qinfo.qname_str.rstrip(".").lower()
                if qname:
                    # Check if query is not whitelisted
                    blockit = False
                    name = False
                    if not check_name(qname, 'white', 'QUERY'):
                        # Check if query is not blacklisted
                        if not check_name(qname, 'black', 'QUERY'):
                            type = msg.qinfo.qtype_str.upper()
                            name = False
                            # Get response and loop through the RRSets
                            rep = msg.rep
                            for i in range(0,rep.an_numrrsets):
                                rk = rep.rrsets[i].rk
                                data = rep.rrsets[i].entry.data
                                type = rk.type_str.upper()
                                # Get data
                                for j in range(0,data.count):
                                    answer = data.rr_data[j]
                                    if type in ('A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SRV'):
                                        if type == 'A':
                                            name = "%d.%d.%d.%d"%(ord(answer[2]),ord(answer[3]),ord(answer[4]),ord(answer[5]))
                                        elif type == 'AAAA':
                                            name = "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x"%(ord(answer[2]),ord(answer[3]),ord(answer[4]),ord(answer[5]),ord(answer[6]),ord(answer[7]),ord(answer[8]),ord(answer[9]),ord(answer[10]),ord(answer[11]),ord(answer[12]),ord(answer[13]),ord(answer[14]),ord(answer[15]),ord(answer[16]),ord(answer[17]))
                                        elif type in ('CNAME', 'NS', 'PTR'):
                                            name = decodedata(answer,0)
                                        elif type == 'MX':
                                            name = decodedata(answer,1)
                                        elif type == 'SRV':
                                            name = decodedata(answer,5)
                                        else:
                                            name = False

                                        if (debug >= 2): log_info('DNS-FIREWALL: Checking RESPONSE \"' + name + '\" (' + type + ') against blacklists')
                                        if check_name(name, 'black', 'RESPONSE', type):
                                            if (debug >= 1): log_info('DNS-FIREWALL: Found RESPONSE \"' + name + '\" (' + type + ') in blacklist')
                                            blockit = True
                                    else:
                                        # If not an A, AAAA, CNAME, MX, PTR or SRV we stop processing.
                                        if (debug >=2): log_info('DNS-FIREWALL: DNS record-type/num ' + type + ' skipped')
                                        blockit = False
    
                                    # Stop looping when blacklisted, no need to process further
                                    if blockit:
                                        break

                                # Stop looping when blacklisted, no need to process further
                                if blockit:
                                    break

                        else:
                            blockit = true

                        # Should we block it, if so, generate response accordingly, otther wise DNS resolution continues as normal
                        if blockit:
                            if name:
                                log_info('DNS-FIREWALL: Blocked RESPONSE \"' + qname + '\" -> \"' + name + '\" (' + type + '), generated REFUSED')
                            else:
                                log_info('DNS-FIREWALL: Blocked RESPONSE \"' + qname + '\" (QNAME), generated REFUSED')

                            # Add query-name to the black-cache
                            if not check_cache('black', qname):
                                add_cache('black', qname)

                            qstate.return_rcode = RCODE_REFUSED
                            invalidateQueryInCache(qstate, qstate.return_msg.qinfo)

                            # Allow response modification (Security setting)
                            qstate.return_msg.rep.security = 2

        # All done
        qstate.ext_state[id] = MODULE_FINISHED
        return True

    # Oops, non-supported event
    log_err('pythonmod: bad event')
    qstate.ext_state[id] = MODULE_ERROR
    return False

def parseIPPart(ipx, shift):
    if ipx is None:
        return 0
    return int(ipx) << shift


# <EOF>
