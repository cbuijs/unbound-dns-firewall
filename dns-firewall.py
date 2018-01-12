#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
=========================================================================================
 dns-firewall.py: v4.58-20180112 Copyright (C) 2017 Chris Buijs <cbuijs@chrisbuijs.com>
=========================================================================================

DNS filtering extension for the unbound DNS resolver.

Based on dns_filter.py by Oliver Hitz <oliver@net-track.ch> and the python
examples providen by UNBOUND/NLNetLabs/Wijngaards/Wouters and others.

At start, it reads the following files:

- blacklist  : contains a domain, IP/CIDR or regex (between forward slashes) per line to block.
- whitelist  : contains a domain, IP/CIDR or regex (between forward slasges) per line to pass thru.

Note: IP's will only be checked against responses (see 'checkresponse' below). 

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

Caching: this module will cache all results after processinging to speed things up,
see caching parameters below.

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

=========================================================================================
'''

# make sure modules can be found
import sys, commands, datetime
sys.path.append("/usr/local/lib/python2.7/dist-packages/")

# Use module regex
import regex

# Use module pysubnettree
import SubnetTree

# Use expiringdictionary for cache
from expiringdict import ExpiringDict

# logging tag
tag = 'DNS-FIREWALL INIT: '
tagcount = 0

# IP Address to redirect to, leave empty to generate REFUSED
intercept_address = '192.168.1.250'
intercept_host = 'dns-firewall.redirected.'

# List files
# Per line you can specify:
# - An IP-Address, Like 10.1.2.3
# - A CIDR-Address/Network, Like: 192.168.1.0/24
# - A Regex (start and end with forward-slash), Like: /^ad[sz]\./
# - A Domain name, Like: bad.company.com
blacklist_file = '/etc/unbound/blacklist' # Blacklist-file
whitelist_file = '/etc/unbound/whitelist' # Whitelist-file

# Lists
blacklist = dict() # Domains blacklist
whitelist = dict() # Domains whitelist
cblacklist = SubnetTree.SubnetTree() # IP blacklist
cwhitelist = SubnetTree.SubnetTree() # IP whitelist
rblacklist = dict() # Regex blacklist
rwhitelist = dict() # Regex whitelist

# Cache
cachesize = 2500
cachettl = 1800
blackcache = ExpiringDict(max_len=cachesize, max_age_seconds=cachettl)
whitecache = ExpiringDict(max_len=cachesize, max_age_seconds=cachettl)

# Forcing blacklist, use with caution
disablewhitelist = False

# Check answers/responses as well
checkresponse = True

# Automatic generated reverse entries for IP-Addresses that are blocke
autoreverse = True

# Block IPv6 queries/responses
blockv6 = False

# Debugging, Levels: 0=Minimal, 1=Default, show blocking, 2=Show all info/processing, 3=Flat out all
# The higher levels include the lower level informations
debug = 2

# Regex to match IPv4/IPv6 Addresses/Subnets (CIDR)
ipregex = regex.compile('^(([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})*|([0-9a-f]{1,4}|:)(:([0-9a-f]{0,4})){1,7}(/[0-9]{1,3})*)$', regex.I)

# Regex to match regex-entries in lists
isregex = regex.compile('^/.*/$')

# Regex tp match domains/hosts in lists
#isdomain = regex.compile('^[a-z0-9\.\-]+$', regex.I) # According RFC, Internet only
isdomain = regex.compile('^[a-z0-9_\.\-]+$', regex.I) # According RFC plus underscore, works everywhere

# Regex for excluded entries to fix issues
exclude = regex.compile('^((0{1,3}\.){3}0{1,3}|(0{1,4}|:)(:(0{0,4})){1,7})/8$', regex.I) # Bug in pysubnettree '::/8' matching IPv4 as well

#########################################################################################

# Check against domain lists
def check_name(name, bw, type, rrtype='ALL'):
    if (bw == 'white') and disablewhitelist:
        return False

    if not check_cache('white', name):
        if not check_cache(bw, name):
            # Check for IP's
            if (type == 'RESPONSE') and rrtype in ('A', 'AAAA'):
                cidr = check_ip(name,bw)
                if cidr:
                    if (debug >= 1): log_info(tag + 'Found IP \"' + name + '\" in ' + bw + '-listed network \"' + cidr + '\"')
                    add_cache(bw, name)
                    return True
                else:
                    return False

            else:
                # Check against domains
                testname = name.lower()
                while True:
                    if (bw == 'black'):
                         found = (testname in blacklist)
                    else:
                         found = (testname in whitelist)
                    if found:
                        if (debug >= 1): log_info(tag + 'Found DOMAIN \"' + name + '\", matched against ' + bw + '-list-entry \"' + testname + '\"')
                        add_cache(bw, name)
                        return True
                    elif testname.find('.') == -1:
                        break
                    else:
                        testname = testname[testname.find('.') + 1:]
                        if (debug >= 3): log_info(tag + 'Checking for ' + bw + '-listed parent domain \"' + testname + '\"')

            # Match against Regex-es
            foundregex = check_regex(name, bw, type, rrtype)
            if foundregex:
                if (debug >= 2): log_info(tag + 'Found \"' + name + '\", matched against ' + bw + '-regex \"' + foundregex +'\"')
                add_cache(bw, name)
                return True

        else:
            return True

    else:
        if (bw == 'white'):
            return True

    return False


# Check cache
def check_cache(bw, name):
    if (bw == 'black'):
        if name in blackcache:
            if (debug >= 2): log_info(tag + 'Found \"' + name + '\" in black-cache')
            return True
    else:
        if name in whitecache:
            if (debug >= 2): log_info(tag + 'Found \"' + name + '\" in white-cache')
            return True

    return False


# Add to cache
def add_cache(bw, name):

    if autoreverse:
        addarpa = revip(name)
    else:
        addarpa = False

    if (bw == 'black'):
       if (debug >= 2): log_info(tag + 'Added \"' + name + '\" to black-cache')
       blackcache[name] = True

       if addarpa:
           if (debug >= 2): log_info(tag + 'Auto-Generated/Added \"' + addarpa + '\" (' + name + ') to black-cache')
           blackcache[addarpa] = True

    else:
       if (debug >= 2): log_info(tag + 'Added \"' + name + '\" to white-cache')
       whitecache[name] = True

       ## Cleanup, maybe redundant
       #if (name in blackcache):
       #    blackcache.pop(name)
       #if (name in blacklist):
       #    blacklist.pop(name)

       if addarpa:
           if (debug >= 2): log_info(tag + 'Auto-Generated/Added \"' + addarpa + '\" (' + name + ') to white-cache')
           whitecache[addarpa] = True

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

    for i in range(1,len(rlist)/2):
        checkregex = rlist[i,1]
        if (debug >= 3): log_info(tag + 'Checking ' + name + ' against regex \"' + rlist[i,2] + '\"')
        if checkregex.search(name):
            return rlist[i,2]
        
    return False


# Reverse IP (arpa)
def revip(ip):
    if ipregex.match(ip):
        if ip.find(':') == -1:
            arpa = '.'.join(ip.split('.')[::-1]) + '.in-addr.arpa'  # Add IPv4 in-addr.arpa
        else:
            a = ip.replace(':', '')
            arpa = '.'.join(a[i:i+1] for i in range(0, len(a), 1))[::-1] + '.ip6.arpa'  # Add IPv6 ip6.arpa

        return arpa
    else:
        return False


# Read file/list
def read_list(name, regexlist, iplist, domainlist):
    if (len(name) > 0):
        try:
            with open(name, 'r') as f:
                log_info(tag + 'Reading file/list \"' + name + '\"')
                regexcount = 0
                ipcount = 0
                domaincount = 0
                for line in f:
                    entry = line.strip().lower()
                    if not (exclude.match(entry)) and not (entry.startswith("#")) and not (len(entry) == 0):
                        if (isregex.match(entry)):
                            # It is an Regex
                            cleanregex = entry.strip('/')
                            regexlist[regexcount,1] = regex.compile(cleanregex, regex.I)
                            regexlist[regexcount,2] = cleanregex
                            regexcount += 1

                        elif (ipregex.match(entry)):
                            # It is an IP
                            if line.find('/') == -1: # Check if Single IP or CIDR already
                                if line.find(':') == -1:
                                    entry = entry + '/32' # Single IPv4 Address
                                else:
                                    entry = entry + '/128' # Single IPv6 Address

                            iplist[entry] = entry
                            ipcount += 1

                        elif (isdomain.match(entry)):
                                # It is a domain
                                domainlist[entry.strip('.')] = True
                                domaincount += 1
                        else:
                            if (debug >= 2): log_info(tag + name + ': Skipped invalid line \"' + entry + '\"')
                                
                    else:
                        if (debug >= 2): log_info(tag + name + ': Skipped/Exclude line \"' + entry + '\"')

                if (debug >= 1): log_info(tag + 'Fetched ' + str(regexcount) + ' REGEXES, ' + str(ipcount) + ' CIDRS and ' + str (domaincount) + ' DOMAINS from file/list \"' + name + '\"')

            return True

        except IOError:
            log_error(tag + 'Unable to open file ' + name)

        return False

    else:
        return True


# Decode names/strings from response message
def decodedata(rawdata, start):
    text = ''
    remain = ord(rawdata[2])
    for c in rawdata[3+start:]:
       if remain == 0:
           text += '.'
           remain = ord(c)
           continue
       remain -= 1
       text += c
    return text.strip('.').lower()


# Generate response DNS message
def generate_response(qstate, rname, rtype, rrtype):
    if (len(intercept_address) > 0 and len(intercept_host) > 0) and (rtype in ('A', 'CNAME', 'MX', 'NS', 'PTR', 'SOA', 'SRV', 'TXT', 'ANY')):
        qname = False

        if rtype in ('CNAME', 'MX', 'NS', 'PTR', 'SOA', 'SRV'):
            if rtype == 'MX':
                fname = '0 ' + intercept_host
            elif rtype == 'SOA':
                serial = datetime.datetime.now().strftime("%Y%m%d%H")
                fname = intercept_host + ' hostmaster.' + intercept_host + ' ' + serial + ' 86400 7200 3600000 120'
            elif rtype == 'SRV':
                fname = '0 0 80 ' + intercept_host
            else:
                fname = intercept_host

            rmsg = DNSMessage(rname, rrtype, RR_CLASS_IN, PKT_QR | PKT_RA )
            redirect = '\"' + intercept_host.strip('.') + '\" (' + intercept_address + ')'
            rmsg.answer.append('%s %d IN %s %s' % (rname, cachettl, rtype, fname))
            qname = intercept_host
        elif rtype == 'TXT':
            rmsg = DNSMessage(rname, rrtype, RR_CLASS_IN, PKT_QR | PKT_RA )
            redirect = '\"BLOCKED BY DNS-FIREWALL\"'
            rmsg.answer.append('%s %d IN %s %s' % (rname, cachettl, rtype, redirect))
        else:
            rmsg = DNSMessage(rname, RR_TYPE_A, RR_CLASS_IN, PKT_QR | PKT_RA )
            redirect = intercept_address
            qname = rname + '.'

        if qname:
		rmsg.answer.append('%s %d IN A %s' % (qname, cachettl, intercept_address))

        rmsg.set_return_msg(qstate)

        if not rmsg.set_return_msg(qstate):
            log_error(tag + 'GENERATE-RESPONSE ERROR: ' + str(rmsg.answer))
            return False

        if qstate.return_msg.qinfo:
            invalidateQueryInCache(qstate, qstate.return_msg.qinfo)

        qstate.no_cache_store = 0
        storeQueryInCache(qstate, qstate.return_msg.qinfo, qstate.return_msg.rep, 0)

        qstate.return_msg.rep.security = 2

        return redirect

    return False


# Initialization
def init(id, cfg):
    log_info(tag + 'Initializing')

    # Read domains
    if not disablewhitelist:
        read_list(whitelist_file, rwhitelist, cwhitelist, whitelist)
    else:
        if (debug >= 1): log_info(tag + 'Whitelist Disabled')

    read_list(blacklist_file, rblacklist, cblacklist, blacklist)

    # Redirect entry, we don't want to expose it
    blacklist[intercept_host.strip('.')] = True

    if len(intercept_address) == 0:
        if (debug >= 1): log_info(tag + 'Using REFUSED for matched queries/responses')
    else:
        if (debug >= 1): log_info(tag + 'Using REDIRECT to \"' + intercept_address + '\" for matched queries/responses')
    return True

    if blockv6:
        if (debug >= 1): log_info(tag + 'Blocking IPv6-Based queries')


def client_ip(qstate):
    reply_list = qstate.mesh_info.reply_list

    while reply_list:
        if reply_list.query_reply:
            return reply_list.query_reply.addr
        reply_list = reply_list.next

    return "?"


def deinit(id):
    return True


def inform_super(id, qstate, superqstate, qdata):
    return True


# Main beef
def operate(id, event, qstate, qdata):

    global tag
    global tagcount

    tagcount += 1

    # New query or new query passed by other module
    if event == MODULE_EVENT_NEW or event == MODULE_EVENT_PASS:
        tag = 'DNS-FIREWALL ' + client_ip(qstate) + ' QUERY (#' + str(tagcount) + '): '

        # Get query name
        qname = qstate.qinfo.qname_str.rstrip('.').lower()
        if qname:
            qtype = qstate.qinfo.qtype_str.upper()

            if (debug >= 2): log_info(tag + 'Started on \"' + qname + '\" (RR:' + qtype + ')')

            blockit = False
            if blockv6:
                if (qtype == 'AAAA') or (qname.find('.ip6.arpa') > 0):
                    if (debug >= 2): log_info(tag + 'Detected IPv6 for \"' + qname + '\" (RR:' + qtype + ')')
                    blockit = True

            # Check if whitelisted, if so, end module and DNS resolution continues as normal (no filtering)
            if blockit or not check_name(qname, 'white', 'QUERY', qtype):
                # Check if blacklisted, if so, genrate response accordingly
                if blockit or check_name(qname, 'black', 'QUERY', qtype):
                    blockit = True

                    # Create response
                    target = generate_response(qstate, qname, qtype, qstate.qinfo.qtype)
                    if target:
                        if (debug >= 1): log_info(tag + 'REDIRECTED \"' + qname + '\" (RR:' + qtype + ') to ' + target)
                        qstate.return_rcode = RCODE_NOERROR
                    else:
                        if (debug >= 1): log_info(tag + 'REFUSED \"' + qname + '\" (RR:' + qtype + ')')
                        qstate.return_rcode = RCODE_REFUSED
                    
            if (debug >= 2): log_info(tag + 'Finished on \"' + qname + '\" (RR:' + qtype + ')')
            if blockit:
                qstate.ext_state[id] = MODULE_FINISHED
                return True

        # Not blacklisted, Nothing to do, all done
        qstate.ext_state[id] = MODULE_WAIT_MODULE
        return True

    if event == MODULE_EVENT_MODDONE:

        tag = 'DNS-FIREWALL ' + client_ip(qstate) + ' RESPONSE (#' + str(tagcount) + '): '

        if checkresponse:
            # Do we have a message
            msg = qstate.return_msg
            if msg:
                # Response message
                rep = msg.rep
                rc = rep.flags & 0xf
                if (rc == RCODE_NOERROR) or (rep.an_numrrsets > 0):
                    # Initialize base variables
                    name = False
                    blockit = False

                    # Get query-name and type and see if it is in cache already
                    qname = qstate.qinfo.qname_str.rstrip('.').lower()
                    if qname:
                        qtype = qstate.qinfo.qtype_str.upper()
                        if not check_cache('white', qname):
                            if not check_cache('black', qname):
                                # Loop through RRSets
                                for i in range(0,rep.an_numrrsets):
                                    rk = rep.rrsets[i].rk
                                    type = rk.type_str.upper()
                                    dname = rk.dname_str.rstrip('.').lower()

                                    # Start checking if black/whitelisted
                                    if dname:
                                        if (debug >= 2): log_info(tag + 'Starting on RESPONSE for QUERY \"' + dname + '\" (RR:' + type + ')')
                                        if not check_name(dname, 'white', 'RESPONSE', type):
                                            if not check_name(dname, 'black', 'RESPONSE', type):
        
                                                # Not listed yet, lets get data
                                                data = rep.rrsets[i].entry.data

                                                # Loop through data records
                                                for j in range(0,data.count):

                                                    # get answer section
                                                    answer = data.rr_data[j]

                                                    # Check if supported ype to record-type
                                                    if type in ('A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SOA', 'SRV'):
                                                        ip6 = False

                                                        # Fetch Address or Name based on record-Type
                                                        if type == 'A':
                                                            name = "%d.%d.%d.%d"%(ord(answer[2]),ord(answer[3]),ord(answer[4]),ord(answer[5]))
                                                        elif type == 'AAAA':
                                                            name = "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x"%(ord(answer[2]),ord(answer[3]),ord(answer[4]),ord(answer[5]),ord(answer[6]),ord(answer[7]),ord(answer[8]),ord(answer[9]),ord(answer[10]),ord(answer[11]),ord(answer[12]),ord(answer[13]),ord(answer[14]),ord(answer[15]),ord(answer[16]),ord(answer[17]))
                                                            if blockv6:
                                                                ip6 = True
                                                        elif type in ('CNAME', 'NS'):
                                                            name = decodedata(answer,0)
                                                        elif type == 'MX':
                                                            name = decodedata(answer,1)
                                                        elif type == 'PTR':
                                                            name = decodedata(answer,0)
                                                            if (name.find('.ip6.arpa') > 0):
                                                                ip6 = True
                                                        elif type == 'SOA':
                                                            name = decodedata(answer,0).split(' ')[0][0].strip('.')
                                                        elif type == 'SRV':
                                                            name = decodedata(answer,5)
                                                        else:
                                                            # Not supported
                                                            name = False
    
                                                        # If we have a name, process it
                                                        if name:
                                                            if (debug >= 2): log_info(tag + 'Checking \"' + dname + '\" -> \"' + name + '\" (RR:' + type + ')')
                                                            if blockv6 and ip6:
                                                                if (debug >= 2): log_info(tag + 'Detected IPv6 for \"' + name + '\" (RR:' + type + ')')
                                                                blockit = True
                                                                break

                                                            # Not Whitelisted?
                                                            if not check_name(name, 'white', 'RESPONSE', type):
                                                                # Blacklisted?
                                                                if check_name(name, 'black', 'RESPONSE', type):
                                                                    blockit = True
                                                                    break
    
                                                            else:
                                                                # Already whitelisted, lets abort processing and passthru
                                                                blockit = False
                                                                break
                                                    else:
                                                        # If not an A, AAAA, CNAME, MX, PTR, SOA or SRV we stop processing and passthru
                                                        if (debug >=2): log_info(tag + 'Ignoring RR-type ' + type)
                                                        blockit = False

                                            else:
                                                # Response Blacklisted
                                                blockit = True
                                                break

                                        else:
                                            # Response Whitelisted
                                            blockit = False
                                            break

                                        if (debug >= 2): log_info(tag + 'Finished on \"' + dname + '\" (RR:' + type + ')')

                                    else:
                                        # Nothing to process
                                        blockit = False

                                    if blockit:
                                        # if we found something to block, abort loop and start blocking
                                        break

                            else:
                                # Query Blacklisted
                                blockit = True

                        else:
                            # Query Whitelisted
                            blockit = False


                        # Block it and generate response accordingly, otther wise DNS resolution continues as normal
                        if blockit:
                            if name:
                                # Block based on response
                                rname = name
                                lname = dname + " -> " + name
                                rtype = type

                                # Add query-name to black-cache
                                if not check_cache('black', qname):
                                    add_cache('black', qname)
 
                            else:
                                # Block based on query
                                rname = qname
                                lname = qname
                                rtype = qtype

                            # Add response-name to the black-cache
                            if not check_cache('black', rname):
                                add_cache('black', rname)

                            # Generate response based on query-name
                            target = generate_response(qstate, qname, qtype, qstate.qinfo.qtype)
                            if target:
                                if (debug >= 1): log_info(tag + 'REDIRECTED \"' + lname + '\" (RR:' + rtype + ') to ' + target)
                                qstate.return_rcode = RCODE_NOERROR
                            else:
                                if (debug >= 1): log_info(tag + 'REFUSED \"' + lname + '\" (RR:' + rtype + ')')
                                qstate.return_rcode = RCODE_REFUSED

        # All done
        qstate.ext_state[id] = MODULE_FINISHED
        return True

    # Oops, non-supported event
    log_err('pythonmod: BAD Event')
    qstate.ext_state[id] = MODULE_ERROR
    return False

# <EOF>
