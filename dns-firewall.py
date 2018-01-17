#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
=========================================================================================
 dns-firewall.py: v5.54-20180117 Copyright (C) 2018 Chris Buijs <cbuijs@chrisbuijs.com>
=========================================================================================

DNS filtering extension for the unbound DNS resolver.

Based on dns_filter.py by Oliver Hitz <oliver@net-track.ch> and the python
examples providen by UNBOUND/NLNetLabs/Wijngaards/Wouters and others.

At start, it reads the following files:

- blacklist  : contains a domain, IP/CIDR or regex (between forward slashes) per line to block.
- whitelist  : contains a domain, IP/CIDR or regex (between forward slasges) per line to pass-thru.

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

=========================================================================================
'''

# Make sure modules can be found
import sys
sys.path.append("/usr/local/lib/python2.7/dist-packages/")

# Standard/Included modules
import os, os.path, commands, datetime, gc

# Enable Garbage collection
gc.enable()

# Use requests module for downloading lists
import requests

# Use module regex instead of re, much faster less bugs
import regex

# Use module pytricia to find ip's in CIDR's fast
import pytricia

# Use expiringdictionary for cache
from expiringdict import ExpiringDict

# logging tag
tag = 'DNS-FIREWALL INIT: '
tagcount = 0

# IP Address to redirect to, leave empty to generate REFUSED
intercept_address = '192.168.1.250'
intercept_host = 'sinkhole.'

# List files
# Per line you can specify:
# - An IP-Address, Like 10.1.2.3
# - A CIDR-Address/Network, Like: 192.168.1.0/24
# - A Regex (start and end with forward-slash), Like: /^ad[sz]\./
# - A Domain name, Like: bad.company.com

# Lists file to configure which lists to use, one list per line, syntax:
# <Identifier>,<black|white>,<filename|url>[,savefile[,maxlistage[,regex]]]
lists = '/etc/unbound/dns-firewall.lists'

# Lists
blacklist = dict() # Domains blacklist
whitelist = dict() # Domains whitelist
cblacklist = pytricia.PyTricia(128) # IP blacklist
cwhitelist = pytricia.PyTricia(128) # IP whitelist
rblacklist = dict() # Regex blacklist (maybe replace with set()?)
rwhitelist = dict() # Regex whitelist (maybe replace with set()?)

# Cache
cachesize = 2500
cachettl = 120
blackcache = ExpiringDict(max_len=cachesize, max_age_seconds=cachettl)
whitecache = ExpiringDict(max_len=cachesize, max_age_seconds=cachettl)
cachefile = '/etc/unbound/cache.file'

# Save
savelists = True
blacksave = '/etc/unbound/blacklist.save'
whitesave = '/etc/unbound/whitelist.save'

# Forcing blacklist, use with caution
disablewhitelist = False

# Filtering on/off
filtering = True

# Keep state/lock on commands
command_in_progress = False

# Queries within bewlow TLD (commandtld) will be concidered commands to execute
# Only works from localhost (system running UNBOUND)
# Query will return NXDOMAIN or timeout, this is normal.
# Commands availble:
# dig @127.0.0.1 <number>.debug.commandtld - Set debug level to <Number>
# dig @127.0.0.1 save.cache.commandtld - Save cache to cachefile
# dig @127.0.0.1 reload.commandtld - Reload saved lists
# dig @127.0.0.1 force.reload.commandtld - Force fetching/processing of lists and reload
# dig @127.0.0.1 pause.commandtld - Pause filtering (everything passthru)
# dig @127.0.0.1 resume.commandtld - Resume filtering
# dig @127.0.0.1 <domain>.add.whitelist.commandtld - Add <Domain> to blacklist
# dig @127.0.0.1 <domain>.add.blacklist.commandtld - Add <Domain> to blacklist
# dig @127.0.0.1 <domain>.del.whitelist.commandtld - Remove <Domain> from whitelist
# dig @127.0.0.1 <domain>.del.blacklist.commandtld - Remove <Domain> from blacklist
commandtld = '.command'

# Check answers/responses as well
checkresponse = True

# Automatic generated reverse entries for IP-Addresses that are listed
autoreverse = True

# Block IPv6 queries/responses
blockv6 = True

# Default maximum age of downloaded lists, can be overruled in lists file
maxlistage = 86400 # In seconds

# Debugging, Levels: 0=Minimal, 1=Default, show blocking, 2=Show all info/processing, 3=Flat out all
# The higher levels include the lower level informations
debug = 2

# Regex to match IPv4/IPv6 Addresses/Subnets (CIDR)
ipregex = regex.compile('^(([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})*|([0-9a-f]{1,4}|:)(:([0-9a-f]{0,4})){1,7}(/[0-9]{1,3})*)$', regex.I)

# Regex to match regex-entries in lists
isregex = regex.compile('^/.*/$')

# Regex to match domains/hosts in lists
#isdomain = regex.compile('^[a-z0-9\.\-]+$', regex.I) # According RFC, Internet only
isdomain = regex.compile('^[a-z0-9_\.\-]+$', regex.I) # According RFC plus underscore, works everywhere

# Regex for excluded entries to fix issues
exclude = regex.compile('^((0{1,3}\.){3}0{1,3}|(0{1,4}|:)(:(0{0,4})){1,7})/[0-8]$', regex.I) # Bug in PyTricia '::/0' matching IPv4 as well

#########################################################################################

# Check against lists
def in_list(name, bw, type, rrtype='ALL'):
    if not filtering:
        if (debug >= 2): log_info(tag + 'Filtering disabled, passthru \"' + name + '\" (RR:' + rrtype + ')')
        return False

    if (bw == 'white') and disablewhitelist:
        return False

    if blockv6 and ((rrtype == 'AAAA') or name.endswith('.ip6.arpa')):
        if (bw == 'black'):
             if (debug >= 2): log_info(tag + 'HIT on IPv6 for \"' + name + '\" (RR:' + rrtype + ')')
             return True

    if not in_cache('white', name):
        if not in_cache(bw, name):
            # Check for IP's
            if (type == 'RESPONSE') and rrtype in ('A', 'AAAA'):
                cidr = check_ip(name,bw)
                if cidr:
                    if (debug >= 2): log_info(tag + 'HIT on IP \"' + name + '\" in ' + bw + '-listed network ' + cidr)
                    add_to_cache(bw, name, cidr)
                    return True
                else:
                    return False

            else:
                # Check against domains
                testname = name.lower()
                while True:
                    if (bw == 'black'):
                         found = (testname in blacklist)
                         if found:
                             id = blacklist[testname]
                    else:
                         found = (testname in whitelist)
                         if found:
                             id = whitelist[testname]

                    if found:
                        if (debug >= 2): log_info(tag + 'HIT on DOMAIN \"' + name + '\", matched against ' + bw + '-list-entry \"' + testname + '\" (' + str(id) + ')')
                        add_to_cache(bw, name, testname)
                        return True
                    elif testname.find('.') == -1:
                        break
                    else:
                        testname = testname[testname.find('.') + 1:]
                        if (debug >= 3): log_info(tag + 'Checking for ' + bw + '-listed parent domain \"' + testname + '\"')

            # Match against Regex-es
            foundregex = check_regex(name, bw)
            if foundregex:
                if (debug >= 2): log_info(tag + 'HIT on \"' + name + '\", matched against ' + bw + '-regex ' + foundregex +'')
                add_to_cache(bw, name)
                return True

        else:
            return True

    else:
        if (bw == 'white'):
            return True

    return False

# Check cache
def in_cache(bw, name):
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
def add_to_cache(bw, name, listentry=False):

    if autoreverse:
        addarpa = rev_ip(name)
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

       if addarpa:
           if (debug >= 2): log_info(tag + 'Auto-Generated/Added \"' + addarpa + '\" (' + name + ') to white-cache')
           whitecache[addarpa] = True

    return True


# Check against IP lists (called from in_list)
def check_ip(ip, bw):
    if (bw == 'black'):
	if ip in cblacklist:
            return cblacklist[ip] 
    else:
        if ip in cwhitelist:
            return cwhitelist[ip]

    return False


# Check against REGEX lists (called from in_list)
def check_regex(name, bw):
    if (bw == 'black'):
        rlist = rblacklist
    else:
        rlist = rwhitelist

    for i in range(0,len(rlist)/3):
        checkregex = rlist[i,1]
        if (debug >= 3): log_info(tag + 'Checking ' + name + ' against regex \"' + rlist[i,2] + '\"')
        if checkregex.search(name):
            return '\"' + rlist[i,2] + '\" (' + rlist[i,0] + ')'
        
    return False


# Generate Reverse IP (arpa) domain
def rev_ip(ip):
    if ipregex.match(ip):
        if ip.find(':') == -1:
            arpa = '.'.join(ip.split('.')[::-1]) + '.in-addr.arpa'  # Add IPv4 in-addr.arpa
        else:
            a = ip.replace(':', '')
            arpa = '.'.join(a[i:i+1] for i in range(0, len(a), 1))[::-1] + '.ip6.arpa'  # Add IPv6 ip6.arpa

        return arpa
    else:
        return False


# Clear lists
def clear_lists():
    tag = 'DNS-FIREWALL LISTS: '

    log_info(tag + 'Clearing Lists')
    rwhitelist.clear()
    whitelist.clear()
    for i in cwhitelist.keys():
        cwhitelist.delete(i)

    rblacklist.clear()
    blacklist.clear()
    for i in cblacklist.keys():
        cblacklist.delete(i)

    clear_cache()

    return True


# Clear cache
def clear_cache():
    tag = 'DNS-FIREWALL CACHE: '

    log_info(tag + 'Clearing Cache')
    blackcache.clear()
    whitecache.clear()

    return True


# Load lists
def load_lists(force):
    tag = 'DNS-FIREWALL LISTS: '

    # Header/User-Agent to use when downloading lists, some sites block non-browser downloads
    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36'
        }

    clear_lists()

    # Read Lists
    readblack = True
    readwhite = True
    if savelists and not force:
        age = file_exist(whitesave)
        if age and age < maxlistage and not disablewhitelist:
            log_info(tag + 'Using White-Savelist, not expired yet (' + str(age) + '/' + str(maxlistage) + ')')
            read_list('saved-whitelist', whitesave, rwhitelist, cwhitelist, whitelist)
            readwhite = False

        age = file_exist(blacksave)
        if age and age < maxlistage:
            log_info(tag + 'Using Black-Savelist, not expired yet (' + str(age) + '/' + str(maxlistage) + ')')
            read_list('saved-blacklist', blacksave, rblacklist, cblacklist, blacklist)
            readblack = False

    try:
        with open(lists, 'r') as f:
            for line in f:
                entry = line.strip()
                if not (entry.startswith("#")) and not (len(entry) == 0):
                    element = entry.split('\t')
                    if len(element) > 2:
                        id = element[0]
                        bw = element[1]
                        if (bw == 'black' and readblack) or (bw == 'white' and readwhite):
                            file = element[2]
                            if (file.find('http://') == 0) or (file.find('https://') == 0):
                                url = file
                                if len(element) > 3:
                                    file = element[3]
                                else:
                                    file = '/etc/unbound/' + id.strip('.').lower() + ".list"
    
                                if len(element) > 4:
                                    filettl = int(element[4])
                                else:
                                    filettl = maxlistage
    
                                fregex = '^(?P<entry>[a-zA-Z0-9\.\-]+)$'
                                if len(element) > 5:
                                    r = element[5]
                                    if r.find('(?P<entry>') == -1:
                                        log_err(tag + 'Regex \"' + r + '\" does not contain group-name \"entry\" (e.g: \"(?P<entry ... )\")')
                                    else:
                                        fregex = r
    
                                fexists = False
    
                                age = file_exist(file)
                                if not age or age > filettl or force:
                                    log_info(tag + 'Downloading \"' + id + '\" from \"' + url + '\" to \"' + file + '\"')
                                    r = requests.get(url, headers=headers, allow_redirects=True)
                                    if r.status_code == 200:
                                        try:
                                            with open(file + '.download', 'w') as f:
                                                f.write(r.text.encode('ascii', 'ignore'))

                                            try:
                                                with open(file + '.download', 'r') as f:
                                                    try:
                                                        with open(file, 'w') as g:
                                                            for line in f:
                                                                matchentry = regex.match(fregex, line)
                                                                if matchentry:
                                                                    g.write(matchentry.group('entry'))
                                                                    g.write('\n')

                                                    except IOError:
                                                        log_err(tag + 'Unable to write to file \"' + file + '\"')

                                            except IOError:
                                                log_err(tag + 'Unable to open file \"' + file + '.download\"')

                                        except IOError:
                                            log_err(tag + 'Unable to write to file \"' + file + '.download\"')

                                    else:
                                        log_err(tag + 'Unable to download from \"' + url + '\"')

                                else:
                                    log_info(tag + 'Skipped download \"' + id + '\" previous downloaded file \"' + file + '\" is ' + str(age) + ' seconds old')

                            if bw == 'black':
                                read_list(id, file, rblacklist, cblacklist, blacklist)
                            else:
                                if not disablewhitelist:
                                    read_list(id, file, rwhitelist, cwhitelist, whitelist)
                        else:
                            log_info(tag + 'Skipping ' + bw + 'list \"' + id + '\", using savelist')
                    else:
                        log_err(tag + 'Not enough arguments: \"' + entry + '\"')

    except IOError:
        log_err(tag + 'Unable to open file ' + lists)

    # Redirect entry, we don't want to expose it
    blacklist[intercept_host.strip('.')] = True

    # Optimize/Aggregate domain lists (remove sub-domains is parent exists and entries matchin regex)
    if readblack:
        optimize_domlist(whitelist, 'white', 'WhiteDoms')
        unreg_list(whitelist, rwhitelist, 'WhiteDoms')
    if readwhite:
        optimize_domlist(blacklist, 'black', 'BlackDoms')
        unreg_list(blacklist, rblacklist, 'BlackDoms')

    if readblack or readwhite:
        # Remove whitelisted entries from blaclist
        uncomplicate_list(whitelist, blacklist)

        # Save processed list for distribution
        write_out(whitesave, blacksave)

    # Clean-up after ourselfs
    gc.collect()

    return True


# Read file/list
def read_list(id, name, regexlist, iplist, domainlist):
    if (len(name) > 0):
        try:
            with open(name, 'r') as f:
                log_info(tag + 'Reading file/list \"' + name + '\" (' + id + ')')
         
                orgregexcount = (len(regexlist)/3-1)+1
                regexcount = orgregexcount
                ipcount = 0
                domaincount = 0

                for line in f:
                    entry = line.strip()
                    if not (entry.startswith("#")) and not (len(entry) == 0):
                        if not (exclude.match(entry)):

                            if (isregex.match(entry)):
                                # It is an Regex
                                cleanregex = entry.strip('/')
                                regexlist[regexcount,0] = str(id)
                                regexlist[regexcount,1] = regex.compile(cleanregex, regex.I)
                                regexlist[regexcount,2] = cleanregex
                                regexcount += 1

                            elif (ipregex.match(entry)):
                                # It is an IP
                                if checkresponse:
                                    if entry.find('/') == -1: # Check if Single IP or CIDR already
                                        if entry.find(':') == -1:
                                            entry = entry + '/32' # Single IPv4 Address
                                        else:
                                            entry = entry + '/128' # Single IPv6 Address

                                    if entry:
                                        iplist[entry.lower()] = '\"' + entry.lower() + '\" (' + str(id) + ')'
                                        ipcount += 1

                            elif (isdomain.match(entry)):
                                    # It is a domain
                                    #domainlist[entry.strip('.').lower()] = True
                                    domainlist[entry.strip('.').lower()] = str(id)
                                    domaincount += 1
                            else:
                                log_err(tag + name + ': Invalid line \"' + entry + '\"')
                            
                        else:
                            if (debug >= 2): log_info(tag + name + ': Excluded line \"' + entry + '\"')


                if (debug >= 1): log_info(tag + 'Fetched ' + str(regexcount-orgregexcount) + ' REGEXES, ' + str(ipcount) + ' CIDRS and ' + str(domaincount) + ' DOMAINS from file/list \"' + name + '\"')

                return True

        except IOError:
            log_err(tag + 'Unable to open file ' + name)

    return False


# Decode names/strings from response message
def decode_data(rawdata, start):
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
    if blockv6 and ((rtype == 'AAAA') or rname.endswith('.ip6.arpa')):
        if (debug >= 3): log_info(tag + 'GR: HIT on IPv6 for \"' + rname + '\" (RR:' + rtype + ')')
        return False

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
            log_err(tag + 'GENERATE-RESPONSE ERROR: ' + str(rmsg.answer))
            return False

        if qstate.return_msg.qinfo:
            invalidateQueryInCache(qstate, qstate.return_msg.qinfo)

        qstate.no_cache_store = 0
        storeQueryInCache(qstate, qstate.return_msg.qinfo, qstate.return_msg.rep, 0)

        qstate.return_msg.rep.security = 2

        return redirect

    return False


# Simple string reverser, reverse string and add tic-tac-toe-grid (#) to start, and reverse/undo when already so
def reverse_hash(s):
    if s.find('#') == -1:
        s = '#' + s[::-1]
    else:
        s = s[::-1]

    return s.rstrip('#')


# Domain aggregator, removes subdomains if parent exists
def optimize_domlist(name, bw, listname):
    log_info(tag + 'Unduplicating/Optimizing \"' + listname + '\"')

    # Get all keys (=domains) into a sorted/uniqued list
    domlist = sorted(map(reverse_hash, name.keys()))

    # Remove all subdomains
    parent = None
    undupped = set()
    for domain in domlist:
        if not parent or not domain.startswith(parent):
            undupped.add(domain)
            parent = domain + '.'
        else:
            if (debug >= 3): log_info(tag + '\"' + listname + '\": Removed domain \"' + reverse_hash(domain) + '\" redundant by parent \"' + reverse_hash(parent).strip('.') + '\"')

    undupped = map(reverse_hash, undupped)

    # New/Work dictionary
    new = dict()

    # Build new dictionary preserving id/category
    for domain in undupped:
        new[domain] = name[domain]

    # Some counting/stats
    before = len(name)
    name = new
    after = len(name)
    count = after - before

    if (debug >= 2): log_info(tag + '\"' + listname + '\": Number of domains went from ' + str(before) + ' to ' + str(after) + ' (' + str(count) + ')')

    if (count > 0):
        return True

    return False


# Uncomplicate lists, removed whitelisted blacklist entries
# !!! NEEDS WORK, TOO SLOW !!!
# !!! Also not really necesarry as already taken care of by logic in the procedures !!!
# !!! Just memory saver and potential speed up as lists are smaller !!!
def uncomplicate_list(wlist, blist):
    log_info(tag + 'Uncomplicating black/whitelists')

    listw = set(map(reverse_hash, wlist.keys()))
    listb = set(map(reverse_hash, blist.keys()))

    # Remove all 1-to-1/same whitelisted entries from blacklist
    # !!! We need logging on this !!!
    listb = listb.difference(listw)

    # Create checklist for speed
    checklistb = ''.join(listb)

    # loop through whitelist entries and find parented entries in blacklist to remove
    for domain in listw:
        child = domain + '.'
        if child in checklistb:
            for found in filter(lambda x: x.startswith(child), listb):
                if (debug >= 3): log_info(tag + 'Removed blacklist-entry \"' + reverse_hash(found) + '\" due to whitelisted parent \"' + reverse_hash(domain) + '\"')
                listb.remove(found)

            checklistb = ''.join(listb)
                
    listb = sorted(map(reverse_hash, listb))

    # Remove blacklisted entries when matched against whitelist regex
    for i in range(0,len(rwhitelist)/3):
        checkregex = rwhitelist[i,1]
        if (debug >= 2): log_info(tag + 'Checking against white-regex \"' + rwhitelist[i,2] + '\"')
        for found in filter(checkregex.search, listb):
            listb.remove(found)
            if (debug >= 3): log_info(tag + 'Removed \"' + found + '\" from blacklist, matched by white-regex \"' + rwhitelist[i,2] + '\"')

    # New/Work dictionary
    new = dict()

    # Build new dictionary preserving id/category
    for domain in listb:
        new[domain] = blist[domain]

    before = len(blist)
    blist = new
    after = len(blist)
    count = after - before

    if (debug >= 2): log_info(tag + 'Number of blocklisted domains went from ' + str(before) + ' to ' + str(after) + ' (' + str(count) + ')')
    return True


# Remove entries from domains already matchin regex
def unreg_list(dlist, rlist, listname):
    log_info(tag + 'Unregging \"' + listname + '\"')

    count = 0
    for i in range(0,len(rlist)/3):
        checkregex = rlist[i,1]
        if (debug >= 2): log_info(tag + 'Checking against \"' + rlist[i,2] + '\"')
	for found in filter(checkregex.search, dlist):
            count += 1
            name = dlist.pop(found, None)
            if (debug >= 3): log_info(tag + 'Removed \"' + found + '\" from \"' + name + '\", already matched by regex \"' + rlist[i,2] + '\"')

    if (debug >= 2): log_info(tag + 'Removed ' + str(count) + ' entries from \"' + listname + '\"')
    return True


# Save lists
# !!!! NEEDS WORK AND SIMPLIFIED !!!!
def write_out(whitefile, blackfile):
    if not savelists:
        return False

    log_info(tag + 'Saving processed lists to \"' + whitefile + '\" and \"' + blackfile + '\"')
    try:
        with open(whitefile, 'w') as f:
            f.write('### WHITELIST REGEXES ###\n')
            for line in range(0,len(rwhitelist)/3):
                f.write('/' + rwhitelist[line,2] + '/')
                f.write('\n')

            f.write('### WHITELIST DOMAINS ###\n')
            for line in sorted(whitelist.keys()):
                f.write(line)
                f.write('\n')

            f.write('### WHITELIST CIDRs ###\n')
            for a in cwhitelist.keys():
                f.write(a)
                f.write('\n')

            f.write('### WHITELIST EOF ###\n')

    except IOError:
        log_err(tag + 'Unable to write to file \"' + whitefile + '\"')

    try:
        with open(blackfile, 'w') as f:
            f.write('### BLACKLIST REGEXES ###\n')
            for line in range(0,len(rblacklist)/3):
                f.write('/' + rblacklist[line,2] + '/')
                f.write('\n')

            f.write('### BLACKLIST DOMAINS ###\n')
            for line in sorted(blacklist.keys()):
                f.write(line)
                f.write('\n')

            f.write('### BLACKLIST CIDRs ###\n')
            for a in cblacklist.keys():
                f.write(a)
                f.write('\n')

            f.write('### BLACKLIST EOF ###\n')

    except IOError:
        log_err(tag + 'Unable to write to file \"' + blackfile + '\"')

    return True

# Check if file exists and return age if so
def file_exist(file):
    if os.path.isfile(file):
        fstat = os.stat(file)
        fsize = fstat.st_size
        if fsize > 0:
            fexists = True
            mtime = int(fstat.st_mtime)
            currenttime = int(datetime.datetime.now().strftime("%s"))
            age = int(currenttime - mtime)
            return age

    return False


# Initialization
def init(id, cfg):
    log_info(tag + 'Initializing')

    # Read Lists
    load_lists(False)

    if len(intercept_address) == 0:
        if (debug >= 1): log_info(tag + 'Using REFUSED for matched queries/responses')
    else:
        if (debug >= 1): log_info(tag + 'Using REDIRECT to \"' + intercept_address + '\" for matched queries/responses')

    if blockv6:
        if (debug >= 1): log_info(tag + 'Blocking IPv6-Based queries')

    log_info(tag + 'READY FOR SERVICE')
    return True


# Get DNS client IP
def client_ip(qstate):
    reply_list = qstate.mesh_info.reply_list

    while reply_list:
        if reply_list.query_reply:
            return reply_list.query_reply.addr
        reply_list = reply_list.next

    return "0.0.0.0"


# Commands to execute based on commandtld query
def execute_command(qstate):
    global filtering
    global command_in_progress
    global debug

    tag = 'DNS-FIREWALL COMMAND: '

    if command_in_progress:
        log_info(tag + 'ALREADY PROCESSING COMMAND')
        return True

    command_in_progress = True

    qname = qstate.qinfo.qname_str.rstrip('.').lower().replace(commandtld,'',1)
    rc = False
    if qname:
        if qname == 'reload':
            rc = True
            log_info(tag + 'Reloading lists')
            load_lists(False)
        elif qname == 'force.reload':
            rc = True
            log_info(tag + 'FORCE Reloading lists')
            load_lists(True)
        elif qname == 'pause':
            rc = True
            if filtering:
                log_info(tag + 'Filtering PAUSED')
                filtering = False
            else:
                log_info(tag + 'Filtering already PAUSED')
        elif qname == 'resume':
            rc = True
            if not filtering:
                log_info(tag + 'Filtering RESUMED')
                clear_cache()
                filtering = True
            else:
                log_info(tag + 'Filtering already RESUMED or Active')
        elif qname == 'save.cache':
            rc = True
            save_cache()
        elif qname == 'save.list':
            rc = True
            write_out(whitesave, blacksave)
        elif qname.endswith('.debug'):
            rc = True
            debug = int('.'.join(qname.split('.')[:-1]))
            log_info(tag + 'Set debug to \"' + str(debug) + '\"')
        elif qname.endswith('.add.whitelist'):
            rc = True
            domain = '.'.join(qname.split('.')[:-2])
            if not domain in whitelist:
                log_info(tag + 'Added \"' + domain + '\" to whitelist')
                whitelist[domain] = 'Whitelisted'
        elif qname.endswith('.add.blacklist'):
            rc = True
            domain = '.'.join(qname.split('.')[:-2])
            if not domain in blacklist:
                log_info(tag + 'Added \"' + domain + '\" to blacklist')
                blacklist[domain] = 'Blacklisted'
        elif qname.endswith('.del.whitelist'):
            rc = True
            domain = '.'.join(qname.split('.')[:-2])
            if domain in whitelist:
                log_info(tag + 'Removed \"' + domain + '\" from whitelist')
                del whitelist[domain]
                clear_cache()
        elif qname.endswith('.del.blacklist'):
            rc = True
            domain = '.'.join(qname.split('.')[:-2])
            if domain in blacklist:
                log_info(tag + 'Removed \"' + domain + '\" from blacklist')
                del blacklist[domain]
                clear_cache()

    if rc:
        log_info(tag + 'DONE')

    command_in_progress = False
    return rc


def save_cache():
    tag = 'DNS-FIREWALL CACHE: '

    log_info(tag + 'Save-ing cache')
    try:
        with open(cachefile, 'w') as f:
	    for line in sorted(blackcache.keys()):
                f.write('BLACK:' + line)
                f.write('\n')
            for line in sorted(whitecache.keys()):
                f.write('WHITE:' + line)
                f.write('\n')

    except IOError:
        log_err(tag + 'Unable to open file \"' + cachefile + '\"')

    return True


def deinit(id):
    tag = 'DNS-FIREWALL DE-INIT: '
    log_info(tag + 'Shutting down')

    if savelists:
        save_cache()

    log_info(tag + 'DONE!')
    return True


def inform_super(id, qstate, superqstate, qdata):
    tag = 'DNS-FIREWALL INFORM-SUPER: '
    log_info(tag + 'HI!')
    return True


# Main beef
def operate(id, event, qstate, qdata):
    global tag
    global tagcount

    tagcount += 1

    cip = client_ip(qstate)

    # New query or new query passed by other module
    if event == MODULE_EVENT_NEW or event == MODULE_EVENT_PASS:

	if cip == '0.0.0.0':
            qstate.ext_state[id] = MODULE_WAIT_MODULE
            return True

        tag = 'DNS-FIREWALL ' + cip + ' QUERY (#' + str(tagcount) + '): '

        # Get query name
        qname = qstate.qinfo.qname_str.rstrip('.').lower()
        if qname:
            if cip == '127.0.0.1' and (qname.endswith(commandtld)) and execute_command(qstate):
                qstate.return_rcode = RCODE_NXDOMAIN
                qstate.ext_state[id] = MODULE_FINISHED
                return True

            qtype = qstate.qinfo.qtype_str.upper()

            if (debug >= 2): log_info(tag + 'Started on \"' + qname + '\" (RR:' + qtype + ')')

            blockit = False

            # Check if whitelisted, if so, end module and DNS resolution continues as normal (no filtering)
            if blockit or not in_list(qname, 'white', 'QUERY', qtype):
                # Check if blacklisted, if so, genrate response accordingly
                if blockit or in_list(qname, 'black', 'QUERY', qtype):
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

	if cip == '0.0.0.0':
            qstate.ext_state[id] = MODULE_FINISHED
            return True

        tag = 'DNS-FIREWALL ' + cip + ' RESPONSE (#' + str(tagcount) + '): '

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
                        if (debug >= 2): log_info(tag + 'Starting on RESPONSE for QUERY \"' + qname + '\" (RR:' + qtype + ')')
                        if not in_cache('white', qname):
                            if not in_cache('black', qname):
                                # Loop through RRSets
                                for i in range(0,rep.an_numrrsets):
                                    rk = rep.rrsets[i].rk
                                    type = rk.type_str.upper()
                                    dname = rk.dname_str.rstrip('.').lower()

                                    # Start checking if black/whitelisted
                                    if dname:
                                        if not in_list(dname, 'white', 'RESPONSE', type):
                                            if not in_list(dname, 'black', 'RESPONSE', type):
        
                                                # Not listed yet, lets get data
                                                data = rep.rrsets[i].entry.data

                                                # Loop through data records
                                                for j in range(0,data.count):

                                                    # get answer section
                                                    answer = data.rr_data[j]

                                                    # Check if supported ype to record-type
                                                    if type in ('A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SOA', 'SRV'):
                                                        # Fetch Address or Name based on record-Type
                                                        if type == 'A':
                                                            name = "%d.%d.%d.%d"%(ord(answer[2]),ord(answer[3]),ord(answer[4]),ord(answer[5]))
                                                        elif type == 'AAAA':
                                                            name = "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x"%(ord(answer[2]),ord(answer[3]),ord(answer[4]),ord(answer[5]),ord(answer[6]),ord(answer[7]),ord(answer[8]),ord(answer[9]),ord(answer[10]),ord(answer[11]),ord(answer[12]),ord(answer[13]),ord(answer[14]),ord(answer[15]),ord(answer[16]),ord(answer[17]))
                                                        elif type in ('CNAME', 'NS'):
                                                            name = decode_data(answer,0)
                                                        elif type == 'MX':
                                                            name = decode_data(answer,1)
                                                        elif type == 'PTR':
                                                            name = decode_data(answer,0)
                                                        elif type == 'SOA':
                                                            name = decode_data(answer,0).split(' ')[0][0].strip('.')
                                                        elif type == 'SRV':
                                                            name = decode_data(answer,5)
                                                        else:
                                                            # Not supported
                                                            name = False
    
                                                        # If we have a name, process it
                                                        if name:
                                                            if (debug >= 2): log_info(tag + 'Checking \"' + dname + '\" -> \"' + name + '\" (RR:' + type + ')')
                                                            # Not Whitelisted?
                                                            if not in_list(name, 'white', 'RESPONSE', type):
                                                                # Blacklisted?
                                                                if in_list(name, 'black', 'RESPONSE', type):
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
                                if not in_cache('black', qname):
                                    add_to_cache('black', qname)
 
                            else:
                                # Block based on query
                                rname = qname
                                lname = qname
                                rtype = qtype

                            # Add response-name to the black-cache
                            if not in_cache('black', rname):
                                add_to_cache('black', rname)

                            # Generate response based on query-name
                            target = generate_response(qstate, qname, qtype, qstate.qinfo.qtype)
                            if target:
                                if (debug >= 1): log_info(tag + 'REDIRECTED \"' + lname + '\" (RR:' + rtype + ') to ' + target)
                                qstate.return_rcode = RCODE_NOERROR
                            else:
                                if (debug >= 1): log_info(tag + 'REFUSED \"' + lname + '\" (RR:' + rtype + ')')
                                qstate.return_rcode = RCODE_REFUSED

                        if (debug >= 2): log_info(tag + 'Finished on RESPONSE for QUERY \"' + qname + '\" (RR:' + qtype + ')')

        # All done
        qstate.ext_state[id] = MODULE_FINISHED
        return True

    # Oops, non-supported event
    log_err('pythonmod: BAD Event')
    qstate.ext_state[id] = MODULE_ERROR
    return False

# <EOF>
