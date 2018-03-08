#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
=========================================================================================
 dns-firewall.py: v6.36-20180308 Copyright (C) 2018 Chris Buijs <cbuijs@chrisbuijs.com>
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

Note: The whitelist has precedence over blacklist (see 'disablewhitelist' below).

The whitelist and blacklist domain matching is done with every requested domain
and includes it subdomains.

The regex versions will match whatever is defined. It will match sequentially
and stops processing after the first hit.

Caching: this module will cache all black or whitelisted results after processinging to speed
things up, see caching parameters below.

Install and configure:

- Make sure all modules used are availble (check 'from" and 'import" statements above).
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

- !!! Better Documentation / Remarks / Comments
- !!! Simplification of IPv4/IPv6 lists and get rid of consolidated list

=========================================================================================
'''

# Modules

# Make sure modules can be found
import sys
sys.path.append("/usr/local/lib/python2.7/dist-packages/")

# Standard/Included modules
import os, os.path, commands, datetime, gc
from thread import start_new_thread

# DNS Resolver (SafeDNS)
#import dns.resolver

# Enable Garbage collection
gc.enable()

# Use requests module for downloading lists
import requests

# Use module regex instead of re, much faster less bugs
import regex

# Use module pytricia to find ip's in CIDR's dicts fast
import pytricia

# Use expiringdictionary for cache
from expiringdict import ExpiringDict

##########################################################################################

# Variables/Dictionaries/Etc ...

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
cblacklist = pytricia.PyTricia(128) # IPv4/IPv6 blacklist
cwhitelist = pytricia.PyTricia(128) # IPv4/IPv6 whitelist
cblacklist4 = pytricia.PyTricia(32) # IPv4 blacklist
cwhitelist4 = pytricia.PyTricia(32) # IPv4 whitelist
cblacklist6 = pytricia.PyTricia(128) # IPv6 blacklist
cwhitelist6 = pytricia.PyTricia(128) # IPv6 whitelist
rblacklist = dict() # Regex blacklist (maybe replace with set()?)
rwhitelist = dict() # Regex whitelist (maybe replace with set()?)
excludelist = dict() # Domain excludelist

# Cache
cachesize = 5000
cachettl = 1800
blackcache = ExpiringDict(max_len=cachesize, max_age_seconds=cachettl)
whitecache = ExpiringDict(max_len=cachesize, max_age_seconds=cachettl)
cachefile = '/etc/unbound/cache.file'

# Save
savelists = True
blacksave = '/etc/unbound/blacklist.save'
whitesave = '/etc/unbound/whitelist.save'

# TLD file
#tldfile = False
tldfile = '/etc/unbound/tlds.list'
tldlist = dict()

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
# dig @127.0.0.1 update.commandtld - Update/Reload lists
# dig @127.0.0.1 force.update.commandtld - Force Update/Reload lists
# dig @127.0.0.1 force.reload.commandtld - Force fetching/processing of lists and reload
# dig @127.0.0.1 pause.commandtld - Pause filtering (everything passthru)
# dig @127.0.0.1 resume.commandtld - Resume filtering
# dig @127.0.0.1 maintenance.commandtld - Run maintenance
# dig @127.0.0.1 <domain>.add.whitelist.commandtld - Add <Domain> to blacklist
# dig @127.0.0.1 <domain>.add.blacklist.commandtld - Add <Domain> to blacklist
# dig @127.0.0.1 <domain>.del.whitelist.commandtld - Remove <Domain> from whitelist
# dig @127.0.0.1 <domain>.del.blacklist.commandtld - Remove <Domain> from blacklist
commandtld = '.command'

# Check answers/responses as well
checkresponse = True

# Maintenance after x queries
maintenance = 100000

# Automatic generated reverse entries for IP-Addresses that are listed
autoreverse = True

# Block IPv6 queries/responses
blockv6 = True

# CNAME Collapsing (note: whitelisted entries are not collapsed)
collapse = True

# Allow RFC 2606 TLD's
rfc2606 = False

# Allow common intranet TLD's
intranet = False

# Default maximum age of downloaded lists, can be overruled in lists file
maxlistage = 43200 # In seconds

# Debugging, Levels: 0=Minimal, 1=Default, show blocking, 2=Show all info/processing, 3=Flat out all
# The higher levels include the lower level informations
debug = 2

# Regex to match IPv4/IPv6 Addresses/Subnets (CIDR)
ipregex = regex.compile('^(([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})*|([0-9a-f]{1,4}|:)(:([0-9a-f]{0,4})){1,7}(/[0-9]{1,3})*)$', regex.I)
#ip4regex = regex.compile('^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[1-2][0-9]|3[0-2]))*$', regex.I)

# Regex to match regex-entries in lists
isregex = regex.compile('^/.*/$')

# Regex to match domains/hosts in lists
#isdomain = regex.compile('^[a-z0-9\.\-]+$', regex.I) # According RFC, Internet only
isdomain = regex.compile('^[a-z0-9_\.\-]+$', regex.I) # According RFC plus underscore, works everywhere

# Regex for excluded entries to fix issues
#exclude = regex.compile('^(((0{1,3}\.){3}0{1,3}|(0{1,4}|:)(:(0{0,4})){1,7})/[0-8]|fastly.net|google\.com|googlevideo\.com|site)$', regex.I) # Bug in PyTricia '::/0' matching IPv4 as well
#exclude = regex.compile('^(fastly.net|googl(e|eapi[s]*|evideo)\.com|site)$', regex.I)
exclude = regex.compile('^(127\.0\.0\.1|::1|localhost)$', regex.I)

# Regex for www entries
wwwregex = regex.compile('^(https*|ftps*|www+)[0-9]*\..*\..*$', regex.I)

# SafeDNS - HIGHLY EXPERIMENTAL AND WILL BREAK STUFF, USE AT OWN RISK !!!
#safedns = False
#safednsblock = False # When False, only monitoring/reporting
#safescore = 33 # Percentage, if score is below we block
#nameservers = dict()
#nameserverslist = '/etc/unbound/safenameservers'

##########################################################################################

# Check against lists
def in_list(name, bw, type, rrtype='ALL'):
    tag = 'DNS-FIREWALL FILTER: '
    if not filtering:
        if (debug >= 2): log_info(tag + 'Filtering disabled, passthru \"' + name + '\" (RR:' + rrtype + ')')
        return False

    if (bw == 'white') and disablewhitelist:
        return False

    if blockv6 and ((rrtype == 'AAAA') or name.endswith('.ip6.arpa')):
        if (bw == 'black'):
             if (debug >= 2): log_info(tag + 'HIT on IPv6 for \"' + name + '\" (RR:' + rrtype + ')')
             #add_to_cache(bw, name) # Do not cache, will block non-v6 queries if cached
             return True

    if not in_cache('white', name):
        if not in_cache('black', name):
            # Check for IP's
            if (type == 'RESPONSE') and rrtype in ('A', 'AAAA'):
                cidr = check_ip(name, bw)
                if cidr:
                    if (debug >= 2): log_info(tag + 'HIT on IP \"' + name + '\" in ' + bw + '-listed network ' + cidr)
                    add_to_cache(bw, name)
                    return True
                else:
                    return False

            else:
                # Check against tlds
                if (bw == 'black') and tldlist:
                    tld = name.split('.')[-1:][0]
                    if not tld in tldlist:
                        if (debug >= 2): log_info(tag + 'HIT on non-existant TLD \"' + tld + '\" for \"' + name + '\"')
                        add_to_cache(bw, name)
                        return True

                # Check against domains
                testname = name
                while True:
                    if (bw == 'black'):
                         found = (testname in blacklist)
                         if found:
                              id = blacklist[testname]
                         elif testname != name:
                             found = (testname in blackcache)
                             if found:
                                 id = 'CACHE'

                    else:
                         found = (testname in whitelist)
                         if found:
                             id = whitelist[testname]
                         elif testname != name:
                             found = (testname in whitecache)
                             if found:
                                 id = 'CACHE'
                          
                    if found:
                        if (debug >= 2): log_info(tag + 'HIT on DOMAIN \"' + name + '\", matched against ' + bw + '-list-entry \"' + testname + '\" (' + str(id) + ')')
                        add_to_cache(bw, name)

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
            if (bw == 'black'):
                return True

    else:
        if (bw == 'white'):
            return True

    return False


# Check if entry is in cache
def in_cache(bw, name):
    tag = 'DNS-FIREWALL FILTER: '
    if (bw == 'black'):
        if name in blackcache:
            if (debug >= 2): log_info(tag + 'Found \"' + name + '\" in black-cache')
            return True
    else:
        if name in whitecache:
            if (debug >= 2): log_info(tag + 'Found \"' + name + '\" in white-cache')
            return True

    return False


# Add matched entry to cache
def add_to_cache(bw, name):
    tag = 'DNS-FIREWALL FILTER: '

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
        if ip.find(':') == -1:
            if ip in cblacklist4:
                return cblacklist4[ip]
        else:
            if ip in cblacklist6:
                return cblacklist6[ip]
    else:
        if ip.find(':') == -1:
            if ip in cwhitelist4:
                return cwhitelist4[ip]
        else:
            if ip in cwhitelist6:
                return cwhitelist6[ip]

    return False


# Check against REGEX lists (called from in_list)
def check_regex(name, bw):
    tag = 'DNS-FIREWALL FILTER: '
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

    global blacklist
    global whitelist
    global rblacklist
    global rwhitelist
    global cblacklist
    global cwhitelist
    global cblacklist4
    global cwhitelist4
    global cblacklist6
    global cwhitelist6
    global excludelist

    log_info(tag + 'Clearing Lists')

    rwhitelist.clear()
    whitelist.clear()
    excludelist.clear()
    for i in cwhitelist.keys():
        cwhitelist.delete(i)

    rblacklist.clear()
    blacklist.clear()
    for i in cblacklist.keys():
        cblacklist.delete(i)

    cwhitelist4, cwhitelist6 = aggregate_ip(cwhitelist, 'WhiteIPs', True)
    cblacklist4, cblacklist6 = aggregate_ip(cblacklist, 'BlackIPs', True)


    clear_cache()

    return True


# Clear cache
def clear_cache():
    tag = 'DNS-FIREWALL CACHE: '

    log_info(tag + 'Clearing Cache')
    blackcache.clear()
    whitecache.clear()

    return True


# Maintenance lists, check expiry, reload, etc...
def maintenance_lists(count):
    tag = 'DNS-FIREWALL MAINTENACE: '

    global command_in_progress

    if command_in_progress:
        log_info(tag + 'ALREADY PROCESSING')
        return True

    command_in_progress = True

    log_info(tag + 'Maintenance Started')

    age = file_exist(whitesave)
    if age and age < maxlistage:
        age = file_exist(blacksave)
        if age and age < maxlistage:
            log_info(tag + 'Nothing to do. Done')
            command_in_progress = False
            return False

    log_info(tag + 'Updating Lists')

    load_lists(False, True)

    log_info(tag + 'Maintenance Done')

    command_in_progress = False

    return True


# Load lists
def load_lists(force, savelists):
    tag = 'DNS-FIREWALL LISTS: '

    global blacklist
    global whitelist
    global rblacklist
    global rwhitelist
    global cblacklist
    global cwhitelist
    global cblacklist4
    global cwhitelist4
    global cblacklist6
    global cwhitelist6
    global tldfile
    global excludelist
    global exclude
    
    # Header/User-Agent to use when downloading lists, some sites block non-browser downloads
    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36'
        }

    # clear lists if already filled
    if (len(blacklist) > 0) or (len(whitelist) > 0):
        clear_lists()

    # Get top-level-domains
    if tldfile:
        tldlist.clear()
        age = file_exist(tldfile)
	if not age or age > maxlistage:
            log_info(tag + 'Downloading IANA TLD list to \"' + tldfile + '\"')
            r = requests.get('https://data.iana.org/TLD/tlds-alpha-by-domain.txt', headers=headers, allow_redirects=True)
            if r.status_code == 200:
                try:
                    with open(tldfile, 'w') as f:
                        f.write(r.text.encode('ascii', 'ignore').replace('\r', '').lower())

                except IOError:
                    log_err(tag + 'Unable to write to file \"' + tldfile + '\"')
                    tldfile = False

        if tldfile:
            log_info(tag + 'Fetching TLD list from \"' + tldfile + '\"')
            try:
                with open(tldfile, 'r') as f:
                    for line in f:
                        entry = line.strip()
                        if not (entry.startswith("#")) and not (len(entry) == 0):
                            tldlist[entry] = True

            except IOError:
                log_err(tag + 'Unable to read from file \"' + tldfile + '\"')
                tldfile = False

            if tldfile:
                if rfc2606:
                    tldlist['example'] = True
                    tldlist['invalid'] = True
                    tldlist['localhost'] = True
                    tldlist['test'] = True

                if intranet:
                    tldlist['corp'] = True
                    tldlist['home'] = True
                    tldlist['host'] = True
                    tldlist['lan'] = True
                    tldlist['local'] = True
                    tldlist['localdomain'] = True
                    tldlist['router'] = True
                    tldlist['workgroup'] = True

            log_info(tag + 'fetched ' + str(len(tldlist)) +  ' TLDs')


    #    if intercept_host:
    #        tldlist[intercept_host.strip('.').split('.')[-1:][0]] = True

    # Read Lists
    readblack = True
    readwhite = True
    if savelists and not force:
        age = file_exist(whitesave)
        if age and age < maxlistage and not disablewhitelist:
            log_info(tag + 'Using White-Savelist, not expired yet (' + str(age) + '/' + str(maxlistage) + ')')
            read_lists('saved-whitelist', whitesave, rwhitelist, cwhitelist, whitelist, True, 'white')
            readwhite = False

        age = file_exist(blacksave)
        if age and age < maxlistage:
            log_info(tag + 'Using Black-Savelist, not expired yet (' + str(age) + '/' + str(maxlistage) + ')')
            read_lists('saved-blacklist', blacksave, rblacklist, cblacklist, blacklist, True, 'black')
            readblack = False

    try:
        with open(lists, 'r') as f:
            for line in f:
                entry = line.strip().replace('\r', '')
                if not (entry.startswith("#")) and not (len(entry) == 0):
                    element = entry.split('\t')
                    if len(element) > 2:
                        id = element[0]
                        bw = element[1].lower()
                        if (bw == 'black' and readblack) or (bw == 'white' and readwhite) or (bw == 'exclude' and (readwhite or readblack)):
                            file = element[2]
                            force = False
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
    
                                fregex = '^(?P<entry>[a-zA-Z0-9\.\-\_]+)$'
                                if len(element) > 5:
                                    r = element[5]
                                    if r.find('(?P<entry>') == -1:
                                        log_err(tag + 'Regex \"' + r + '\" does not contain group-name \"entry\" (e.g: \"(?P<entry ... )\")')
                                    else:
                                        fregex = r

                                if len(element) > 6:
                                    exclude = regex.compile(element[6], regex.I)
                                else:
                                    exclude = regex.compile('^(127\.0\.0\.1|::1|localhost)$', regex.I)
    
                                fexists = False
    
                                age = file_exist(file)
                                if not age or age > filettl or force:
                                    log_info(tag + 'Downloading \"' + id + '\" from \"' + url + '\" to \"' + file + '\"')
                                    r = requests.get(url, headers=headers, allow_redirects=True)
                                    if r.status_code == 200:
                                        try:
                                            with open(file + '.download', 'w') as f:
                                                f.write(r.text.encode('ascii', 'ignore').replace('\r', ''))

                                            try:
                                                with open(file + '.download', 'r') as f:
                                                    try:
                                                        with open(file, 'w') as g:
                                                            seen = set()
                                                            for line in f:
                                                                matchentry = regex.match(fregex, line)
                                                                if matchentry:
                                                                    entry = matchentry.group('entry').lower()
                                                                    if entry and not entry in seen:
                                                                        g.write(entry)
                                                                        g.write('\n')
                                                                        seen.add(entry)

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
                            else:
                                force = True # Always load when file on disk

                            if bw == 'black':
                                read_lists(id, file, rblacklist, cblacklist, blacklist, force, bw)
                            elif bw == 'white':
                                if not disablewhitelist:
                                    read_lists(id, file, rwhitelist, cwhitelist, whitelist, force, bw)
                            elif bw == 'exclude':
                                excount = 0
                                try:
                                    with open(file, 'r') as f:
                                        for line in f:
                                            entry = line.strip().replace('\r', '')
                                            if (len(entry) > 0) and isdomain.match(entry):
                                                excludelist[entry] = id
                                                excount += 1

                                    log_info(tag + 'Fetched ' + str(excount) + ' exclude entries from \"' + file + '\" (' + id + ')')

                                except IOError:
                                    log_err(tag + 'Unable to open file \"' + file + '\"')
                            else:
                                log_err(tag + 'Unknow type \"' + bw + '\" for file \"' + file + '\"')
                        else:
                            log_info(tag + 'Skipping ' + bw + 'list \"' + id + '\", using savelist')
                    else:
                        log_err(tag + 'Not enough arguments: \"' + entry + '\"')

    except IOError:
        log_err(tag + 'Unable to open file ' + lists)

    # Redirect entry, we don't want to expose it
    blacklist[intercept_host.strip('.')] = 'Intercept_Host'

    # Excluding domains
    if excludelist and readblack and readwhite:
        optimize_domlists('exclude', 'ExcludeDoms')
        blacklist = exclude_list(blacklist, 'BlackDoms')
        whitelist = exclude_list(whitelist, 'WhiteDoms')

    # Optimize/Aggregate domain lists (remove sub-domains is parent exists and entries matchin regex)
    if readblack:
        optimize_domlists('white', 'WhiteDoms')
        unreg_lists('white', 'WhiteDoms')

    if readwhite:
        optimize_domlists('black', 'BlackDoms')
        unreg_lists('black', 'BlackDoms')

    if readblack or readwhite:
        # Remove whitelisted entries from blacklist
        uncomplicate_lists()

    cwhitelist4, cwhitelist6 = aggregate_ip(cwhitelist, 'WhiteIPs', readwhite)
    cblacklist4, cblacklist6 = aggregate_ip(cblacklist, 'BlackIPs', readblack)

    regexcount = str(len(rblacklist)/3)
    ipcount = str (len(cblacklist))
    domaincount = str(len(blacklist))
    log_info(tag + 'BlackList Totals: ' + regexcount + ' REGEXES, ' + ipcount + ' IPs/CIDRs and ' + domaincount + ' DOMAINS')

    regexcount = str(len(rwhitelist)/3)
    ipcount = str (len(cwhitelist))
    domaincount = str(len(whitelist))
    log_info(tag + 'WhiteList Totals: ' + regexcount + ' REGEXES, ' + ipcount + ' IPs/CIDRs and ' + domaincount + ' DOMAINS')

    # Save processed list for distribution
    write_out(whitesave, blacksave)

    # Clean-up after ourselfs
    gc.collect()

    return True


# Read file/list
def read_lists(id, name, regexlist, iplist, domainlist, force, bw):
    tag = 'DNS-FIREWALL LISTS: '

    orgid = id

    if (len(name) > 0):
        try:
            with open(name, 'r') as f:
                log_info(tag + 'Reading ' + bw + '-file/list \"' + name + '\" (' + id + ')')
         
                orgregexcount = (len(regexlist)/3-1)+1
                regexcount = orgregexcount
                ipcount = 0
                domaincount = 0

                for line in f:
                    entry = line.split('#')[0].strip().replace('\r', '')
                    if not (len(entry) == 0) and not (entry.startswith("#")):
                        id = orgid
                        elements = entry.split('\t')
                        if len(elements) > 1:
                            entry = elements[0]
                            if elements[1]:
                                id = elements[1]

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
                                        ip = entry.lower()
                                        if iplist.has_key(ip):
                                            if iplist[ip].find(id) == -1:
                                                oldid = iplist[ip].split('(')[1].split(')')[0].strip()
                                                iplist[ip] = '\"' + ip + '\" (' + str(oldid) + ', ' + str(id) + ')'
                                        else:
                                            try:
                                                iplist[ip] = '\"' + ip + '\" (' + str(id) + ')'
                                                ipcount += 1
                                            except:
                                                log_err(tag + name + ': Skipped invalid line/ip-address \"' + entry + '\"')
                                                pass


                            elif (isdomain.match(entry)):
                                    # It is a domain
                                    entry = entry.strip('.').lower()
    
                                    # Strip 'www." if appropiate
                                    if wwwregex.match(entry):
                                        label = entry.split('.')[0]
                                        if (debug >= 3): log_info(tag + 'Stripped \"' + label + '\" from \"' + entry + '\"')
                                        entry = '.'.join(entry.split('.')[1:])

                                    if entry:
                                        if tldlist and not force:
                                            tld = entry.split('.')[-1:][0]
                                            if not tld in tldlist:
                                                if (debug >= 2): log_info(tag + 'Skipped DOMAIN \"' + entry + '\", TLD (' + tld + ') does not exist')
                                                entry = False
                                                
                                        if entry:
                                            if entry in domainlist:
                                                if domainlist[entry].find(id) == -1:
                                                    domainlist[entry] = domainlist[entry] + ', ' + id
                                            else:
                                                domainlist[entry] = id
                                                domaincount += 1


                            else:
                                log_err(tag + name + ': Skipped invalid line \"' + entry + '\"')

                        else:
                            if (debug >= 1): log_info(tag + name + ': Skipped/Excluded line \"' + entry + '\"')


                if (debug >= 1): log_info(tag + 'Fetched ' + str(regexcount-orgregexcount) + ' REGEXES, ' + str(ipcount) + ' CIDRS and ' + str(domaincount) + ' DOMAINS from ' + bw + '-file/list \"' + name + '\"')
                if (debug >= 2): log_info(tag + 'Total ' + str(len(regexlist)/3) + ' REGEXES, ' + str(len(iplist)) + ' CIDRS and ' + str(len(domainlist)) + ' DOMAINS in ' + bw + '-list')

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
                serial = datetime.datetime.now().strftime('%Y%m%d%H')
                fname = intercept_host + ' hostmaster.' + intercept_host + ' ' + serial + ' 86400 7200 3600000 ' + str(cachettl)
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
            redirect = '\"Domain \'' + rname + '\' blocked by DNS-Firewall\"'
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


# Domain aggregator, removes subdomains if parent exists
def optimize_domlists(bw, listname):
    tag = 'DNS-FIREWALL LISTS: '

    global blacklist
    global whitelist
    global excludelist

    log_info(tag + 'Unduplicating/Optimizing \"' + listname + '\"')

    # Get all keys (=domains) into a sorted/uniqued list
    if (bw == 'black'):
	name = blacklist
    elif (bw == 'white'):
        name = whitelist
    elif (bw == 'exclude'):
        name = excludelist

    domlist = dom_sort(name.keys())

    # Remove all subdomains
    parent = False
    undupped = set()
    for domain in domlist:
        if not parent or not domain.endswith(parent):
            undupped.add(domain)
            parent = '.' + domain.lstrip('.')
        else:
            if (debug >= 3): log_info(tag + '\"' + listname + '\": Removed domain \"' + domain + '\" redundant by parent \"' + parent.strip('.') + '\"')

    # New/Work dictionary
    new = dict()

    # Build new dictionary preserving id/category
    for domain in undupped:
        new[domain] = name[domain]

    # Some counting/stats
    before = len(name)
    after = len(new)
    count = after - before

    if (bw == 'black'):
        blacklist = new
    elif (bw == 'white'):
        whitelist = new
    elif (bw == 'exclude'):
        excludelist = new

    if (debug >= 2): log_info(tag + '\"' + listname + '\": Number of domains went from ' + str(before) + ' to ' + str(after) + ' (' + str(count) + ')')

    if (count > 0):
        return True

    return False


# Uncomplicate lists, removed whitelisted domains from blacklist
def uncomplicate_lists():
    tag = 'DNS-FIREWALL LISTS: '

    global blacklist
    global whitelist
    global rwhitelist

    log_info(tag + 'Uncomplicating Domain black/whitelists')

    listw = dom_sort(whitelist.keys())
    listb = dom_sort(blacklist.keys())

    # Remove all 1-to-1/same whitelisted entries from blacklist
    # !!! We need logging on this !!!
    listb = dom_sort(list(set(listb).difference(listw)))

    # Create checklist for speed
    checklistb = '#'.join(listb) + '#'

    # loop through whitelist entries and find parented entries in blacklist to remove
    for domain in listw:
        if '.' + domain + '#' in checklistb:
            if (debug >= 3): log_info(tag + 'Checking against \"' + domain + '\"')
            for found in filter(lambda x: x.endswith('.' + domain), listb):
                if (debug >= 3): log_info(tag + 'Removed blacklist-entry \"' + found + '\" due to whitelisted parent \"' + domain + '\"')
                listb.remove(found)

            checklistb = '#'.join(listb) + "#"
        #else:
        #    # Nothing to whitelist (breaks stuff, do not uncomment)
        #    if (debug >= 2): log_info(tag + 'Removed whitelist-entry \"' + domain + '\", no blacklist hit')
        #    del whitelist[domain]

    # Remove blacklisted entries when matched against whitelist regex
    for i in range(0,len(rwhitelist)/3):
        checkregex = rwhitelist[i,1]
        if (debug >= 3): log_info(tag + 'Checking against white-regex \"' + rwhitelist[i,2] + '\"')
        for found in filter(checkregex.search, listb):
            listb.remove(found)
            if (debug >= 3): log_info(tag + 'Removed \"' + found + '\" from blacklist, matched by white-regex \"' + rwhitelist[i,2] + '\"')

    # New/Work dictionary
    new = dict()

    # Build new dictionary preserving id/category
    for domain in listb:
        new[domain] = blacklist[domain]

    before = len(blacklist)
    after = len(new)
    count = after - before

    blacklist = new

    if (debug >= 2): log_info(tag + 'Number of blacklisted domains went from ' + str(before) + ' to ' + str(after) + ' (' + str(count) + ')')

    uncomplicate_ip_lists()

    return True


# Remove excluded entries from domain-lists
def exclude_list(domlist, listname):
    global excludelist

    tag = 'DNS-FIREWALL LISTS: '

    log_info( tag + 'Excluding \"' + listname + '\"')

    newlist = domlist
    checklist = '#'.join(newlist.keys()) + '#'

    deleted = 0
    for domain in dom_sort(excludelist.keys()):
        # Just the domain
        if domain in newlist:
            lname = newlist.pop(domain, None)
            if (debug > 1): log_info(tag + 'Removed excluded entry \"' + domain + '\" from \"' + listname + '\" (' + lname + ')')
            checklist = '#'.join(newlist.keys()) + '#'
            deleted += 1

        # All domains ending in excluded domain (Breaks too much, leave commented out)
        #if '.' + domain + "#" in checklist:
        #    for found in filter(lambda x: x.endswith('.' + domain), domlist.keys()):
        #        lname = newlist.pop(found, None)
        #        if (debug > 1): log_info(tag + 'Removed excluded entry \"' + found + '\" (' + domain + ') from \"' + listname + '\" (' + lname + ')')
        #        checklist = '#'.join(newlist.keys()) + '#'
        #        deleted += 1

    before = len(domlist)
    after = before - deleted

    log_info(tag + '\"' + listname + '\" went from ' + str(before) + ' to ' + str(after) + ', after removing ' + str(deleted) + ' excluded entries')

    return newlist


# Uncomplicate IP lists, remove whitelisted IP's from blacklist
def uncomplicate_ip_lists():
    tag = 'DNS-FIREWALL LISTS: '

    global cblacklist
    global cwhitelist

    log_info(tag + 'Uncomplicating IP black/whitelists')

    listw = cwhitelist.keys()
    listb = cblacklist.keys()
    listw4, listw6 = split_46(cwhitelist)

    # Remove all 1-to-1/same whitelisted entries from blacklist
    # !!! We need logging on this !!!
    listb = dom_sort(list(set(listb).difference(listw)))

    # loop through blacklist entries and find whitelisted entries to remove
    for ip in listb:
        found = False
        if ip.find(':') == -1:
            if ip in listw4:
                found = True
        else:
            if ip in listw6:
                found = True

        if found:
            if (debug >= 3): log_info(tag + 'Removed blacklist-entry \"' + ip + '\" due to whitelisted \"' + cwhitelist[ip] + '\"')
            listb.remove(ip)

    new = pytricia.PyTricia(128)

    # Build new dictionary preserving id/category
    for ip in listb:
        new[ip] = cblacklist[ip]

    before = len(cblacklist)
    after = len(new)
    count = after - before

    cblacklist = new

    if (debug >= 2): log_info(tag + 'Number of blacklisted IPs went from ' + str(before) + ' to ' + str(after) + ' (' + str(count) + ')')

    return True


# Remove entries from domains already matching by a regex
def unreg_lists(bw, listname):
    tag = 'DNS-FIREWALL LISTS: '

    global blacklist
    global whitelist
    global rblacklist
    global rwhitelist
    global excludelist

    if (bw == 'black'):
        dlist = blacklist
        rlist = rblacklist
    else:
        dlist = whitelist
        rlist = rwhitelist

    log_info(tag + 'Unregging \"' + listname + '\"')

    before = len(dlist)

    for i in range(0,len(rlist)/3):
        checkregex = rlist[i,1]
        if (debug >= 3): log_info(tag + 'Checking against \"' + rlist[i,2] + '\"')
	for found in filter(checkregex.search, dlist):
            name = dlist.pop(found, None)
            if (debug >= 3): log_info(tag + 'Removed \"' + found + '\" from \"' + name + '\", already matched by regex \"' + rlist[i,2] + '\"')

    after = len(dlist)
    count = after - before

    if (bw == 'black'):
        blacklist = dlist
    else:
        whitelist = dlist

    if (debug >= 2): log_info(tag + 'Number of \"' + listname + '\" entries went from ' + str(before) + ' to ' + str(after) + ' (' + str(count) + ')')
    return True


# Save lists to files
# !!!! NEEDS WORK AND SIMPLIFIED !!!!
def write_out(whitefile, blackfile):
    tag = 'DNS-FIREWALL LISTS: '

    if not savelists:
        return False

    log_info(tag + 'Saving processed lists to \"' + whitefile + '\" and \"' + blackfile + '\"')
    try:
        with open(whitefile, 'w') as f:
            f.write('### WHITELIST REGEXES ###\n')
            for line in range(0,len(rwhitelist)/3):
                f.write('/' + rwhitelist[line,2] + '/\t' + rwhitelist[line,0])
                f.write('\n')

            f.write('### WHITELIST DOMAINS ###\n')
            for line in dom_sort(whitelist.keys()):
                f.write(line + '\t' + whitelist[line])
                f.write('\n')

            list4, list6 = split_46(cwhitelist)
            f.write('### WHITELIST IPv4 ###\n')
            for a in list4.keys():
                f.write(a + '\t' + list4[a].split('(')[1].split(')')[0].strip())
                f.write('\n')

            f.write('### WHITELIST IPv6 ###\n')
            for a in list6.keys():
                f.write(a + '\t' + list6[a].split('(')[1].split(')')[0].strip())
                f.write('\n')

            f.write('### WHITELIST EOF ###\n')

    except IOError:
        log_err(tag + 'Unable to write to file \"' + whitefile + '\"')

    try:
        with open(blackfile, 'w') as f:
            f.write('### BLACKLIST REGEXES ###\n')
            for line in range(0,len(rblacklist)/3):
                f.write('/' + rblacklist[line,2] + '/\t' + rblacklist[line,0])
                f.write('\n')

            f.write('### BLACKLIST DOMAINS ###\n')
            for line in dom_sort(blacklist.keys()):
                f.write(line + '\t' + blacklist[line])
                f.write('\n')

            list4, list6 = split_46(cblacklist)
            f.write('### BLACKLIST IPv4 ###\n')
            for a in list4.keys():
                f.write(a + '\t' + list4[a].split('(')[1].split(')')[0].strip())
                f.write('\n')

            f.write('### BLACKLIST IPv6 ###\n')
            for a in list6.keys():
                f.write(a + '\t' + list6[a].split('(')[1].split(')')[0].strip())
                f.write('\n')

            f.write('### BLACKLIST EOF ###\n')

    except IOError:
        log_err(tag + 'Unable to write to file \"' + blackfile + '\"')

    return True


# Domain sort
def dom_sort(domlist):
    newdomlist = list()
    for y in sorted([x.split('.')[::-1] for x in domlist]):
        newdomlist.append('.'.join(y[::-1]))

    return newdomlist


# Split IPv4/IPv6 list
def split_46(iplist):
    iplist4 = pytricia.PyTricia(32)
    iplist6 = pytricia.PyTricia(128)

    for ip in iplist.keys():
        if ip.find(':') == -1:
            iplist4[ip] = iplist[ip]
        else:
            iplist6[ip] = iplist[ip]

    return iplist4, iplist6


# Aggregate IP list
def aggregate_ip(iplist, listname, aggregate):
    tag = 'DNS-FIREWALL LISTS: '

    log_info(tag + 'Aggregating \"' + listname + '\"')

    newlist = iplist
    iplist4, iplist6 = split_46(iplist)

    if aggregate:
        for ip in iplist.keys():
            bitmask = ip.split('/')[1]
            if (bitmask != '32') and (bitmask != '128'):
                try:
                    if ip.find(':') == -1:
                        children = iplist4.children(ip)
                    else:
                        children = iplist6.children(ip)

                    if children:
                        for child in children:
                            del newlist[child]
                            if child.find(':') == -1:
                                del iplist4[child]
                            else:
                                del iplist6[child]

                            if (debug >= 3): log_info(tag + 'Removed ' + child + ', already covered by ' + ip)

                except Exception:
                    pass
    else:
        log_info(tag + 'Skipping aggregating \"' + listname + '\", just splitting')

    before = len(iplist)
    after = len(newlist)
    count = after - before

    iplist = newlist

    if (debug >= 2): log_info(tag + '\"' + listname + '\": Number of IP-Entries went from ' + str(before) + ' to ' + str(after) + ' (' + str(count) + ')')

    return iplist4, iplist6


# Check if file exists and return age (in seconds) if so
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
    tag = 'DNS-FIREWALL INIT: '

    global blacklist
    global whitelist
    global rblacklist
    global rwhitelist
    global cblacklist
    global cwhitelist
    global cblacklist4
    global cwhitelist4
    global cblacklist6
    global cwhitelist6
    global excludelist
#    global safedns

    log_info(tag + 'Initializing')

    # Read Lists
    load_lists(False, savelists)
    #start_new_thread(load_lists, (savelists,)) # !!! EXPERIMENTAL !!!

#    if safedns:
#        log_info(tag + 'Loading SafeDNS nameservers')
#        try:
#            with open(nameserverslist, 'r') as f:
#                for line in f:
#                    entry = line.strip().replace('\r', '')
#                    if not (entry.startswith("#")) and not (len(entry) == 0):
#                        element = entry.split('\t')
#			nameservers[element[0].upper()] = element[1].replace(' ', '')
#                        if (debug >= 1): log_info(tag + 'Fetched Nameservers for \"' + element[0] + '\" (' + element[1] + ')')
#
#        except IOError:
#            log_err(tag + 'Unable to open file \"' + nameserverlist + '\"')
#
#        if not ('DEFAULT' in nameservers):
#            safedns = False
#            log_err(tag + 'No \"DEFAULT\" nameserver, SafeDNS disabled')

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
    tag = 'DNS-FIREWALL COMMAND: '

    global filtering
    global command_in_progress
    global debug

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
            load_lists(False, savelists)
        elif qname == 'force.reload':
            rc = True
            log_info(tag + 'FORCE Reloading lists')
            load_lists(True, savelists)
        elif qname == 'update':
            rc = True
            log_info(tag + 'Updating lists')
            load_lists(False, False)
        elif qname == 'force.update':
            rc = True
            log_info(tag + 'Force updating lists')
            load_lists(True, False)
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
        elif qname == 'maintenance':
            rc = True
            maintenance_lists(True)
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
                whitelist.pop(domain, None)
                clear_cache()
        elif qname.endswith('.del.blacklist'):
            rc = True
            domain = '.'.join(qname.split('.')[:-2])
            if domain in blacklist:
                log_info(tag + 'Removed \"' + domain + '\" from blacklist')
                blacklist.pop(domain, None)
                clear_cache()

    if rc:
        log_info(tag + 'DONE')

    command_in_progress = False
    return rc


# Save cache to file
def save_cache():
    tag = 'DNS-FIREWALL CACHE: '

    log_info(tag + 'Saving cache')
    try:
        with open(cachefile, 'w') as f:
	    for line in dom_sort(blackcache.keys()):
                f.write('BLACK:' + line)
                f.write('\n')
            for line in dom_sort(whitecache.keys()):
                f.write('WHITE:' + line)
                f.write('\n')

    except IOError:
        log_err(tag + 'Unable to open file \"' + cachefile + '\"')

    return True


# Unload/Finish-up
def deinit(id):
    tag = 'DNS-FIREWALL DE-INIT: '
    log_info(tag + 'Shutting down')

    if savelists:
        save_cache()

    log_info(tag + 'DONE!')
    return True


# Sub-Query
def inform_super(id, qstate, superqstate, qdata):
    tag = 'DNS-FIREWALL INFORM-SUPER: '
    log_info(tag + 'HI!')
    return True


# Query DNS
#def query_dns(name, ns, type, qname, qtype, domain):
#    resolver = dns.resolver.Resolver(configure=False)
#    resolver.lifetime = 8
#    resolver.timeout = 2
#    resolver.nameservers = ns
#
#    if qtype == 'A':
#        answers = set()
#        if type == 'DNS':
#            response = resolver.query(qname, qtype)
#            if response:
#                for answer in response:
#                    answers.add(str(answer.address))
#
#                return sorted(answers)
#
#        elif type == 'DNSBL':
#            response = resolver.query(qname + '.' + domain, qtype)
#            if response:
#                for answer in response:
#                    if str(answer.address).startswith('127.'):
#                        return 'BLOCK'
#
#    return False
#
## Get DNS Params/Args
#def get_ns(nameservers, dns):
#    numfields = len(nameservers[dns].split(':'))
#    domain = False
#    if numfields > 1:
#        type = nameservers[dns].split(':')[0].upper()
#        ns = nameservers[dns].split(':')[1].split(',')
#        if numfields > 2:
#             domain = nameservers[dns].split(':')[2]
#    else:
#        type = 'DNS'
#        ns = nameservers[dns].split(',')
#
#    return type, ns, domain

# Main beef/process
def operate(id, event, qstate, qdata):
    tag = 'DNS-FIREWALL INIT: '

    #global tag
    global tagcount

    tagcount += 1

    if maintenance and ((tagcount) % maintenance == 0):
        start_new_thread(maintenance_lists, (True,))

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
            #if cip == '127.0.0.1' and (qname.endswith(commandtld)) and execute_command(qstate):
            if cip == '127.0.0.1' and (qname.endswith(commandtld)):
                start_new_thread(execute_command, (qstate,))

                qstate.return_rcode = RCODE_NXDOMAIN
                qstate.ext_state[id] = MODULE_FINISHED
                return True

            qtype = qstate.qinfo.qtype_str.upper()

            if (debug >= 2): log_info(tag + 'Started on \"' + qname + '\" (RR:' + qtype + ')')

            blockit = False

            # Check if whitelisted, if so, end module and DNS resolution continues as normal (no filtering)
            if not in_list(qname, 'white', 'QUERY', qtype):

                # Check if blacklisted, if so process and block
                if not in_list(qname, 'black', 'QUERY', qtype):
                    dummy = 0
#                    # Use SafeDNS to determine if a domain is bad
#                    if safedns and qtype == 'A':
#                        type, ns, domain = get_ns(nameservers, 'DEFAULT')
#                        if ns:
#                            if (debug >= 2): log_info(tag + 'SafeDNS: Checking \"' + qname + '/' + qtype + '\" against DEFAULT (' + type + ')')
#
#                            defaultresponse = query_dns('DEFAULT', ns, type, qname, qtype, domain)
#                            if defaultresponse:
#                                maxscore = len(nameservers.keys()) - 1
#                                scorecount = 0
#                                for dns in sorted(nameservers.keys()):
#                                    if not dns == 'DEFAULT':
#                                        type, ns, domain = get_ns(nameservers, dns)
#                                        if ns:
#                                            if (debug >= 2): log_info(tag + 'SafeDNS: Checking \"' + qname + '/' + qtype + '\" against ' + dns + ' (' + type + ')')
#
#                                            response = query_dns(dns, ns, type, qname, qtype, domain)
#                                            if response:
#                                                if type != 'DNS':
#                                                    if response == 'BLOCK':
#                                                        if safednsblock:
#                                                            log_info(tag + 'SafeDNS HIT: \"' + qname + '/' + qtype + '\" blocked by ' + dns + ' (' + type + ')')
#                                                            blockit = True
#                                                            break
#                                                        else:
#                                                            log_info(tag + 'SafeDNS MONITOR: \"' + qname + '/' + qtype + '\" blocked by ' + dns + ' (' + type + ')')
#
#                                                    maxscore -= 1
#
#                                                else:
#                                                    print '\nSAFEDNS DEFAULT RESPONSE:', qname, defaultresponse
#                                                    print 'SAFEDNS', dns, 'RESPONSE:', qname, response
#                                                    if response == defaultresponse:
#                                                        if (debug >= 3): log_info(tag + 'SafeDNS: ' + dns + ' same \"' + qname + '/' + qtype + '\" then DEFAULT')
#                                                        scorecount += 1
#                                                    else:
#                                                        if (debug >= 2): log_info(tag + 'SafeDNS: ' + dns + ' different \"' + qname + '/' + qtype + '\" then DEFAULT')
#                                            else:
#                                                if (debug >= 2): log_info(tag + 'SafeDNS: No response for \"' + qname + '/' + qtype + '\" using \"' + dns + '\"')
#                                                maxscore -= 1
#                                        else:
#                                            if (debug >= 2): log_info(tag + 'SafeDNS: No nameservers for \"' + dns + '\"')
#                                            maxscore -= 1
#
#
#                                if not blockit:
#                                    # Calculate score (percentage)
#                                    score = 100 * scorecount/maxscore
#                                    log_info(tag + 'SafeDNS: \"' + qname + '\" has ' + str(score) + '%% score')
#
#                                    if scorecount > 0 and maxscore > 0 and score > 0 and score < safescore:
#                                        if safednsblock:
#                                            log_info(tag + 'SafeDNS HIT: \"' + qname + '/' + qtype + '\" (Score: ' + str(score) + '%% of DEFAULT)')
#                                            blockit = True
#                                        else:
#                                            log_info(tag + 'SafeDNS MONITOR: \"' + qname + '/' + qtype + '\" (Score: ' + str(score) + '%% of DEFAULT)')
#
#                            else:
#                                if (debug >= 2): log_info(tag + 'SafeDNS: No response for \"' + qname + '/' + qtype + '\" using \"DEFAULT\"')
#
#                        else:
#                            if (debug >= 2): log_info(tag + 'SafeDNS: No nameservers for \"DEFAULT\"')

                else:
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

                        # Pre-set some variables for cname collapsing
                        if collapse:
                            firstname = False
                            firstttl = False
                            firsttype = False
                            lastname = dict()

                        # Loop through RRSets
                        for i in range(0,rep.an_numrrsets):
                            rk = rep.rrsets[i].rk
                            type = rk.type_str.upper()
                            dname = rk.dname_str.rstrip('.').lower()

                            if collapse and i == 0 and type == 'CNAME':
                                firstname = dname
                                firstttl = rep.ttl
                                firsttype = type

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
                                                    if collapse and firstname and type in ('A', 'AAAA'):
                                                        lastname[name] = type

                                                    if (debug >= 2): log_info(tag + 'Checking \"' + dname + '\" -> \"' + name + '\" (RR:' + type + ') (TTL:' + str(rep.ttl) + ')')

                                                    # Not Whitelisted?
                                                    if not in_list(name, 'white', 'RESPONSE', type):
                                                        # Blacklisted?
                                                        if in_list(name, 'black', 'RESPONSE', type):
                                                            blockit = True
                                                            break

                                                    #else:
                                                        # Already whitelisted, lets abort processing and passthru
                                                    #    blockit = False
                                                    #    break

                                            else:
                                                # If not an A, AAAA, CNAME, MX, PTR, SOA or SRV we stop processing and passthru
                                                if (debug >=2): log_info(tag + 'Ignoring RR-type ' + type)
                                                blockit = False
                                                break

                                    else:
                                        # dname Response Blacklisted
                                        blockit = True
                                        break

                                else:
                                    # dname Response Whitelisted
                                    blockit = False
                                    break

                            else:
                                # Nothing to process
                                blockit = False
                                break

                            if blockit:
                                # if we found something to block, abort loop and start blocking
                                break

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

                        elif collapse and lastname:
                            rmsg = DNSMessage(firstname, RR_TYPE_A, RR_CLASS_IN, PKT_QR | PKT_RA )
                            for lname in lastname.keys():
                                if (debug >= 2): log_info (tag + 'COLLAPSE CNAME \"' + firstname + '\" -> ' + lastname[lname] + ' \"' + lname + '\"')
                                rmsg.answer.append('%s %d IN %s %s' % (firstname, firstttl, lastname[lname], lname))

                            rmsg.set_return_msg(qstate)
                            if not rmsg.set_return_msg(qstate):
                                log_err(tag + 'CNAME COLLAPSE ERROR: ' + str(rmsg.answer))
                                return False

                            if qstate.return_msg.qinfo:
                                invalidateQueryInCache(qstate, qstate.return_msg.qinfo)

                            qstate.no_cache_store = 0
                            storeQueryInCache(qstate, qstate.return_msg.qinfo, qstate.return_msg.rep, 0)

                            qstate.return_msg.rep.security = 2

                            qstate.return_rcode = RCODE_NOERROR

                        if (debug >= 2): log_info(tag + 'Finished on RESPONSE for QUERY \"' + qname + '\" (RR:' + qtype + ')')

        # All done
        qstate.ext_state[id] = MODULE_FINISHED
        return True

    # Oops, non-supported event
    log_err('pythonmod: BAD Event')
    qstate.ext_state[id] = MODULE_ERROR
    return False

# <EOF>
