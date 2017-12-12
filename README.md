# unbound-dns-firewall
DNS-Firewall Python script for <a href="http://unbound.net/">UNBOUND</a>

Little blurp to facilitate DNS filtering using UNBOUND and it's <a href="https://www.unbound.net/documentation/pythonmod/">python-module</a> facility. Scales very well and is very fast. Might work well as alternative for <a href="https://www.isc.org/rpz/">RPZ</a> or <a href="http://www.thekelleys.org.uk/dnsmasq/doc.html">DNSMasq</a> / <a href="https://github.com/StevenBlack/hosts">HOSTS Files</a> combo.

All of this began when I started to search for an alternative for using UNBOUND's "local-zone/data" which doesn't scale very well with large lists and trashes memory. I also wanted to stay on UNBOUND for my DNS resolution purposes. Also liked the concept of <a href="https://github.com/conformal/adsuck">ADSUCK</a> using regex (ADSUCK has been abandoned though). During my search I tripped over a <a href="https://github.com/ohitz/unbound-domainfilter">Python script</a> by <a href="https://github.com/ohitz">Oliver Hitz</a>, started to test it, optimized it, added regexp and NXDOMAIN feature, and some more informative logging.

See <a href="https://github.com/cbuijs/unbound-dns-firewall/blob/master/dns-firewall.py">dns-firewall.py</a> and the <a href="https://github.com/cbuijs/unbound-dns-firewall/wiki">Wiki</a> for more info.

<b>Disclaimer</b>: The lists are generated automatically, unduplicated, aggregrated and are provided as is. Some thougth and filtering went into the process to have as less false-positives as possible. By no means are these lists complete and do not guarantee an error-free or disrupted-free experience when used in any way. Using the Python module with UNBOUND has it's own impact as well and can disturb and bring down your DNS when fiddling to much. Use at own risk! 

Included lists are compiled from my generic <a href="https://github.com/cbuijs/dns-firewall">DNS-Firewall</a> lists repository, and is intended to block online/web Advertising, Cyber-Attacks, Fake-News/Info, Gambling, Intrusion/Privacy, Malicious/Malware, Phising, Pornography and Tracking.

<b>NOTE</b>: This is a work-in-progress and mistakes/errors/faults will creep in from time to time. The lists are updated at least once very 24 hours. This is done by an automated process, which can fail. See disclaimer. 
