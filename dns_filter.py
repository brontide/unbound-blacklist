'''
by Eric Warnke <ericew@gmail.com>

Heavily inspired by
dns_filter.py: Copyright (C) 2014 Oliver Hitz <oliver@net-track.ch>
dns-firewall.py: v3.75-20171226 Copyright (C) 2017 Chris Buijs <cbuijs@chrisbuijs.com>

For every query sent to unbound, the extension checks if the name is in the
whitelist or in the blacklist. If it is in the whitelist, processing continues
as usual (i.e. unbound will resolve it). If it is in the blacklist, unbound
stops resolution and returns the IP address configured in intercept_address.

The whitelist and blacklist matching is done with every domain part of the
requested name. So, if www.domain.com is requested, the extension checks
whether www.domain.com, domain.com or .com is listed. 

Install and configure:

- copy dns_filter.py to /etc/unbound/dns_filter.py

- if needed, change intercept_address

- change unbound.conf as follows:

  server:
    module-config: "python validator iterator"
  python:
    python-script: "/etc/unbound/dns_filter.py"

- create /etc/unbound/blacklist and /etc/unbound/whitelist as you desire

- restart unbound

'''
import re
from glob import glob
import codecs
import ipaddress

blacklist = set()
matches = { 
        'tapjoy': re.compile('.*tapjoy[\.\-]com', re.I),
        'moatads': re.compile('.*moatads.com', re.I),
        'doubleclick': re.compile('.*doubleclick.net', re.I),
        'beacon 1': re.compile('.*imrworldwide.com', re.I),
        'beacon 2': re.compile('.*appsflyer', re.I),
        }

def hostfile_to_set(filename):
    '''
    Each line starting with 0.0.0.0 is a hostname
    '''
    myset = set()
    for line in codecs.open(filename, encoding='utf-8'):
        line = line.strip()
        if line.startswith("#"): continue
        if not line.startswith('0.0.0.0 '): continue
        try:
            ip, hostname, *rest = line.split()
            myset.add(hostname.lower())
        except:
            pass
    return myset


def init(id, cfg):
    log_info("dns_filter.py: ")
    for filename in glob('filter.d/*.hosts'):
        out = hostfile_to_set(filename)
        log_info("Loaded " + filename + " with " + str(len(out)) + " hosts")
        blacklist.update(out)
    return True

def is_filtered(name):
    '''
    Match the name against our lists
    '''
    if name in blacklist:
        return True
    for tag, regexp in matches.items():
        if regexp.match(name):
            blacklist.add(name)
            return True
    return False

def deinit(id):
    return True

def inform_super(id, qstate, superqstate, qdata):
    return True

# Decode names/strings from response message
def decodedata(rawdata,start=0):
    '''
    Take the wire bytestring and convert to string
    by finding the lengths of each part and replacing
    them with '.'
    '''

    # Make a copy to a bytestring
    working = bytearray(rawdata[start+1:])
    if len(working) == 0:
        # Simple case of the single '.'
        return ''

    # Find the label lengths and replace them with '.'
    count = rawdata[start]
    i = -1
    while count:
        i += count+1
        count = working[i]
        working[i] = ord(b'.')

    # Return the bytestring decoded
    return working.decode().rstrip('.')

def decodemsg(msg, types=['A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SRV']):
    '''
    Helper.  The odd syntax is because the arrays provided by the libary
    do not support slicing which is very wierd.  Use a generator to do
    slicing.
    '''
    for rrset in (msg.rep.rrsets[x] for x in range(0,msg.rep.an_numrrsets)):
        rk = rrset.rk
        type_str = rk.type_str
        # If we don't care about the type, jump to the next rrset
        if type_str not in types: continue
        dname = decodedata(rk.dname)
        if dname:
            data = rrset.entry.data
            for answer in (data.rr_data[x] for x in range(0,data.count)): # The module doesn't support ranges
                if type_str == 'A':
                    yield dname, type_str, ipaddress.ip_address(answer[2:6])
                elif type_str == 'AAAA':
                    yield dname, type_str, ipaddress.ip_address(answer[2:18])
                elif type_str in ('CNAME', 'NS', 'PTR'):
                    yield dname, type_str, decodedata(answer,2)
                elif type_str == 'MX':
                    yield dname, type_str, decodedata(answer,4)
                elif type_str == 'SRV':
                    yield dname, type_str, decodedata(answer,8)

def operate(id, event, qstate, qdata):

    if (event == MODULE_EVENT_NEW) or (event == MODULE_EVENT_PASS):

        name = decodedata(qstate.qinfo.qname)
        log_info("dns_filter.py: Checking %s"%(name))

        if (is_filtered(name)):

            # Build and return a blank answer with a refused flag
            msg = DNSMessage(name, RR_TYPE_A, RR_CLASS_IN, PKT_QR | PKT_RA | PKT_AA)
            msg.answer = []
            qstate.return_rcode = RCODE_REFUSED
            if not msg.set_return_msg(qstate):
                qstate.ext_state[id] = MODULE_ERROR
                return False

            # Allow response modification (Security setting)
            qstate.return_msg.rep.security = 2

            qstate.ext_state[id] = MODULE_FINISHED 
            return True
        else:
            # Non filtered
            qstate.ext_state[id] = MODULE_WAIT_MODULE 
            return True

    if event == MODULE_EVENT_MODDONE:

        try:
            msg = qstate.return_msg
            if msg:
                blocked = False
                for dname, dnstype, value in decodemsg(msg, types=['A','AAAA','CNAME']):
                    log_info("dns_filter.py: Checkin return %s %s %s"%(dname, dnstype, str(value)))
                    if is_filtered(dname):
                        blocked = True
                        break
                    if dnstype == 'CNAME' and is_filtered(value):
                        blocked = True
                        break

                if blocked:
                    qstate.return_rcode = RCODE_REFUSED
                    # Invalidate any cached entry
                    invalidateQueryInCache(qstate, msg.qinfo)
                    # Allow response modification (Security setting)
                    qstate.return_msg.rep.security = 2
        except Exception as e:
            log_info(repr(e))

        qstate.ext_state[id] = MODULE_FINISHED 
        return True
      
    log_err("pythonmod: bad event")
    qstate.ext_state[id] = MODULE_ERROR
    return True
