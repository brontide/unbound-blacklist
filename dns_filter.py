'''
dns_filter.py: Copyright (C) 2014 Oliver Hitz <oliver@net-track.ch>

DNS filtering extension for the unbound DNS resolver. At start, it reads the
two files /etc/unbound/blacklist and /etc/unbound/whitelist, which contain a
host name on every line.

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

blacklist = set()
matches = { 'youtube ads': re.compile('r\d+.+sn.+\.googlevideo\.com\.$',re.I) }

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
    if name in blacklist or name.rstrip('.') in blacklist:
        log_info("dns_filter.py: " + name + " found in blacklist")
        return True
    for tag, regexp in matches.items():
        if regexp.match(name):
            log_info("dns_filter.py: " + name + " matches " +tag)
            return True
    return False

def deinit(id):
    return True

def inform_super(id, qstate, superqstate, qdata):
    return True

def operate(id, event, qstate, qdata):

    if (event == MODULE_EVENT_NEW) or (event == MODULE_EVENT_PASS):

        # Check if whitelisted.
        name = b'.'.join(qstate.qinfo.qname_list).decode('ascii')
        log_info("dns_filter.py: Checking "+name)

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
#        log_info("pythonmod: iterator module done")
        qstate.ext_state[id] = MODULE_FINISHED 
        return True
      
    log_err("pythonmod: bad event")
    qstate.ext_state[id] = MODULE_ERROR
    return True
