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
#matches = { 'youtube ads': re.compile('r\d+.+sn-(8xgp1vo|p5qlsnll|a5mekner|vgqs7nez|vgqs7n7k|vgqsenes|p5qs7n7s|p5qlsnzd|p5qlsnsy|p5qlsnsy).+\.googlevideo\.com\.$',re.I) }
#matches = { 'youtube ads': re.compile('r\d+.+sn-.*[76olrzksedyd]\.googlevideo\.com\.$',re.I) }
matches = { 
        'tapjoy': re.compile('.*tapjoy[\.\-]com', re.I),
        'moatads': re.compile('.*moatads.com', re.I),
        'doubleclick': re.compile('.*doubleclick.net', re.I),
        #'youtube': re.compile('.*8xgp1vo\-xfge.+googlevideo.com', re.I),
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
    if name in blacklist or name[:-1] in blacklist:
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

# Decode names/strings from response message
def decodedata(rawdata,start):
    text = ''
    remain = rawdata[2]
    for c in rawdata[3+start:]:
       if remain == 0:
           text += '.'
           remain = c
           continue
       remain -= 1
       text += chr(c).lower()
    return text.strip('.')

def decodename(list):
    return b'.'.join(list).decode('ascii')

def decodemsg(msg, types=['A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SVR']):
    rep = msg.rep
    for i in range(0,rep.an_numrrsets):
        rrset = rep.rrsets[i]
        rk = rrset.rk
        type = rk.type_str.upper()
        dname = decodename(rk.dname_list).rstrip('.').lower()
        if dname:
            log_info("dns_filter.py: " + 'Starting on RESPONSE \"' + dname + '\" (RR:' + type + ')')
            data = rrset.entry.data
            # Get data
            for j in range(0,data.count):
                answer = data.rr_data[j]
                if type in types:
                    if type == 'A':
                        yield dname, type, "%d.%d.%d.%d"%(answer[2],answer[3],answer[4],answer[5])
                    elif type == 'AAAA':
                        yield dname, type, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x"%(answer[2],answer[3],answer[4],answer[5],answer[6],answer[7],answer[8],answer[9],answer[10],answer[11],answer[12],answer[13],answer[14],answer[15],answer[16],answer[17])
                    elif type in ('CNAME', 'NS', 'PTR'):
                        yield dname, type, decodedata(answer,0)
                    elif type == 'MX':
                        yield dname, type, decodedata(answer,1)
                    elif type == 'SRV':
                        yield dname, type, decodedata(answer,5)
                        

def operate(id, event, qstate, qdata):

    if (event == MODULE_EVENT_NEW) or (event == MODULE_EVENT_PASS):

        # Check if whitelisted.
        name = decodename(qstate.qinfo.qname_list)
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

        msg = qstate.return_msg
        if msg:
            blocked = False
            for dname, dnstype, value in decodemsg(msg, types=['A']):
                if is_filtered(dname):
                    blocked = True
                #elif value.startswith('63.117.14'):
                #    log_info("Blocking youtube ad")
                #    blocked = True

            if blocked:
                qstate.return_rcode = RCODE_REFUSED
                # Invalidate any cached entry
                invalidateQueryInCache(qstate, msg.qinfo)

                # Allow response modification (Security setting)
                qstate.return_msg.rep.security = 2

        qstate.ext_state[id] = MODULE_FINISHED 
        return True
      
    log_err("pythonmod: bad event")
    qstate.ext_state[id] = MODULE_ERROR
    return True
