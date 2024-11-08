#!/usr/bin/python
"""
[properties]
@version: 1.0
@author: Mario Robles
@name: NSLOOKUP
@id: nslookup
@description: Run NSLOOKUP command in the local system
@syntax: nslookup [options] <domain.com> [dns_server]
@type: function
@return_type: null
[properties]
"""


# Module Integration
mod_requirements = {'name': 'options', 'description': 'NSLOOKUP options, use -h for help',
                    'type': 'string', 'required': True, 'value': None}


def requirements():
    return mod_requirements


# Console is the object used for printing the results in the main console
console = print


# Module Integration
def run(reqs):
    global console
    try:
        options = reqs['value']
        console = reqs['console'] if 'console' in reqs.keys() else print
        scanner = reqs['scanner'] if 'scanner' in reqs.keys() else None
        if scanner is None:
            console('Scanner not defined', 'red')
            return
        if rce(options):
            msg = 'Invalid characters in the options provided'
            console(msg, 'red')
            return
        if str(options).strip(" ") != "" and str(options).strip(" ") != "-h":
            scanner.run_shell_command(f"nslookup {options}")
        elif str(options).strip(" ") == "-h":
            console('Syntax:', 'blue')
            console('='*50, 'red')
            console('   nslookup [-type=[a,any,mx|txt|cname|hinfo|ns|ptr|soa]] [-timeout=10] domain.com [dns_server]',
                    'orange')
            print(" ")
            console('Examples:', 'blue')
            console('='*50, 'red')
            console('   nslookup -type=mx domain.com', 'orange')
            console('      Type: a,any,mx,txt,cname,hinfo,ns,ptr,soa', 'red')
            console('   nslookup -timeout=10 domain.com', 'orange')
            console('   nslookup domain.com dns_server', 'orange')
    except Exception as e:
        console(f"[ X ] Error: {e}", "red")


def rce(txt):
    whitelist = 'abcdefghijklmnopqrstuvwxyz1234567890-=. '
    for c in txt:
        if c not in whitelist:
            return True
    return False
