#!/usr/bin/python
"""
[properties]
@version: 1.0
@author: Mario Robles
@name: NMAP
@id: nmap
@description: Run NMAP command in the local system
@syntax: nmap <options>
@type: function
@return_type: null
[properties]
"""

# Module Integration
mod_requirements = {'name': 'options', 'description': 'NMAP options, use -h for displaying nmap help',
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
        if options == "-h":
            console("[ ! ] NMAP Help", "blue")
            scanner.run_shell_command("nmap")
        else:
            scanner.run_shell_command(f"nmap {options}")
    except Exception as e:
        console(f"[ X ] Error: {e}", "red")


def rce(txt):
    whitelist = 'abcdefghijklmnopqrstuvwxyz1234567890-=. '
    for c in txt:
        if c not in whitelist:
            return True
    return False
