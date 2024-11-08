#!/usr/bin/python
"""
[properties]
@version: 1.0
@author: Mario Robles
@name: Ping
@id: ping
@description: Run Ping command in the local system
@syntax: ping <host> [count]
@type: function
@return_type: null
[properties]
"""

import platform

# Module Integration
mod_requirements = [
    {'name': 'host', 'description': 'Host or IP address',
     'type': 'host', 'required': True, 'value': None},
    {'name': 'c', 'description': 'ICMP packet count',
     'type': 'integer', 'required': False, 'value': 4}
    ]


def requirements():
    return mod_requirements


# Console is the object used for printing the results in the main console
console = print


def parse_reqs(reqs):
    options = dict()
    for req in reqs:
        keys = ['name', 'console', 'scanner']
        for k in keys:
            if k in req.keys():
                if k == 'name':
                    options[req['name']] = req['value']
                else:
                    options[k] = req[k]
    return options


# Module Integration
def run(reqs):
    global console
    try:
        options = parse_reqs(reqs)
        console = options['console'] if 'console' in options.keys() else print
        scanner = options['scanner'] if 'scanner' in options.keys() else None
        if scanner is None:
            console(f"[ X ] Scanner not defined", "red")
            return
        if platform.system() == 'Windows':
            cmd = 'ping -n {} {}'.format(options['c'], options['host'])
        else:
            cmd = 'ping -c {} {}'.format(options['c'], options['host'])
        scanner.run_shell_command(cmd)
    except Exception as e:
        console(f"[ X ] Error: {e}", "red")

