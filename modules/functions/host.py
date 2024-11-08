#!/usr/bin/python
"""
[properties]
@version: 1.0
@author: Mario Robles
@name: Host
@id: host
@description: Return the IP address for the host name provided
@syntax: host <hostname>
@type: function
@return_type: null
[properties]
"""

# Module Integration
mod_requirements = {'name': 'hostname', 'description': 'Host command options',
                    'type': 'host', 'required': True, 'value': None}


def requirements():
    return mod_requirements


# Console is the object used for printing the results in the main console
console = print


# Module Integration
def run(reqs):
    global console
    try:
        ip = reqs['value']
        console = reqs['console'] if 'console' in reqs.keys() else print
        scanner = reqs['scanner'] if 'scanner' in reqs.keys() else None
        if scanner is None:
            console('Scanner not defined', 'red')
            return
        scanner.run_shell_command(f"host {ip}")
    except Exception as e:
        console(f"[ X ] Error: {e}", "red")
