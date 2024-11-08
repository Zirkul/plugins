#!/usr/bin/python
"""
[properties]
@version: 1.0
@author: Mario Robles
@name: Dig
@id: dig
@description: Run Dig command in the local system
@syntax: dig <host>
@type: function
@return_type: null
[properties]
"""

# Module Integration
mod_requirements = {'name': 'host', 'description': 'DIG command options',
                    'type': 'host', 'required': True, 'value': None}

console = print


def requirements():
    return mod_requirements


# Module Integration
def run(reqs):
    global console
    try:
        ip = reqs['value']
        console = reqs.get('console', print)
        scanner = reqs.get('scanner', None)
        if scanner is None:
            console('Scanner not defined', 'red')
            return
        scanner.run_shell_command(f"dig {ip}")
    except Exception as e:
        console(f"[ X ] Error: {e}", "red")
