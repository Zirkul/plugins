#!/usr/bin/python
"""
[properties]
@version: 1.0
@author: Mario Robles
@name: Whois
@id: whois
@description: Run WHOIS command in the local system
@syntax: whois <ip_or_hostname>
@type: function
@return_type: null
[properties]
"""

# Module Integration
mod_requirements = {'name': 'host',
                    'description': 'Host name or IP address',
                    'type': 'host',
                    'required': True,
                    'value': None
                    }

# Console is the object used for printing the results in the main console
console = print


def requirements():
    return mod_requirements


# Module Integration
def run(reqs):
    global console
    try:
        ip = reqs['value']
        console = reqs['console'] if 'console' in reqs.keys() else print
        scanner = reqs['scanner'] if 'scanner' in reqs.keys() else None
        if scanner is None:
            console(f"[ X ] Scanner not defined", "red")
            return
        scanner.run_shell_command(f"whois {ip}")
    except Exception as e:
        console(f"[ X ] Error: {e}", "red")
