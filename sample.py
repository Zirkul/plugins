#!/usr/bin/python
"""
[properties]
@author: Your name
@name: Use this for setting up the integration or tool name
@id: shortname
@version: 1.0
@description: This is the description in one line
@syntax: descriptive text on how to run this, example: tool-name -i -o -etc
@type: tool
@impact: intrusive
@service: https
@return_type: vuln
[properties]

Quick Help:
    type = [function,exploit,integration,tool]
    impact = [safe,intrusive,dos]
    service = [ssh,ftp,smtp,pop,imap,web,http,https,smb,tcp-##,udp-##]
    return_type = [vuln,asset,boolean,null]
"""


try:
    import subprocess, re, platform, sys, time, pickle, os, random
    from datetime import datetime, timedelta
except ImportError as err:
    print(f"[ X ] Missing libraries need to be installed: {err}")

console = print

# REQUIRED OBJECT
mod_requirements = [{'name': 'url', 'description': 'URL to be scanned', 'type': 'url', 'required': True,
                     'value': None},
                    {'name': 'args', 'description': 'Send custom arguments or whatever else',
                     'type': 'string', 'required': False, 'value': None},
                    {'name': 'port', 'description': 'You may also require numeric values', 'type': 'port',
                     'required': False, 'value': 9995}]


# REQUIRED FUNCTION
def requirements():
    return mod_requirements


def parse_reqs(reqs):
    global console
    options = dict()
    for req in reqs:
        if "console" in req.keys():
            console = req.get('console', print)
        if "scanner" in req.keys():
            options['scanner'] = req.get('scanner', None)
        if 'name' in req.keys() and 'value' in req.keys():
            options[req['name']] = req['value']
    return options


# REQUIRED FUNCTION
def run(reqs) -> dict | list:
    """
    This function will be executed by Zirkul CLI when the user send the command: run
    :param reqs:
    :return: dict
    """
    try:
        config = parse_reqs(reqs)
        if not config:
            return {'description': 'Errors found in the data provided', 'status': 'error'}
        console("[ ! ] Parameters validated", "green")
        scanner = config.get('scanner', None)
        if scanner is None:
            console("[ X ] Scanner not defined", "red")
            return {'description': 'Scanner not defined', 'status': 'error'}
        cmd = 'echo "{}"'.format(config["url"])
        output = scanner.run_shell_command(cmd)
        results = build_results(config["url"], output)
        if results is None:
            return {'description': "The scan didn't completed correctly, see the event log for details",
                    'status': 'error'}
        return {'results': results, 'status': True}
    
    except Exception as e:
        console(f"[ X ] Error: {e}", "red")
        return {'description': f'Error: {e}', 'status': 'error'}


def build_results(target, evidence):
    console('[ ! ] Scanning: {}'.format(target), 'green')

    results = []

    # REQUIRED Format for Vulnerabilities
    vuln = {"issue_type": "vulnerability",
            "vulnerability_type": "web",
            "type": "Cross-site scripting",
            "scan_type": "dynamic scan",
            'severity': "critical",
            'confidence': "confirmed",
            'evidence': evidence,
            'details': "Any details",
            'url': target,
            'port': "443",
            'transport': 'tcp',
            'protocol': "https",
            'attack': "the command for replicating this issue",
            'cve': "CVE-XXX",
            'cvss': 10,
            'cvss string': "",
            'cwe': "CWE-78",
            'wasc': "",
            'owasp': 'A1:2021',
            'remediation': "Remediation guidance",
            'references': [{'title': 'Page title', 'url': 'http://site.com/relevant-url'}],
            'request': "Http raw request data",
            'response': "Http raw response data",
            'tool': 'the name of your script'
            }
    results.append(vuln)
    return results

    
if __name__ == '__main__':
    try:
        # Emulating what the scan server would do for running this module
        mod_target = 'https://127.0.0.1'
        mod_requirements[0]["value"] = mod_target
        mod_results = run(mod_requirements)
        print(mod_results)
        console("[ ! ] Test completed", "green")
        
    except Exception as err:
        console(f"[ X ] Error: {err}", "red")
