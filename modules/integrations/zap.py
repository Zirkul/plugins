#!/usr/bin/python
"""
[properties]
@version: 1.2
@author: Mario Robles
@name: OWASP ZAP
@id: zap
@description: Run OWASP ZAP
@syntax: zap
@type: integration
@impact: intrusive
@service: [http,https]
@return_type: vuln
[properties]
type = [function,exploit,integration,tool]
impact = [safe,intrusive,dos]
service = [ssh,ftp,smtp,pop,imap,web,http,https,smb,tcp-##,udp-##]
return_type = [vuln,asset,boolean,null]
"""

import subprocess
import platform
import sys
import time
import os
import signal
import random
import requests
import threading
from secrets import token_urlsafe
from datetime import datetime, timedelta
try:
    from zapv2 import ZAPv2
except ImportError as import_error:
    print("[ X ] Missing libraries need to be installed: " + str(import_error))
    print("      Install python ZAP:")
    print("      pip install python-owasp-zap-v2.4")


# Module Integration
mod_requirements = [{'name': 'url', 'description': 'URL ZAP will be scanning',
                     'type': 'url', 'required': True, 'value': None},
                    {'name': 'args', 'description': 'Send custom arguments for running ZAP (override other parameters)',
                     'type': 'string', 'required': False, 'value': None},
                    {'name': 'port', 'description': 'The port used by ZAP for running the local proxy', 'type': 'port',
                     'required': False, 'value': 9999},
                    {'name': 'apikey', 'description': 'Setup a custom API key for ZAP, if not provided JaguarScan will '
                                                      'generate one for you',
                     'type': 'string', 'required': False, 'value': None},
                    {'name': 'path', 'description': 'Custom path for locating the zap.bat or zap.sh script, if not '
                                                    'provided the module will use the default based on the current OS',
                     'type': 'string', 'required': False, 'value': None},
                    {'name': 'memory', 'description': 'You can specify how much memory Zap will use (512 default)',
                     'type': [512, 1024, 2048, 4096], 'required': False, 'value': 512},
                    {'name': 'scantype', 'description': 'What scan type do you want ZAP to run: spider,active,full',
                     'type': ['spider', 'active', 'full'], 'required': True, 'value': 'full'},
                    {'name': 'max_minutes', 'description': 'Maximum minutes allowed for the scan to run',
                     'type': 'integer', 'required': False, 'value': 120},
                    {'name': 'timeout', 'description': 'Abort the scan if the progress is stuck for 30 minutes',
                     'type': 'integer', 'required': False, 'value': 30},
                    {'name': 'daemon_mode', 'description': 'Run Zap in daemon mode (no GUI)',
                     'type': 'boolean', 'required': False, 'value': True},
                    {'name': 'rules_quality', 'description': 'Define the quality of rules to be used',
                     'type': ['release', 'beta', 'alpha'], 'required': False, 'value': 'release'},
                    {'name': 'severity_level', 'description': 'Define minimum severity to be reported',
                     'type': ['critical', 'high', 'medium', 'low', 'informational'], 'required': False, 'value': 'low'},
                    {'name': 'confidence_level', 'description': 'Define minimum confidence level to be reported',
                     'type': ['confirmed', 'strong', 'moderate', 'low'], 'required': False, 'value': 'moderate'},
                    ]


def requirements():
    return mod_requirements


def parse_reqs(reqs):
    options = dict()
    for req in reqs:
        if 'name' in req.keys():
            options[req['name']] = req['value']
    return options



def run(reqs):
    zap_integration = ZapIntegration()
    try:
        zap_config = parse_reqs(reqs)
        if not isinstance(zap_config, dict):
            return {'description': 'Errors found in the data provided', 'status': 'error'}
        if 'console' in zap_config.keys():
            zap_integration.console = zap_config['console']
        zap_integration.console("[ ! ] Parameters validated")
        if not zap_integration.test_url(zap_config["url"]):
            return {'description': 'URL unreachable', 'status': 'error'}
        zap_integration.console("[ ! ] Loading ZAP")
        if not zap_integration.load_zap(zap_config):
            return {'description': "ZAP didn't started correctly, make sure the path is correct", 'status': 'error'}
        zap_integration.console('[ ! ] ZAP successfully loaded!', 'green')
        all_good = zap_integration.zap_scan(zap_config["url"], scan_type=zap_config["scantype"])
        if not all_good:
            return {'description': "ZAP scan didn't completed correctly, see the event log for details",
                    'status': 'error'}
        return {'results': zap_integration.issues, 'status': True}

    except Exception as e:
        zap_integration.console(f'[ X ] Error: {e}', "red")
        return {'description': f'Error: {e}', 'status': 'error'}

class ZapIntegration:
    def __init__(self):
        self.zap = None
        self.console = self.terminal_console
        self.port_blocked = False
        self.apikey = None
        self.daemon_mode = True
        self.memory = 512
        self.port = 9999
        self.zap_args = None
        self.zap_path = self.__get_default_zap_path()
        self.zap_command = None
        self.max_minutes = 120
        self.timeout = 30
        self.rules_quality = 'release'
        self.confidence_level = 'low'
        self.severity_level = 'low'
        self.issues = []
        self.zap_process = None

    @staticmethod
    def terminal_console(txt, col=''):
        if col == '':
            print(txt, col)
        else:
            print(txt)

    def test_url(self, url):
        try:
            r = requests.get(url)
            if r.status_code in [200, 302, 303]:
                return True
        except Exception as e:
            self.console(f'[ X ] Error connecting to {url}: {e}')
        return False

    def is_valid_config(self, zap_config):
        config = self.__parse_config(zap_config)
        if config is None:
            return False
        if config['apikey'] is None:
            self.apikey = self.gen_token()
        if isinstance(config['daemon_mode'], bool):
            self.daemon_mode = config['daemon_mode']
        if not self.is_valid_port(config['port']):
            self.console('[ X ] Port value is not valid', 'red')
            return False
        self.port = config['port']
        if not self.is_valid_memory(config['memory']):
            self.console('[ X ] Memory value is not valid', 'red')
            return False
        self.memory = config['memory']
        if not self.is_valid_zap_args(config['zap_args']):
            self.console('[ X ] zap_args value is not valid', 'red')
            return False
        self.zap_args = config['zap_args']
        if config['zap_path'] not in [None, '']:
            self.zap_path = config['zap_path']
        if not self.is_valid_zap_path(self.zap_path):
            self.console("[ X ] Unable to locate Zap sh or bat file, use the 'zap_path' attribute with the full path.",
                         'red')
            return False
        zap_command = self.__build_zap_command(self.zap_path)
        if zap_command is None:
            self.console('[ X ] Operating system not recognized', 'red')
            return False
        self.zap_command = zap_command
        if not self.is_valid_max_time(config['max_minutes']):
            self.console('[ X ] max_minutes value is not valid', 'red')
            return False
        self.max_minutes = config['max_minutes']
        if not self.is_valid_max_time(config['timeout']):
            self.console('[ X ] timeout value is not valid', 'red')
            return False
        self.timeout = config['timeout']
        if config['rules_quality'] not in ['release', 'beta', 'alpha']:
            self.console('[ X ] rules_quality value is not valid', 'red')
            return False
        self.rules_quality = config['rules_quality']
        if not self.is_valid_confidence(config['confidence_level']):
            self.console('[ X ] confidence_level value is not valid', 'red')
            return False
        self.confidence_level = config['confidence_level']
        if not self.is_valid_severity(config['severity_level']):
            self.console('[ X ] severity_level value is not valid', 'red')
            return False
        self.severity_level = config['severity_level']
        return True

    @staticmethod
    def __parse_config(zap_config):
        if not isinstance(zap_config, dict):
            return None
        config = dict()
        config['zap_path'] = None
        config['zap_args'] = None
        config['apikey'] = None
        config['port'] = 9999
        config['memory'] = 512
        config['max_minutes'] = 120
        config['timeout'] = 30
        config['daemon_mode'] = True
        config['rules_quality'] = 'release'
        config['severity_level'] = 'low'
        config['confidence_level'] = 'low'
        for k, v in zap_config.items():
            if k in config.keys():
                config[k] = v
        return config

    @staticmethod
    def __get_default_zap_path():
        zap_path = None
        if platform.system() == "Darwin":
            zap_path = '/Applications/OWASP ZAP.app/Contents/MacOS/OWASP ZAP.sh'
        elif platform.system() == "Linux":
            zap_path = "/usr/share/zaproxy/zap.sh"
        elif platform.system() == "Windows":
            program_files = os.path.expandvars('%programfiles%')
            zap_path = f"{program_files}\OWASP\Zed Attack Proxy\zap.bat"
        return zap_path

    def __build_zap_command(self, zap_path):
        if self.apikey is None:
            api_string = '-config api.disablekey=true'
        else:
            api_string = f'-config api.disablekey=false -config api.key={self.apikey}'
        if self.port in [None, 0]:
            zap_port = '-port 9999'
        else:
            zap_port = f'-port {self.port}'
        daemon_string = '-daemon'
        if not self.daemon_mode:
            daemon_string = ''
        if self.zap_args is None:
            self.zap_args = f' {daemon_string} {api_string} {zap_port}'
        zap_command = None
        if platform.system() == "Darwin":
            zap_command = f"bash \"{zap_path}\" {self.zap_args}"
        elif platform.system() == "Linux":
            zap_command = f"bash \"{zap_path}\" {self.zap_args}"
        elif platform.system() == "Windows":
            program_files = os.path.expandvars('%programfiles%')
            zap_command = f"cd \"{program_files}\OWASP\Zed Attack Proxy\" && zap.bat {self.zap_args}"
        return zap_command

    # Module Integration
    def load_zap(self, zap_config):
        if not self.is_valid_config(zap_config):
            return False
        loaded = False
        c = 0
        while not loaded:
            loaded = self.run_shell_command(self.zap_command)
            if not loaded and self.port_blocked:
                self.port = random.randint(19000, 19999)
                self.zap_command = self.__build_zap_command(self.zap_path)
            c += 1
            if c > 5:
                self.console('[ X ] Max retries number reached, unable to start Zap')
                return False
        return True

    def zap_scan(self, target_url, scan_type='full'):
        try:
            self.zap = ZAPv2(apikey=self.apikey,
                             proxies={'http': 'http://127.0.0.1:' + str(self.port),
                                      'https': 'http://127.0.0.1:' + str(self.port)})
        except Exception as e:
            self.console(f'[ ! ] Unable to start Zap: {e}', 'red')
            return False
        context_name = self.__zap_prepare_context(target_url)
        if context_name is None:
            return False
        self.__scanners_quality_setup()
        self.__wait_for_passive_scanner()
        if scan_type in ['spider', 'full']:
            self.__zap_start_spider(target_url, context_name)
            self.__wait_for_passive_scanner()

        if scan_type in ['active', 'full']:
            self.__zap_start_active_scan(target_url)
            self.__wait_for_passive_scanner()

        self.__process_results()
        return self.__zap_shutdown()

    def __zap_shutdown(self):
        self.console('[ ! ] Shutting down ZAP', 'orange')
        c = 1
        try:
            self.zap.core.shutdown()
            while self.zap_process is not None:
                c += 1
                time.sleep(1)
                if c > 10 or self.zap_process is None:
                    break
            if self.zap_process is not None:
                os.killpg(os.getpgid(self.zap_process.pid), signal.SIGTERM)
                self.zap_process = None
            return True
        except Exception as e:
            self.console(f'[ ! ] Unable to shutdown Zap: {e}', 'red')
        return False

    def __zap_prepare_context(self, target_url):
        # Create new context
        self.console('[ ! ] Creating a new context', "green")
        context_name = "ZirkulScan"
        try:
            self.zap.context.new_context(contextname=context_name)
            self.zap.context.remove_context(contextname='Default Context')
            self.zap.context.include_in_context(contextname=context_name, regex="{}{}".format(target_url, '.*'))
            self.zap.context.set_context_in_scope(contextname=context_name, booleaninscope=True)
            self.console('[ ! ] Accessing target {}'.format(target_url), 'green')
            self.zap.urlopen(target_url)
            # Give the sites tree a chance to get updated
            time.sleep(2)
            return context_name
        except Exception as e:
            self.console(f'[ ! ] Error creating context: {e}', 'red')
        return None

    def __zap_start_spider(self, target_url, context_name):
        self.console('[ ! ] Start Spider : {}'.format(target_url), "green")
        try:
            scanid = self.zap.spider.scan(contextname=context_name, recurse=True, subtreeonly=True)
            # Give the Spider a chance to start
            time.sleep(2)
            progress = int(self.zap.spider.status(scanid))
            last_progress = 0
            started = datetime.now()
            expiration = started + timedelta(minutes=self.max_minutes)
            timeout = started + timedelta(minutes=self.timeout)
            while progress < 100:
                progress = int(self.zap.spider.status(scanid))
                if last_progress != progress:
                    timeout = datetime.now() + timedelta(minutes=self.timeout)
                    self.console(f'[ ! ] Spider progress %: {progress}', 'green')
                    last_progress = progress
                if datetime.now() > expiration:
                    self.console('[ X ] The process reached the maximum minutes allowed', 'red')
                    self.zap.ascan.stop_all_scans()
                    return False
                if datetime.now() > timeout:
                    self.console('[ X ] The process reached the timeout', 'red')
                    self.zap.ascan.stop_all_scans()
                    return False
                if progress < 100:
                    time.sleep(5)
            self.console('[ ! ] Spider progress %: {}'.format(self.zap.spider.status(scanid)), 'green')
            self.console('[ ! ] Spider completed', 'green')
            return True
        except Exception as e:
            self.console(f'[ ! ] Error running spider: {e}', 'red')
        return False

    def __zap_start_active_scan(self, target_url):
        self.console('[ ! ] Active Scanning target {}'.format(target_url), 'green')
        try:
            scanid = self.zap.ascan.scan(target_url, recurse=True, inscopeonly=True)
            started = datetime.now()
            last_progress = ''
            expiration = started + timedelta(minutes=self.max_minutes)
            timeout = started + timedelta(minutes=self.timeout)
            while int(self.zap.ascan.status(scanid)) < 100:
                # Loop until the scanner has finished
                progress = self.zap.ascan.status(scanid)
                if last_progress != progress:
                    timeout = datetime.now() + timedelta(minutes=self.timeout)
                    self.console(f'[ ! ] Scan progress : {progress}%')
                    last_progress = progress
                if datetime.now() > expiration:
                    self.console('[ X ] The process reached the maximum minutes allowed', 'red')
                    self.zap.ascan.stop_all_scans()
                    return False
                if datetime.now() > timeout:
                    self.console('[ X ] The process reached the timeout', 'red')
                    self.zap.ascan.stop_all_scans()
                    return False
                time.sleep(5)
            self.console('[ ! ] Scan progress %: {}'.format(self.zap.ascan.status(scanid)), 'green')
            self.console('[ ! ] Active Scan completed', 'green')
            return True
        except Exception as e:
            self.console(f'[ ! ] Error running active scan: {e}', 'red')
        return False

    def __scanners_quality_setup(self):
        try:
            self.console('[ ! ] Rules quality: {}'.format(self.rules_quality))
            allowed = []
            if self.rules_quality == 'release':
                allowed.append('release')
            if self.rules_quality == 'beta':
                allowed.append('release')
                allowed.append('beta')
            if self.rules_quality == 'alpha':
                allowed.append('release')
                allowed.append('beta')
                allowed.append('alpha')
            scanners = self.zap.ascan.scanners()
            disabled = []
            for scanner in scanners:
                if scanner["quality"] not in allowed:
                    disabled.append(scanner["id"])
                    self.console('[ ! ] Active rule disabled by rule_quality setting: {} {} - {}'.format(
                        scanner['quality'],
                        scanner['id'],
                        scanner['name']
                        ))
            if len(disabled) > 0:
                self.console('[ ! ] Total active rules disabled: {}'.format(len(disabled)))
                self.zap.ascan.disable_scanners(disabled)
            disabled = []
            scanners = self.zap.pscan.scanners
            for scanner in scanners:
                if scanner["quality"] not in allowed:
                    disabled.append(scanner['id'])
                    self.console('[ ! ] Passive rule disabled by rule_quality setting: {} {} - {}'.format(
                        scanner['quality'],
                        scanner['id'],
                        scanner['name']
                    ))
            if len(disabled) > 0:
                self.console('[ ! ] Total passive rules disabled: {}'.format(len(disabled)))
                self.zap.pscan.disable_scanners(disabled)
        except Exception as e:
            self.console(f'[ ! ] Error setting up scanners quality: {e}', 'red')

    def __wait_for_passive_scanner(self):
        try:
            progress = int(self.zap.pscan.records_to_scan)
            last_progress = 0
            while progress > 0:
                progress = int(self.zap.pscan.records_to_scan)
                if last_progress != progress and progress != 0:
                    self.console(f'[ ! ] Passive scanner remaining records to analyze : {progress}', 'green')
                    last_progress = progress
                if progress == 0:
                    break
                time.sleep(2)
            return True
        except Exception as e:
            self.console(f'[ ! ] Error waiting for passive scan to complete: {e}', 'red')
        return False

    def __process_results(self):
        self.console('[ ! ] Hosts: {}'.format(', '.join(self.zap.core.hosts)), 'green')
        self.console('[ ! ] Collecting vulnerabilities (alerts)', 'green')
        results = self.zap.core.alerts()
        self.console('[ ! ] Total results found: {}'.format(len(results)), 'orange')
        self.issues = []

        for issue in results:
            new_issue = self.__process_issue(issue)
            if new_issue in ['confidence', 'severity']:
                self.console('[ ! ] Skipping record because of {} policy'.format(new_issue), 'orange')
                self.console('[ - ] {} - {} : {}'.format(issue['risk'], issue['name'], issue['url']), 'orange')
            elif new_issue is not None:
                self.issues.append(new_issue)
                self.console('[ + ] {} - {} : {}'.format(issue['risk'], issue['name'], issue['url']), 'green')
            else:
                self.console('[ X ] Skipping record due to errors in the data', 'red')
                self.console('[ X ] {} - {} : {}'.format(issue['risk'], issue['name'], issue['url']), 'red')

    def __issue_in_confidence_level(self, confidence):
        if not isinstance(confidence, str):
            return False
        c = {'confirmed': 4, 'strong': 3, 'moderate': 2, 'low': 1}
        policy_confidence = c[self.confidence_level.lower()]
        issue_confidence = c[confidence.lower()]
        if issue_confidence >= policy_confidence:
            return True
        return False

    def __issue_in_severity_level(self, severity):
        if not isinstance(severity, str):
            return False
        c = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'informational': 0}
        policy_severity = c[self.severity_level.lower()]
        issue_severity = c[severity.lower()]
        if issue_severity >= policy_severity:
            return True
        return False

    def __process_issue(self, issue):
        new_issue = self.__new_issue()
        try:
            message_data = self.zap.core.message(issue['messageId'])
            url_data = self.parse_url(issue['url'])
            if url_data is None:
                return None
            confidence = self.__issue_confidence(issue['confidence'])
            severity = issue['risk']
            evidence = self.__issue_evidence(issue)
            if not self.is_valid_severity(severity):
                return None
            if not self.is_valid_confidence(confidence):
                return None
            if not self.__issue_in_confidence_level(confidence):
                return 'confidence'
            if not self.__issue_in_severity_level(severity):
                return 'severity'
            new_issue['type'] = issue['name']
            new_issue['severity'] = severity
            new_issue['confidence'] = confidence
            new_issue['evidence'] = evidence
            new_issue['parameters'] = issue['param']
            new_issue['details'] = issue['description']
            new_issue['url'] = issue['url']
            new_issue['port'] = url_data['port']
            new_issue['transport'] = 'tcp'
            new_issue['protocol'] = url_data['protocol']
            new_issue['attack'] = issue['attack']
            new_issue['cve'] = ''
            new_issue['cvss'] = ''
            new_issue['cvss string'] = ''
            if issue['cweid'] not in ['-1', '']:
                new_issue['cwe'] = 'CWE-{}'.format(issue['cweid'])
            if issue['wascid'] not in ['-1', '']:
                new_issue['wasc'] = 'WASC-{}'.format(issue['wascid'])
            new_issue['remediation'] = issue['solution']
            new_issue['references'] = issue['reference']
            new_issue['request'] = '{}\n{}'.format(message_data['requestHeader'], message_data['requestBody'])
            new_issue['response'] = '{}\n{}'.format(message_data['responseHeader'], message_data['responseBody'])
            return new_issue
        except Exception as e:
            self.console(f'[ ! ] Error processing issue: {e}', 'red')
        return None

    @staticmethod
    def __new_issue():
        return {'issue_type': 'vulnerability',
                'vulnerability_type': 'Web',
                'scan_type': 'dynamic scan',
                'type': None,
                'severity': None,
                'confidence': 'moderate',
                'evidence': None,
                'parameters': None,
                'details': None,
                'description': 'Vulnerability detected by OWASP Zap',
                'url': None,
                'port': 443,
                'transport': 'tcp',
                'protocol': 'https',
                'attack': None,
                'cve': '',
                'cvss': '',
                'cvss string': '',
                'cwe': '',
                'wasc': '',
                'remediation': 'Not provided by ZAP',
                'references': None,
                'request': None,
                'response': None,
                'tool': 'zap'
                }

    @staticmethod
    def __issue_confidence(value):
        confidence_values = {'confirmed': 'confirmed', 'high': 'strong', 'medium': 'moderate', 'low': 'low',
                             'false positive': 'false positive'}
        if isinstance(value, str) and value.lower() in confidence_values:
            return confidence_values[value.lower()]
        return ''

    @staticmethod
    def __issue_evidence(issue):
        evidence = ''
        if issue['method'] != '':
            evidence = 'HTTP Method: {}\n'.format(issue['method'])
        if issue['evidence'] != '':
            evidence = '{}Evidence:\n{}\n'.format(evidence, issue['evidence'])
        if issue['other'] != '':
            evidence = '{}Other details:\n{}'.format(evidence, issue['other'])
        return evidence

    @staticmethod
    def is_valid_port(port):
        if not isinstance(port, int) or port < 1 > 65535:
            return False
        return True

    @staticmethod
    def is_valid_memory(memory):
        if memory not in [512, 1024, 2048, 4096]:
            return False
        return True

    @staticmethod
    def is_valid_zap_args(zap_args):
        if not isinstance(zap_args, str) and zap_args is not None:
            return False
        return True

    @staticmethod
    def is_valid_zap_path(zap_path):
        if not os.path.isfile(zap_path) or not os.path.exists(zap_path):
            return False
        return True

    @staticmethod
    def is_valid_max_time(max_time):
        if not isinstance(max_time, int) or max_time < 0 > 10000:
            return False
        return True

    @staticmethod
    def is_valid_rules_quality(rules_quality):
        if rules_quality not in ['release', 'beta', 'alpha']:
            return False
        return True

    @staticmethod
    def is_valid_confidence(confidence):
        if confidence not in ['confirmed', 'strong', 'moderate', 'low']:
            return False
        return True

    @staticmethod
    def is_valid_severity(severity):
        if not isinstance(severity, str) or severity.lower() not in ['critical', 'high', 'medium', 'low', 'informational']:
            return False
        return True

    def parse_url(self, url):
        res = {'protocol': '', 'port': 0, 'domain': '', 'location': '', 'querystring': '', 'service': ''}
        if not isinstance(url, str):
            return None
        if len(url) >= 2048:
            return None
        if url[:4] != 'http':
            res = None
        # Seems to be a URL
        if url[:7] == 'http://':
            res['domain'] = url[7:]
            res['protocol'] = 'http'
            res['service'] = 'http'
            res['port'] = '80'
        elif url[:8] == 'https://':
            res['domain'] = url[8:]
            res['protocol'] = 'https'
            res['service'] = 'https'
            res['port'] = '443'
        if '/' in res['domain']:
            t = str(res['domain']).split('/', 1)
            res['location'] = t[1]
            res['domain'] = t[0]
        if '?' in res['location']:
            t = str(res['location']).split('?', 1)
            res['querystring'] = t[1]
            res['location'] = t[0]
        if ':' in res['domain']:
            t = str(res['domain']).split(':')
            res['port'] = t[1]
            if not self.is_valid_port(res['port']):
                return None
            res['domain'] = t[0]
        if res['port'] == '80' and res['protocol'] == 'http':
            res['base_url'] = 'http://{}/'.format(res['domain'])
        elif res['port'] == '443' and res['protocol'] == 'https':
            res['base_url'] = 'https://{}/'.format(res['domain'])
        else:
            res['base_url'] = '{}://{}:{}/'.format(res['protocol'], res['domain'], res['port'])
        if not str(res['base_url']).endswith('/'):
            res['base_url'] = '{}/'.format(res['base_url'])
        res['ext'] = ''
        if '.' in res["location"]:
            i = str(res['location']).rfind('.')
            res['ext'] = str(res['location'])[i + 1:]
        if res['domain'] == '':
            return None
        return res

    def run_shell_command(self, cmd):
        self.port_blocked = False
        try:
            self.zap_process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            # Poll process for new output until finished
            zap_loaded = False
            while True:
                nextline = str(self.zap_process.stdout.readline())
                txt = nextline[2:]
                txt = txt[:len(txt)-1]
                txt = txt.replace('\\n', '').replace('\\r', '').replace('\\t', '')
                txt = txt.replace('\n', '').replace('\r', '').replace('\t', '').strip(' ')
                if txt != '':
                    self.console(f'[ ! ] {txt}', 'orange')
                    if 'ZAP is now listening' in txt and self.daemon_mode:
                        zap_loaded = True
                        t1 = threading.Thread(target=self.process_monitor)
                        t1.start()
                        break
                    if 'org.parosproxy.paros.control.Control - Create and Open Untitled Db' in txt and not self.daemon_mode:
                        zap_loaded = True
                        t1 = threading.Thread(target=self.process_monitor)
                        t1.start()
                        break
                    elif 'Cannot listen on port' in txt:
                        self.console('[ X ] The port specified is probably being used by another application', 'red')
                        self.port_blocked = True
                        return False
                if txt == '' and self.zap_process.poll() is not None:
                    break
                sys.stdout.flush()
            return zap_loaded
        except Exception as e:
            self.console(f'[ X ] Error running zap command: {e}', 'red')
            return False

    def process_monitor(self):
        last_txt = ''
        while True:
            if self.zap_process is None:
                break
            nextline = str(self.zap_process.stdout.readline())
            if nextline == '' and self.zap_process.poll() is not None:
                break
            txt = nextline.replace('b\'', '').replace('\\n', '').replace('\\r', '').replace('\'', '').replace("\n", "")
            txt = txt.replace('\n', '').replace('\r', '').strip(' ')
            if txt != '' and txt != last_txt:
                self.console(f'[ ! ] {txt}', "orange")
                last_txt = txt
            if '[ZAP-Shutdown]' in txt:
                self.zap_process = None
                break

    @staticmethod
    def gen_token(length=20):
        ext = token_urlsafe(nbytes=length)
        return ext

if __name__ == '__main__':
    try:
        requirement_list = requirements()
        for requirement in requirement_list:
            if requirement['name'] == 'url':
                requirement['value'] = 'http://dev.zirkul.internal'
        script_results = run(requirement_list)
        if isinstance(script_results, dict) and script_results['status'] != 'error':
            print(script_results)
        else:
            print("[ X ] ZAP didn't started correctly, make sure ZAP is installed and the executable path is correct")
    except Exception as script_exception:
        print("[ X ] Error: " + str(script_exception))
