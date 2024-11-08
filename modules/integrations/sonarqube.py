#!/usr/bin/python
"""
[properties]
@version: 1.7
@author: Mario Robles
@name: SonarQube
@id: sonarqube
@description: SonarQube integration for Static Analysis
@syntax: load sonarqube
@type: integration
@impact: safe
@service: http
@return_type: vuln
[properties]
type = [function,exploit,integration,tool]
impact = [safe,intrusive,dos]
service = [ssh,ftp,smtp,pop,imap,web,http,https,smb,tcp-##,udp-##]
return_type = [vuln,asset,boolean,null]
"""

import subprocess, re, platform, sys, time, os, requests, math
from requests import Response

try:
    from bs4 import BeautifulSoup
except ImportError as import_error:
    print("[ X ] Missing libraries need to be installed: " + str(import_error))


# Module Integration
mod_requirements = [{'name': 'project', 'description': 'Project name', 'type': 'string', 'required': True,
                     'value': None},
                    {'name': 'technology', 'description': 'Main technology or language included in the payload',
                     'type': ['java', 'python', 'php', 'javascript', '.net'], 'required': False, 'value': None},
                    {'name': 'sonar_url',
                     'description': 'SonarQube URL for uploading the results',
                     'type': 'url', 'required': True, 'value': None},
                    {'name': 'sonar_path',
                     'description': 'Full path to the sonar-scanner or sonar-scanner.bat file',
                     'type': 'directory', 'required': False, 'value': None},
                    {'name': 'project_key',
                     'description': 'Project identifier',
                     'type': 'string', 'required': False, 'value': "def"},
                    {'name': 'auth_token',
                     'description': 'Token used for connecting to SonarQube',
                     'type': 'string', 'required': False, 'value': None},
                    {'name': 'base_dir',
                     'description': 'Full path to the project repository files',
                     'type': 'string', 'required': False, 'value': None},
                    {'name': 'src_path',
                     'description': 'Relative path inside base_dir where the source files can be found',
                     'type': 'string', 'required': False, 'value': None},
                    {'name': 'bin_path',
                     'description': 'Relative path inside base_dir where the binary files can be found',
                     'type': 'string', 'required': False, 'value': None},
                    {'name': 'test_path',
                     'description': 'Relative path inside base_dir where the unit tests can be found',
                     'type': 'string', 'required': False, 'value': None},
                    {'name': 'action', 'description': "Action : 'run_scan_locally', 'pull_results_from_server'",
                     'type': ['run_scan_locally', 'pull_results_from_server'], 'required': False, 'value': None},
                    {'name': 'branch', 'description': 'Branch name', 'type': 'string', 'required': False, 'value': None},
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
    sonar_integration = SonarQubeIntegration()
    try:
        config = parse_reqs(reqs)
        if config is None:
            return {'description': 'Errors found in the data provided', 'status': 'error'}
        if 'console' in config.keys():
            sonar_integration.console = config['console']
        sonar_integration.console("[ ! ] SonarQube integration loaded", 'green')
        result = sonar_integration.run_scan(config)
        gate: dict = sonar_integration.security_gate()
        if not isinstance(result, list):
            sonar_integration.console(f'[ ! ] {result}', "red")
            return {'description': result, 'status': 'error'}
        if not isinstance(gate, dict):
            sonar_integration.console(f'[ ! ] {gate}', "red")
            return {'description': gate, 'status': 'error'}
        sonar_integration.console("[ ! ] SonarQube process completed: {} issues found".format(len(result)), "green")
        sonar_integration.console("[ ! ] Security Gate Result: {}".format(gate.get("security_gate_result")), "green")
        return {'results': result, 'status': True, "security_gate_result": gate.get("security_gate_result")}
    except Exception as e:
        sonar_integration.console(f'[ X ] Error: {e}', 'red')
        return {'description': f'Error: {e}', 'status': 'error'}
# Module Integration

class SonarQubeIntegration:
    def __init__(self):
        self.console = self.terminal_console
        self.project_name = None
        self.project_key = None
        self.sonar_path = None
        self.technology = None
        self.sonar_url = None
        self.base_dir = None
        self.source_path = None
        self.binaries_path = None
        self.tests_path = None
        self.auth_token = None
        self.action = None
        self.sonar_rules = dict()
        self.sources = dict()
        self.branch: str | None = None

    @staticmethod
    def terminal_console(txt, col=''):
        if col == '':
            print(txt, col)
        else:
            print(txt)

    def run_scan(self, config):
        if not self.load_config(config):
            return 'There are errors in the configuration'
        if self.action == 'run_scan_locally' and not self.run_scan_locally():
            self.console('[ X ] Process aborted')
            return 'Local scan process completed with errors'
        issues = self.download_issues()
        if issues is None:
            return 'No issues downloaded'
        issues = self.translate_issues_to_vulns(issues)
        return issues

    def security_gate(self) -> dict:
        the_url: str = "{}/api/project_branches/list?project={}&format=json".format(self.sonar_url,
                                                                                    self.project_name)
        search_branch: str = "master" if not self.branch else self.branch
        try:
            response: Response = requests.get(the_url, auth=(self.auth_token, ""), verify=False)
            if response.status_code != 200:
                self.console("[ X ] Unable to download branches from SonarQube", "red")
                return dict()
            json_data: dict = response.json()
            cache: dict = {}
            for i in json_data.get("branches"):
                if i.get("name") != search_branch:
                    continue
                t_status = i.get("status")
                if isinstance(t_status, dict) and t_status.get("qualityGateStatus"):
                    cache["security_gate_result"] = t_status.get("qualityGateStatus")
                    break
            return cache
        except requests.exceptions.RequestException:
            self.console("[ X ] Server not responding", "red")
            return {}
        except Exception as e:
            self.console("[ X ] Error: {0}".format(e), "red")
            return {}

    def load_config(self, config):
        required = ['project', 'sonar_url']
        for r in required:
            if r not in config.keys():
                self.console(f'[ X ] {r} is required')
                return False
        self.parse_config(config)
        if not self.test_url(self.sonar_url):
            self.console('[ X ] Error: sonar_url is unreachable')
            return False
        if self.action not in ['run_scan_locally', 'pull_results_from_server']:
            self.console(f'[ X ] Error: action is not valid: {self.action}')
            return False
        if self.action == 'run_scan_locally':
            return self.__local_scan_validation()
        return True

    def __local_scan_validation(self):
        if not self.is_valid_file_path(self.sonar_path):
            self.console(
                f'[ X ] Error: sonar_path must be the full path for the sonar-scanner file: {self.sonar_path}')
            return False
        if platform.system() == "Windows" and not self.sonar_path.endswith('sonar-scanner.bat'):
            self.console(
                f'[ X ] Error: sonar_path must be the full path for the sonar-scanner.bat file: {self.sonar_path}')
            return False
        elif platform.system() in ["Darwin", 'Linux'] and not self.sonar_path.endswith('sonar-scanner'):
            self.console(
                f'[ X ] Error: sonar_path must be the full path for the sonar-scanner file: {self.sonar_path}')
            return False
        if not self.is_valid_folder_path(self.base_dir):
            self.console(f'[ X ] Error: base_dir not found: {self.base_dir}')
            return False
        if self.technology not in ['java', 'python', 'php', 'javascript', '.net']:
            self.console('[ X ] Error: technology is required for run_scan_locally')
            self.console('[ ! ] Technology allowed values: {}'.format(', '.join(self.technology)))
            return False
        return True

    def parse_config(self, config):
        if 'project' in config.keys():
            self.project_name = config['project']
        if 'project_key' in config.keys():
            self.project_key = config['project_key']
        if 'sonar_path' in config.keys():
            self.sonar_path = config['sonar_path']
        if 'technology' in config.keys():
            self.technology = config['technology']
        if 'sonar_url' in config.keys():
            self.sonar_url = config['sonar_url']
        if 'base_dir' in config.keys():
            self.base_dir = config['base_dir']
        if 'src_path' in config.keys():
            self.source_path = config['src_path']
        if 'bin_path' in config.keys():
            self.binaries_path = config['bin_path']
        if 'tests_path' in config.keys():
            self.tests_path = config['tests_path']
        if 'auth_token' in config.keys():
            self.auth_token = config['auth_token']
        if 'action' in config.keys():
            self.action = config['action']
        if 'branch' in config.keys():
            self.branch = config['branch']

    @staticmethod
    def is_valid_folder_path(folder_path):
        if not isinstance(folder_path, str) or not os.path.isdir(folder_path) or not os.path.exists(folder_path):
            return False
        return True

    @staticmethod
    def is_valid_file_path(file_path):
        if not isinstance(file_path, str) or not os.path.isfile(file_path) or not os.path.exists(file_path):
            return False
        return True

    def test_url(self, url):
        try:
            r = requests.get(url, verify=False)
            if r.status_code in [200, 302, 303]:
                return True
        except Exception as e:
            self.console(f'[ X ] Error connecting to {url}: {e}')
        return False

    def run_scan_locally(self):
        sonar_cmd = self.__build_sonar_command()
        cmd_result, cmd_log = self.run_shell_command(sonar_cmd, "EXECUTION SUCCESS", "EXECUTION FAILURE")
        if not cmd_result:
            for each_line in cmd_log.split("\n"):
                if "ERROR:" in each_line:
                    self.console("[ X ] {0}".format(each_line), "red")
            return False
        time.sleep(5)
        return True
        # Wait for Sonar to process the results, some errors faced due to "No results found" responses

    def __build_sonar_command(self):
        if not isinstance(self.sonar_path, str):
            return None
        self.__normalize_paths()
        url = f' -Dsonar.host.url={self.sonar_url}'
        technology = ''
        if self.technology not in [None, '']:
            technology = f' -Dsonar.language={self.technology}'
        project_name = ''
        if self.project_name is not None:
            project_name = f' "-Dsonar.projectName={self.project_name}"'
        project_key = ''
        if self.project_key is not None:
            project_key = f' -Dsonar.sourceEncoding=UTF-8 "-Dsonar.projectKey={self.project_key}"'
        sources = f' "-Dsonar.sources={self.source_path}"'
        binaries = ''
        if self.binaries_path is not None:
            binaries = f' "-Dsonar.java.binaries={self.binaries_path}"'
        base_dir = f' "-Dsonar.projectBaseDir={self.base_dir}"'
        auth_token = ''
        if self.auth_token is not None:
            auth_token = f' "-Dsonar.login={self.auth_token}" "-Dsonar.password="'

        sonar_args = f'{url}{technology}{project_name}{project_key}{sources}{binaries}{base_dir}{auth_token}'
        sonar_command = f'"{self.sonar_path}" scan -X {sonar_args}'
        return sonar_command

    def __normalize_paths(self):
        if platform.system() == 'Windows':
            self.base_dir = self.__normalize_windows_path(self.base_dir)
            self.source_path = self.__normalize_windows_path(self.source_path)
            self.binaries_path = self.__normalize_windows_path(self.binaries_path)
            return
        self.base_dir = self.__normalize_unix_path(self.base_dir)
        self.source_path = self.__normalize_unix_path(self.source_path)
        self.binaries_path = self.__normalize_unix_path(self.binaries_path)

    @staticmethod
    def __normalize_windows_path(current_path):
        new_path = current_path
        if current_path not in [None, '']:
            if not current_path.endswith('\\'):
                new_path = f'{current_path}\\'
            new_path = f'{new_path}\\'
        return new_path

    @staticmethod
    def __normalize_unix_path(current_path):
        new_path = current_path
        if current_path not in [None, ''] and not current_path.endswith('/'):
            new_path = f'{current_path}/'
        return new_path


    def translate_issues_to_vulns(self, issues_json):
        self.console("[ ! ] Translating issues into vulnerability format for Zirkul Server", "green")
        if not isinstance(issues_json, dict):
            return None
        if 'issues' not in issues_json.keys():
            return None
        if not isinstance(issues_json['issues'], list):
            return None
        vulns = []
        for issue in issues_json["issues"]:
            new_vuln = self.__new_issue()
            rule_key = None
            rule_data = None
            # Static settings
            new_vuln = self.__process_issue(issue, new_vuln)
            evidence = self.get_evidence(issue)
            if evidence not in [None, '']:
                new_vuln['evidence'] = evidence
            if 'rule' in issue.keys():
                rule_key = issue['rule']
            if rule_key is not None and new_vuln['issue_type'] == 'vulnerability':
                rule_data = self.get_rule_information(rule_key)
            if rule_data is None:
                self.console('[ ! ] Unable to get rule data', "orange")
            else:
                rule_data = rule_data['rule']
                rule_name, rule_desc, rule_details, rule_refs = self.__get_rule_attributes(new_vuln, rule_data)
                new_vuln['details'] = rule_details
                new_vuln['description'] = rule_desc
                if rule_name is not None:
                    new_vuln["type"] = rule_name.replace('Security - ', '')
                new_vuln['references'] = rule_refs
                new_vuln = self.__fill_out_from_systags(new_vuln, rule_data)
                new_vuln = self.__fill_out_from_other(new_vuln, issue)
            vulns.append(new_vuln)
        return vulns

    def __fill_out_from_systags(self, new_vuln, rule_data):
        if 'sysTags' in rule_data.keys():
            return new_vuln
        if not isinstance(rule_data["sysTags"], list):
            return new_vuln
        for tag in rule_data["sysTags"]:
            tag_text = "{}".format(tag)
            new_vuln = self.__fill_out_from_text(new_vuln, tag_text)
        return new_vuln

    def __fill_out_from_other(self, new_vuln, rule_data):
        new_vuln = self.__fill_out_from_dict(new_vuln, new_vuln)
        new_vuln = self.__fill_out_from_dict(new_vuln, rule_data)
        return new_vuln

    def __fill_out_from_dict(self, new_vuln, data):
        for k, v in data.items():
            if isinstance(data[k], str):
                new_vuln = self.__fill_out_from_text(new_vuln, v)
        return new_vuln

    def __fill_out_from_text(self, new_vuln, txt):
        cwe = self.find_cwe_in_txt(txt)
        cve = self.find_cve_in_txt(txt)
        wasc = self.find_wasc_in_txt(txt)
        owasp = self.find_owasp_in_txt(txt)
        if cwe is not None and new_vuln['cwe'] is None:
            new_vuln['cwe'] = cwe
        if cve is not None and new_vuln['cve'] is None:
            new_vuln['cve'] = cve
        if wasc is not None and new_vuln['wasc'] is None:
            new_vuln['wasc'] = wasc
        if owasp is not None and new_vuln['owasp'] is None:
            new_vuln['owasp'] = owasp
        return new_vuln

    def __get_rule_attributes(self, new_vuln, rule_data):
        rule_name = None
        rule_desc = 'Vulnerability found by SonarQube'
        rule_details = None
        rule_refs = None
        if 'name' in rule_data:
            rule_name = '{}'.format(rule_data['name'])
        if 'htmlDesc' in rule_data:
            rule_details = "{}".format(rule_data['htmlDesc']).strip()
            if '<a ' in rule_details:
                rule_refs = self.get_links(rule_details)
            rule_details = self.remove_tags(rule_details)
            rem_key = None
            if 'Solution:' in rule_details:
                rem_key = 'Solution:'
            if 'Countermeasures:' in rule_details:
                rem_key = 'Countermeasures:'
            if rem_key is not None:
                ini = rule_details.find(rem_key)
                fin = rule_details.find('Reference')
                if fin == -1:
                    fin = len(rule_desc) - ini
                new_vuln['remediation'] = rule_desc[ini:fin]
                rule_desc = rule_desc.replace(new_vuln['remediation'], '')
            if 'Vulnerable Code:' in rule_desc:
                ini = rule_desc.find("Vulnerable Code:")
                rule_details = rule_desc[ini:]
                rule_desc = rule_desc[0:ini]
        return rule_name, rule_desc, rule_details, rule_refs

    def __process_issue(self, issue, new_vuln):
        keys = [x.lower() for x in issue.keys()]
        if 'key' in keys:
            new_vuln['external id'] = issue['key']
        if 'message' in keys:
            new_vuln['remediation'] = issue['message']
        if 'component' in keys:
            new_vuln['file name'] = issue['component']
        if 'creationDate' in keys:
            new_vuln['introduced date'] = issue['creationDate']
        if 'updateDate' in keys:
            new_vuln['last found'] = issue['updateDate']
        if 'line' in keys:
            new_vuln['line of code'] = issue['line']
        if 'severity' in keys:
            new_vuln['severity'] = self.get_severity(issue['severity'])
        if 'type' in keys:
            new_vuln['vulnerability_type'] = 'Code'
            new_vuln['issue_type'] = self.get_type(issue['type'])
        return new_vuln

    @staticmethod
    def __new_issue():
        new_vuln = {'vulnerability_type': 'code',
                    'scan_type': 'static scan',
                    'type': None,
                    'severity': None,
                    'confidence': 'moderate',
                    'evidence': 'No evidence provided',
                    'description': None,
                    'details': None,
                    'file name': None,
                    'line of code': None,
                    'cve': None,
                    'cvss': None,
                    'cvss string': None,
                    'cwe': None,
                    'wasc': None,
                    'remediation': 'Not provided by SonarQube',
                    'references': None,
                    'tool': "sonarqube",
                    'external id': None,
                    'introduced date': None,
                    'last found': None
                    }
        return new_vuln

    def get_evidence(self, issue):
        evidence = ''
        loc = None
        file_key = None
        if 'line' in issue.keys():
            loc = issue['line']
        if 'component' in issue.keys():
            file_key = issue['component']
        if loc is not None and file_key is not None:
            evidence = self.__get_source(file_key, loc)
        if evidence not in [None, '']:
            return evidence
        evidence = self.get_evidence_from_issue(issue)
        if len(evidence) > 4095:
            evidence = evidence[:4095]
        return evidence

    def get_evidence_from_issue(self, issue):
        evidence_data = ["key", "rule", "project", "effort", "creationDate", "updateDate", "author", "line"]
        evidence = ''
        for ev_key in evidence_data:
            if ev_key in list(issue.keys()):
                try:
                    data = issue[ev_key]
                    if data != '':
                        evidence = f'{evidence}\n{ev_key}: {data}' if evidence != '' else f'{ev_key}: {data}'
                except Exception as err:
                    self.console("Error: {}".format(err))
        return evidence


    @staticmethod
    def get_type(value):
        value = str(value).lower()
        response = {'code_smell': 'code Smell',
                    'bug': 'bug',
                    'vulnerability': 'vulnerability',
                    }
        if value in response.keys():
            return response[value]
        return ''


    @staticmethod
    def get_severity(value):
        response = {'BLOCKER': 'Critical',
                    'CRITICAL': 'High',
                    'MAJOR': 'Medium',
                    'MINOR': 'Low',
                    'INFO': 'Informational'}
        if value in response.keys():
            return response[value]
        return 'Informational'


    @staticmethod
    def get_status(value):
        response = {'OPEN': 'Backlog',
                    'CONFIRMED': 'Backlog',
                    'REOPENED': 'Reopened',
                    'RESOLVED': 'Closed',
                    'CLOSED': 'Closed',
                    'TO_REVIEW': 'Backlog',
                    'IN_REVIEW': 'Backlog',
                    'REVIEWED': 'Backlog'
                    }
        if value in response.keys():
            return response[value]
        return 'Backlog'

    @staticmethod
    def find_owasp_in_txt(search_in):
        txt = search_in.lower()
        patterns = ['owasp-a', 'owasp:a', 'owasp_a', 'owasp a',
                    'owasp-api', 'owasp:api', 'owasp_api', 'owasp api',
                    'owasp-m', 'owasp:m', 'owasp_m', 'owasp m']
        ini = -1
        for pattern in patterns:
            ini = txt.find(pattern)
            if ini != -1:
                break
        owasp_id = ""
        if ini != -1:
            patterns = ['a10', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'a1',
                        'a10', 'a02', 'a03', 'a04', 'a05', 'a06', 'a07', 'a08', 'a09', 'a01',
                        'api10', 'api2', 'api3', 'api4', 'api5', 'api6', 'api7', 'api8', 'api9', 'api1',
                        'm10', 'm2', 'm3', 'm4', 'm5', 'm6', 'm7', 'm8', 'm9', 'm1']
            txt = txt.replace(" ", "").replace("-", "").replace(":", "")
            for pattern in patterns:
                match = txt.find(pattern)
                if match != -1:
                    owasp_id = pattern
                    break
            patterns = ['2003', '2007', '2010', '2013', '2016', '2017', '2019', '2021', '2023']
            for pattern in patterns:
                match = txt.find(pattern)
                if match != -1:
                    owasp_id = "{}:{}".format(pattern, owasp_id)
                    break
        if owasp_id != "":
            owasp_id = owasp_id.replace(" ", "")
            return str(owasp_id).upper()
        return None

    @staticmethod
    def find_cwe_in_txt(search_in):
        try:
            if not isinstance(search_in, str) or len(search_in) < 5:
                return None
            txt = search_in.lower().replace(' ', '')
            ini = txt.find('cwe-')
            cwe_id = ''
            if ini != -1:
                cwe_done = False
                while not cwe_done:
                    character = txt[ini]
                    if character in 'cwe - 1234567890':
                        cwe_id = f'{cwe_id}{character}'
                        ini += 1
                        if ini >= len(txt):
                            cwe_done = True
                    else:
                        cwe_done = True
            if cwe_id != '':
                cwe_id = cwe_id.replace(' ', '')
                return str(cwe_id).upper()
        except Exception as e:
            return None
        return None

    @staticmethod
    def find_cve_in_txt(search_in):
        try:
            if not isinstance(search_in, str) or len(search_in) < 5:
                return None
            txt = search_in.lower().replace(" ", "")
            ini = txt.find("cve-")
            cve_id = ""
            if ini != -1:
                cve_done = False
                while not cve_done:
                    character = txt[ini]
                    if character in "cve - 1234567890":
                        cve_id = "{0}{1}".format(cve_id, character)
                        ini += 1
                        if ini >= len(txt):
                            cve_done = True
                    else:
                        cve_done = True
            if cve_id != "":
                cve_id = cve_id.replace(" ", "")
                return str(cve_id).upper()
        except Exception as e:
            return None
        return None

    @staticmethod
    def find_wasc_in_txt(search_in):
        try:
            if not isinstance(search_in, str) or len(search_in) < 5:
                return None
            txt = search_in.lower().replace(" ", "")
            ini = txt.find("wasc-")
            wasc_id = ""
            if ini != -1:
                wasc_done = False
                while not wasc_done:
                    character = txt[ini]
                    if character in "wasc - 1234567890":
                        wasc_id = "{0}{1}".format(wasc_id, character)
                        ini += 1
                        if ini >= len(txt):
                            wasc_done = True
                    else:
                        wasc_done = True
            if wasc_id != "":
                wasc_id = wasc_id.replace(" ", "")
                return str(wasc_id).upper()
        except Exception as e:
            return None
        return None


    @staticmethod
    def get_links(html_page):
        soup = BeautifulSoup(html_page, features="html.parser")
        links = []
        for link in soup.findAll('a', attrs={'href': re.compile("^http://")}):
            links.append({"title": link.text, "url": link.get('href')})
        for link in soup.findAll('a', attrs={'href': re.compile("^https://")}):
            links.append({"title": link.text, "url": link.get('href')})
        return links


    @staticmethod
    def remove_tags(text):
        tag_re = re.compile(r'<[^>]+>')
        return tag_re.sub('', text)


    def get_rule_information(self, rule_key):
        the_url = '{}/api/rules/show?key={}'.format(self.sonar_url, rule_key)
        completed = False
        cont = 0
        if rule_key in self.sonar_rules.keys():
            return self.sonar_rules[rule_key]
        while not completed:
            try:
                self.console(f"[ + ] Downloading rule information from the API: {rule_key}", "green")
                if self.auth_token is not None:
                    response = requests.get(the_url, auth=(self.auth_token, ""), verify=False)
                else:
                    response = requests.get(the_url, verify=False)
                if response.status_code == 200:
                    json_data = response.json()
                    self.sonar_rules[rule_key] = json_data
                    return json_data
                else:
                    self.console("[ X ] Unable to download rule information from SonarQube", "red")
                    return None
            except requests.exceptions.RequestException:
                self.console("[ X ] Server not responding, retrying in 5 seconds", "red")
                time.sleep(5)
            except Exception as e:
                self.console("[ X ] Error: {0}".format(e), "red")
                completed = True
            cont += 1
            if cont > 5:
                completed = True
        self.console("[ X ] Unable to download rule information from SonarQube", "red")
        return None


    def download_issues(self):
        the_url = '{}/api/issues/search?componentKeys={}&format=json&types=VULNERABILITY'.format(self.sonar_url,
                                                                                                 self.project_key)
        if self.branch is not None:
            the_url = f'{the_url}&branch={self.branch}'
        completed = False
        cont = 0
        while not completed:
            try:
                self.console("[ + ] Downloading results from the API", "green")
                if self.auth_token is not None:
                    response = requests.get(the_url, auth=(self.auth_token, ""), verify=False)
                else:
                    response = requests.get(the_url, verify=False)
                if response.status_code == 200:
                    json_data = response.json()
                    issues_per_page = 0
                    total = 0

                    if "ps" in json_data:
                        issues_per_page = int(json_data["ps"])
                    if "total" in json_data:
                        total = int(json_data["total"])
                    pages = math.ceil(total / issues_per_page) if total > issues_per_page else 1
                    if total <= issues_per_page:
                        self.console("[ + ] Results downloaded successfully", "green")
                        completed = True
                        return json_data
                    elif total == 0:
                        self.console("[ X ] No issues returned from SonarQube", "red")
                        return None
                    else:
                        completed = True
                        self.console("[ ! ] Total issues found: {0} in {1} pages".format(total, pages), "green")
                        self.console("[ ! ] Downloading additional pages", "green")
                        if pages > 20:
                            self.console("[ ! ] This is going to take a while", "green")
                        for page in range(2, pages + 1):
                            self.console("[ ! ] Page: {} of {}".format(page, pages), "green")
                            next_url = "{}&pageIndex={}".format(the_url, page)
                            if self.auth_token is not None:
                                next_response = requests.get(next_url, auth=(self.auth_token, ""), verify=False)
                            else:
                                next_response = requests.get(next_url, verify=False)

                            timeout_counter = 0
                            while next_response.status_code != 200:
                                self.console("[ ! ] Retrying in 5 seconds", "orange")
                                time.sleep(5)
                                if self.auth_token is not None:
                                    next_response = requests.get(next_url, auth=(self.auth_token, ""), verify=False)
                                else:
                                    next_response = requests.get(next_url, verify=False)
                                timeout_counter += 1
                                if timeout_counter > 5:
                                    break
                            if next_response.status_code == 200:
                                new_issues = next_response.json()
                                if new_issues is not None and "issues" in new_issues:
                                    for new_issue in new_issues["issues"]:
                                        json_data["issues"].append(new_issue)
                            else:
                                self.console("[ X ] Unexpected response from server, process aborted", "red")
                                return None

                        self.console("[ ! ] {} issues downloaded".format(len(json_data['issues'])), "green")
                        return json_data
                else:
                    self.console("[ X ] Unable to download the issues from SonarQube", "red")
                    return None
            except requests.exceptions.RequestException:
                self.console("[ X ] Server not responding, retrying in 5 seconds", "red")
                time.sleep(5)
            except Exception as e:
                self.console("[ X ] Error: {0}".format(e), "red")
                completed = True
            cont += 1
            if cont > 5:
                completed = True
        self.console("[ X ] Unable to download the issues from SonarQube", "red")
        return None

    def __get_source(self, file_key, loc):
        the_url = f'{self.sonar_url}/api/sources/raw?key={file_key}'
        evidence = ''
        try:
            txt = ''
            if file_key in self.sources.keys():
                txt = self.sources[file_key]
            else:
                self.console("[ + ] Downloading source evidence from the API", "green")
                if self.auth_token is not None:
                    response = requests.get(the_url, auth=(self.auth_token, ""), verify=False)
                else:
                    response = requests.get(the_url, verify=False)
                if response.status_code == 200:
                    txt = response.text
            self.sources[file_key] = txt
            if txt == '':
                return None
            lines = txt.split('\n')
            c = 1
            for line in lines:
                if c > loc-5 < loc+5:
                    current_line = ''
                    if loc == c:
                        current_line = '>>'
                    evidence = '{}\n{} {} {}'.format(evidence, c, current_line, line)
                if c > loc + 5:
                    break
                c += 1
            return evidence
        except requests.exceptions.RequestException:
            self.console("[ X ] Server not responding", "red")
        except Exception as e:
            self.console("[ X ] Error: {0}".format(e), "red")
        return None

    def run_shell_command(self, cmd, good_msg, bad_msg):
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        # Poll process for new output until finished
        result = False
        response = ""
        while True:
            nextline = str(process.stdout.readline())
            txt = nextline[2:]
            txt = txt[:len(txt) - 1]
            txt = txt.replace('\\n', '').replace('\\r', '').replace('\\t', '')
            txt = txt.replace('\n', '').replace('\r', '').replace('\t', '').strip(' ')
            if txt != "":
                self.console(f'[ ! ] {txt}', "orange")
                response = "{0}\n{1}".format(response, txt)
                if good_msg in txt:
                    result = True
                elif bad_msg in txt:
                    result = False
            if txt == '' and process.poll() is not None:
                break
            sys.stdout.flush()
        return result, response


    @staticmethod
    def run_raw_shell_command(cmd):
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        response = ""
        # Poll process for new output until finished
        while True:
            nextline = str(process.stdout.readline())
            if nextline == '' and process.poll() is not None:
                break
            txt = nextline[2:]
            txt = txt[:len(txt) - 1]
            txt = txt.replace('\\n', '').replace('\\r', '').replace('\\t', '')
            txt = txt.replace('\n', '').replace('\r', '').replace('\t', '').strip(' ')
            if txt != "":
                response = "{0}\n{1}".format(response, txt)
            sys.stdout.flush()
        return response
