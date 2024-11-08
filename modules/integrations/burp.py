#!/usr/bin/env python

"""
[properties]
@version: 1.2
@author: Mario Robles
@name: BurpSuite
@id: burp
@description: BurpSuite integration for Dynamic automated scanning
@syntax: load burp
@type: integration
@impact: intrusive
@service: http
@return_type: vuln
[properties]
"""

try:
    import requests
    import json
    import argparse
    import subprocess
    import sys
    import re
    import platform
    import os
    import signal
    import base64

    from time import sleep as sleep
    from bs4 import BeautifulSoup
except ImportError as err:
    requests = None
    json = None
    argparse = None
    subprocess = None
    sys = None
    re = None
    platform = None
    os = None
    signal = None
    base64 = None
    sleep = None
    BeautifulSoup = None
    print(f'[ X ] Missing libraries need to be installed: {err}')

__version__ = '1.2'


class BaseColors:
    WHITE = '\033[1;37m'
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    ORANGE = '\033[93m'
    RED = '\033[91m'
    YELLOW = '\033[1;33m'
    PURPLE = '\033[0;35m'
    ENDC = '\033[0m'
    BOLD = "\033[;1m"
    black = '\033[30m'
    red = '\033[31m'
    green = '\033[32m'
    orange = '\033[33m'
    blue = '\033[34m'
    purple = '\033[35m'
    cyan = '\033[36m'
    lightgrey = '\033[37m'
    darkgrey = '\033[90m'
    lightred = '\033[91m'
    lightgreen = '\033[92m'
    yellow = '\033[93m'
    lightblue = '\033[94m'
    pink = '\033[95m'
    lightcyan = '\033[96m'


def Print(txt, col=None):
    c_color = BaseColors.ENDC
    if col is None or platform.system() == 'Windows':
        print(txt)
        return
    elif col == 'red':
        c_color = BaseColors.RED
    elif col == 'green':
        c_color = BaseColors.GREEN
    elif col == 'orange':
        c_color = BaseColors.ORANGE
    elif col == 'blue':
        c_color = BaseColors.cyan
    print(f'{c_color}{txt}{BaseColors.ENDC}')


class Burp:
    def __init__(self):
        """
        Initializes the Burp class, set up the default values
        :return: None
        """
        self.process = None
        self.nocolor = None
        self.target = '127.0.0.1'
        self.port = 1337
        self.uri = None
        self.path = '/v0.1/'
        self.key = None
        self.username = None
        self.password = None
        self.issues = None
        self.issue_definitions = None
        self.taskid = None
        self.status = ''
        self.progress = None
        self.progress_caption = ''
        self.crawl_config = None
        self.audit_config = None
        self.__valid_config = False
        self.logs = []
        self.debug = False
        self.headless = True

    def setup(self, uri, api_key=None, username=None, password=None, burp_ip=None, port=None, crawl_config=None,
              audit_config=None, debug=False, headless=True, nocolor=False):
        """
        Setup with user supplied data
        :param uri:
        :param api_key:
        :param username:
        :param password:
        :param burp_ip:
        :param port:
        :param crawl_config:
        :param audit_config:
        :param debug:
        :param headless:
        :param nocolor:
        :return: Valid configuration value, False if some of the configuration values is incorrect
        """
        self.debug = debug
        self.headless = headless
        self.nocolor = nocolor
        if uri is None:
            self.log('URI is required', 'X')
            return False
        self.key = api_key
        if self.key is not None:
            self.path = f'/{api_key}/v0.1/'
        self.username = username
        self.password = password
        if burp_ip is not None:
            self.target = burp_ip
        if port is not None:
            self.port = port
        if crawl_config is not None:
            self.crawl_config = self.__load_json(crawl_config)
            if self.crawl_config is None or 'crawler' not in self.crawl_config.keys():
                self.log('The crawler configuration file is invalid', 'X')
                return False
        if audit_config is not None:
            self.audit_config = self.__load_json(audit_config)
            if self.audit_config is None or 'scanner' not in self.audit_config.keys():
                self.log('The crawler configuration file is invalid', 'X')
                return False
        self.path = 'http://{}:{}{}'.format(self.target, self.port, self.path)
        self.uri = uri
        self.__valid_config = self.verify_connection()
        return self.__valid_config

    def __load_json(self, filename):
        """
        This will load the provided file name as json object (dict)
        :param filename: JSON file to be loaded
        :return: Data obtained from json file, None in case of error
        """
        try:
            with open(filename) as json_file:
                data = json.load(json_file)
            return data
        except Exception as ex:
            self.log(f'Error reading json file: {ex}', 'X')
            return None

    def scan(self):
        """
        This will start the Burp Scan
        :return: True is scan start correctly, False otherwise
        """
        if not self.__valid_config:
            self.log('Valid setup is required', 'X')
            return False
        path = f'{self.path}{"scan"}'

        post = {'urls': [self.uri]}
        if self.username is not None and self.password is not None:
            self.log('This will be an authenticated scan', '!')
            post['application_logins'] = [{'password': self.password, 'username': self.username}]

        if self.audit_config is not None or self.crawl_config is not None:
            scan_config = []
            if self.audit_config is not None:
                self.log('Using custom audit settings', '!')
                scan_config.append({'config': json.dumps(self.audit_config), 'type': 'CustomConfiguration'})
            if self.crawl_config is not None:
                self.log('Using custom crawling settings', '!')
                scan_config.append({'config': json.dumps(self.crawl_config), 'type': 'CustomConfiguration'})
            post['scan_configurations'] = scan_config
        self.log(f'Requesting scan: {self.uri}', '!')
        response = requests.post(url=path, json=post)
        if response.status_code == 201:
            self.taskid = int(response.headers['location'])
            self.log(f'Successfully initiated task_id: {response.headers["location"]}', '!')
            return True
        else:
            self.log(f'Error launching scan against {self.uri}', 'X')
            self.taskid = None
            return False

    def pull_issues(self, task_id):
        """
        This will pull the issues from Burp for a specific task
        :param task_id: Identifier of the Burp process
        :return: True if
        """
        if not self.__valid_config:
            self.log('Valid setup is required', 'X')
            return None
        path = f'{self.path}scan/{task_id}'
        response = requests.get(url=path)
        if response.status_code != 200:
            self.log(f'Unable to pull results from Burp task: {task_id}', 'X')
            self.log('Keep in mind Burp pro allows access for tasks generated from the API only', 'X')
            return False
        progress = json.loads(response.text)
        if progress['scan_status'] == 'failed':
            self.log('Cannot pull results from failed tasks', "!")
            return False
        if self.issues is None:
            self.issues = list()
        self.log(f'Pulling results from task: {task_id}', '!')
        for issue in progress['issue_events']:
            self.issues.append(issue['issue'])
        self.log('Process completed', '!')
        return True

    def scan_completed(self):
        """
        This will check for the status of the current scan running, once completed it will gather the results into
        the issues variable
        :return: True if scan completed successfully, False otherwise
        """
        if not self.__valid_config:
            self.log('Valid setup is required', 'X')
            return None
        path = f'{self.path}scan/{self.taskid}'
        response = requests.get(url=path)
        progress = json.loads(response.text)
        completion = 0
        progress_caption = ''
        if 'scan_metrics' in progress.keys():
            if 'crawl_and_audit_progress' in progress['scan_metrics']:
                completion = progress['scan_metrics']['crawl_and_audit_progress']
            if 'crawl_and_audit_caption' in progress['scan_metrics']:
                progress_caption = progress['scan_metrics']['crawl_and_audit_caption']
        if self.status != progress['scan_status'] or self.progress != completion:
            self.log(f'Status: {progress["scan_status"]} - {completion}%', '!')
        if self.progress_caption != progress_caption:
            self.log(progress_caption, '!')
        self.status = progress['scan_status']
        self.progress = completion
        self.progress_caption = progress_caption
        if self.status == 'succeeded':
            if self.issues is None:
                self.issues = []
            self.log('Pulling results from the main scan', '!')
            self.pull_issues(self.taskid)
            # This is more like a hack since Burp is not letting us know that there was another scan task created
            # for issues detected by Extensions using an ID right next to the one created here
            # self.pull_issues(self.taskid + 1)
            self.log('Scan completed', '!')
            return True
        elif self.status == 'failed':
            self.log('Scan failed, there\'s nothing to report', 'X')
            return True
        elif self.status == 'paused':
            self.log('Scan paused, most likely because of errors detected during the scan', 'X')
            return True
        else:
            return False

    def pull_issue_definitions(self):
        """
        This will download the issue definitions from Burp
        :return: None
        """
        if not self.__valid_config:
            self.log('Valid setup is required', 'X')
            return None
        path = f'{self.path}/knowledge_base/issue_definitions'
        response = requests.get(url=path)
        self.issue_definitions = json.loads(response.text)

    def get_issues(self):
        """
        This will pull the issues from recent scan
        :return: Issues
        """
        self.pull_issue_definitions()
        if self.issues is not None and self.issue_definitions is not None:
            self.log(f'Issues found: {len(self.issues)}', '!')
            self.__prepare_issues()
            self.__translate_issues_to_zirkul_format()
            self.print_scan_summary()
        return self.issues

    def __translate_issues_to_zirkul_format(self):
        """
        Create the issue list to be sent to Zirkul
        return: None
        """
        zirkul_issues = []
        for issue in self.issues:
            new_issue = Burp.__issue()
            new_issue['tool'] = 'burp'
            new_issue['issue_type'] = 'vulnerability'
            new_issue['type'] = Burp.__issue_attribute_if_not_none(issue, 'name')
            new_issue['url'] = self.uri
            new_issue['severity'] = Burp.__issue_attribute_if_not_none(issue, 'severity')
            new_issue['cvss'] = Burp.__get_cvss_score(new_issue['severity'])
            confidence = Burp.__issue_attribute_if_not_none(issue, 'confidence')
            if confidence not in [None, '']:
                new_issue['confidence'] = Burp.__issue_confidence(confidence)

            # Start analysis of evidence field
            new_issue = Burp.analyze_evidence(issue, new_issue)

            description = Burp.__issue_attribute_if_not_none(issue, 'description')
            new_issue['description'] = Burp.__remove_tags(description)
            details = Burp.__issue_attribute_if_not_none(issue, 'issue_background')
            new_issue['details'] = Burp.__remove_tags(details)
            if new_issue['details'] in ['', None]:
                new_issue['details'] = 'Vulnerability detected by Burp Suite'
            new_issue['port'] = None
            new_issue['transport'] = None
            new_issue['protocol'] = 'http'
            new_issue['attack'] = Burp.__issue_attribute_if_not_none(issue, 'path')
            new_issue['cve'] = None
            new_issue['cvss_string'] = None
            new_issue['cwe'] = None
            if 'vulnerability_classifications' in issue.keys():
                new_issue['cwe'] = Burp.__find_cwe(issue['vulnerability_classifications'])
            new_issue['wasc'] = None
            if 'remediation' in issue.keys() or 'remediation_background' in issue.keys():
                remediation = Burp.__issue_attribute_if_not_none(issue, 'remediation', as_str=True)
                remediation = Burp.__remove_tags(remediation)
                remediation_background = Burp.__issue_attribute_if_not_none(issue,
                                                                            'remediation_background', as_str=True)
                remediation_background = Burp.__remove_tags(remediation_background)
                if remediation_background != remediation:
                    remediation = f'{remediation}\n{remediation_background}'
                new_issue['remediation'] = remediation
            new_issue['screenshot'] = None
            if 'references' in issue.keys():
                references = Burp.__issue_attribute_if_not_none(issue, 'references', as_str=True)
                new_issue['references'] = Burp.__get_links(references)
            new_issue['Proof of concept'] = '''
            1. Go to the URL using a tool such as Burp or OWASP ZAP
            2. In the browsing history from the tool, find the record for the URL
            3. In the "Response" section, validate the conditions provided in the evidence
            '''
            zirkul_issues.append(new_issue)
        self.issues = zirkul_issues

    @classmethod
    def analyze_evidence(cls, issue, new_issue):
        """
        Do analysis of evidence field
        :param issue: Burp issue
        :param new_issue: New issue translated to zirkul format
        :return: New issue with new fields
        """
        no_evidence_message = 'The scanner didn\'t provided evidence for this issues, manual validation is required' \
                              'for confirming it\'s accuracy'
        new_issue['evidence'] = ''

        if len(issue['evidence']) > 0:
            if 'request_response' in issue['evidence'][0].keys():
                new_issue = Burp.process_request_response(issue, new_issue)
        else:
            new_issue['confidence'] = 'Moderate'
            new_issue['evidence'] = no_evidence_message
            new_issue['request'] = no_evidence_message
            new_issue['response'] = no_evidence_message

        return new_issue

    @classmethod
    def process_request_response(cls, issue, new_issue):
        """
        Process the field request response to generate url, request and response
        :param issue: Burp issue
        :param new_issue: New issue translated to zirkul format
        :return: New issue with new fields
        """
        # Start getting url
        new_issue['url'] = issue['evidence'][0]['request_response']['url']
        # Start getting request
        request = ''
        for value in issue['evidence'][0]['request_response']['request']:
            if value['type'] == 'DataSegment':
                request = f'{request}{Burp.__decode_base64_text(value["data"])}'
        new_issue['request'] = request
        # Start getting response
        response = ''
        for value in issue['evidence'][0]['request_response']['response']:
            if value['type'] == 'DataSegment':
                response = f'{response}{Burp.__decode_base64_text(value["data"])}'
        new_issue['response'] = response

        return new_issue

    @classmethod
    def __issue_confidence(cls, value):
        """
        Check if value correspond to a valid confidence value
        :param value: Confidence value to be evaluated
        :return: Confidence value evaluated, empty string otherwise
        """
        confidence_values = {'certain': 'Confirmed', 'firm': 'Strong', 'tentative': 'Moderate'}
        if isinstance(value, str) and value.lower() in confidence_values:
            return confidence_values[value]
        return ''

    @classmethod
    def __issue_attribute_if_not_none(cls, issue, key, as_str=False):
        """
        Check if attribute (key) is not none
        :param issue: Issue dictionary
        :param key: Value to find
        :param as_str: If True return empty string
        :return: Issue attribute to be found, or empty string if as_str parameter is True
        """
        if isinstance(issue, dict) and key in issue.keys():
            return issue[key]
        if as_str:
            return ''

    @classmethod
    def __get_cvss_score(cls, severity):
        """
        Accordingly with the severity, returns the cvss score
        :param severity: Severity to be analyzed
        :return: CVSS score
        """
        score = 0.0
        if severity.lower() == 'low':
            # Low: 0.1 - 3.9
            score = 1.9
        elif severity.lower() == 'medium':
            # Medium: 4.0 - 6.9
            score = 5.4
        elif severity.lower() == 'high':
            # High: 7.0 - 8.9
            score = 7.9
        elif severity.lower() == 'critical':
            # Critical: 9.0 - 10.0
            score = 9.5

        return score

    @classmethod
    def __get_links(cls, text):
        """
        Obtain http or https links from a text
        :param text: Text where links will be found
        :return: List with links found
        """
        soup = BeautifulSoup(text, features="html.parser")
        links = []
        for link in soup.findAll('a', attrs={'href': re.compile("^http://")}):
            links.append({"title": link.text, "url": link.get('href')})
        for link in soup.findAll('a', attrs={'href': re.compile("^https://")}):
            links.append({"title": link.text, "url": link.get('href')})

        return links

    @classmethod
    def __remove_tags(cls, text):
        """
        Remove any html tag from text
        :param text: Text to remove tags
        :return: String without tags
        """
        tag_re = re.compile(r'<[^>]+>')

        return tag_re.sub('', text)

    @classmethod
    def __find_cwe(cls, text):
        """
        Subtract the cwe from a text
        :param text: Text to find a cwe
        :return: cwe value
        """
        txt = text.lower().replace(" ", "")
        ini = txt.find("cwe-")
        cwe_id = ""
        if ini != -1:
            cwe_done = False
            while not cwe_done:
                character = txt[ini]
                if character in "cwe - 1234567890":
                    cwe_id = "{0}{1}".format(cwe_id, character)
                    ini += 1
                    if ini > len(txt):
                        cwe_done = True
                else:
                    cwe_done = True
        if cwe_id != "":
            return cwe_id

        return None

    @classmethod
    def __decode_base64_text(cls, text):
        base64_bytes = text.encode('ascii')
        message = base64.b64decode(base64_bytes)
        message = message.decode('ascii')

        return message

    def __prepare_issues(self):
        """
        Add missing attributes from issue definition to the issue
        :return: None
        """
        i = 0
        for issue in self.issues:
            issue_def = self.get_issue_definition(issue)
            if issue_def is not None:
                for attribute in issue_def.keys():
                    if str(attribute) not in issue.keys():
                        self.issues[i][attribute] = str(issue_def[attribute])
            i += 1

    def get_issue_definition(self, issue):
        """
        From issue find the issue definition
        :param issue: Issue to find in issue definition
        :return: If found, issue definition, None otherwise
        """
        for issue_def in self.issue_definitions:
            if str(issue['type_index']) == str(issue_def['issue_type_id']):
                return issue_def
        return None

    def print_scan_summary(self):
        """
        console the quantity of issues found by severity
        :return: None
        """
        severities = self.get_issues_summary()
        for severity in severities.keys():
            self.log("      {}: {}".format(severity, severities[severity]))

    def get_issues_summary(self):
        """
        Calculate quantity of each severity
        :return: Dictionary with the severity quantities
        """
        severities = {'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        if self.issues is not None:
            for issue in self.issues:
                for severity in severities.keys():
                    if str(issue['severity']) == severity:
                        severities[severity] += 1
        return severities

    def verify_connection(self):
        """
        Check if the connection with Burp is valid including the URL, port and API Key provided
        :return: True if connection established, False otherwise
        """
        try:
            response = requests.get(url=self.path)
        except Exception as e:
            self.log(e, "X")
            self.log('  Unable to connect to Burp REST API', "X")
            self.log('  In Burp, go to: User options > Misc > REST API', "X")
            self.log('  Make sure the option "Service running" is enabled', "X")
            return False
        if response.status_code == 200:
            self.log("Connection successful", "!")
            return True
        elif response.status_code == 401:
            self.log("Unable to connect, make sure the API Key is valid and the URL or port are correct", "X")
            return False

    def start_burp(self, jar_path=None):
        """
        Start the Burp process
        :return: True is process started successfully, False otherwise
        """
        headless = str(self.headless).lower()
        cmd = f'java -Xmx4G -Djava.awt.headless={headless} -jar "{jar_path}" --diagnostics --unpause-spider-and-scanner'
        self.log('Starting Burp', '!')
        return self.run_jar(cmd)

    def stop_burp(self):
        """
        Stop the Burp process
        :return: None
        """
        if self.process is not None:
            self.log('Stopping Burp', '!')
            self.process.terminate()

    def run_jar(self, cmd):
        """
        Run burp jar file
        :param cmd: Command to be run
        :return: True if process ran correctly, False otherwise
        """
        self.process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        while True:
            nextline = str(self.process.stdout.readline())
            if nextline == '' and self.process.poll() is not None:
                break
            otxt = nextline.replace('b\'', '').replace('\\n', '').replace('\'', '')
            otxt = re.sub('[^0-9a-zA-Z\%\$\&\#\@\!\+\-\_\?\(\)\{\}\[\]<=>\.\,\'\":;\\\/\s]+', '', otxt)
            otxt = otxt.replace('\n', '')
            otxt = otxt.strip(' ')
            if otxt != '':
                self.log(otxt, '!')
                if 'Number of processors' in otxt:
                    sleep(5)
                    return True
                elif 'Failed to start proxy service' in otxt:
                    self.log('The port specified is probably being used by another application', 'X')
                    self.log('      Select another port in your configuration and try again')
                    return False
                elif 'Burp requires a license key' in otxt:
                    self.log('Burp Pro license is not activated', 'X')
                    return False
            sys.stdout.flush()
        return False

    def log(self, txt, level=''):
        """
        All activity will be stored in the variable 'log', if the variable debug is True, then the log entry will be
        displayed in the terminal
        :param txt: Value to be logged
        :param level: Level of the log
        :return: None
        """
        if self.debug:
            p = ''
            if level != '':
                p = f'[ {level} ]'
            if platform.system() == 'Windows' or self.nocolor:
                print(f'{p} {txt}')
            else:
                c_color = BaseColors.ENDC
                alert_color = {'!': BaseColors.ORANGE, '+': BaseColors.GREEN,
                               '-': BaseColors.ORANGE, 'X': BaseColors.RED}
                if level in alert_color.keys():
                    c_color = alert_color[level]
                print("{}{} {}".format(c_color, p, txt, BaseColors.ENDC))
        self.logs.append(txt)

    @classmethod
    def __issue(cls):
        """
        Create new empty issue
        :return: New issue
        """
        new_issue = {'vulnerability_type': 'web',
                     'type': None,
                     'scan_type': 'dynamic scan',
                     'severity': None,
                     'confidence': None,
                     'evidence': None,
                     'target': None,
                     'details': None,
                     'url': None,
                     'port': None,
                     'transport': 'tcp',
                     'protocol': 'http',
                     'attack': None,
                     'cve': '',
                     'cvss': '',
                     'cvss_string': '',
                     'cwe': None,
                     'wasc': None,
                     'screenshot': None,
                     'request': None,
                     'response': None,
                     'tool': 'burp'
                     }
        return new_issue


# Module Integration
mod_requirements = [
    {'name': 'url', 'description': 'URL Burp will be scanning', 'type': 'url', 'required': True, 'value': None},
    {'name': 'headless', 'description': 'Running Burp Pro in headless mode',
     'type': 'boolean', 'required': False, 'value': True},
    {'name': 'version', 'description': 'What Burp version is used: pro, ent',
     'type': ['pro', 'ent'], 'required': True, 'value': 'pro'},
    {'name': 'port', 'description': 'The port used for connecting to the API', 'type': 'port', 'required': False,
     'value': 1337},
    {'name': 'apikey', 'description': 'Setup a custom API key for connecting to Burp',
     'type': 'string', 'required': False, 'value': None},
    {'name': 'path', 'description': 'Custom path for locating the file burp.jar', 'type': 'string', 'required': False,
     'value': None},
    {'name': 'scantype',
     'description': 'What scan type do you want Burp to run (pull: Just pull the results): spider,active,full,pull',
     'type': ['spider', 'active', 'full', 'pull'], 'required': True, 'value': 'full'},
    {'name': 'ip', 'description': 'Burp IP, defaults to 127.0.0.1', 'type': 'ip', 'required': False,
     'value': '127.0.0.1'},
    {'name': 'task', 'description': 'Task ID, used for pulling the results when scantype = pull',
     'type': 'integer', 'required': False, 'value': None},
    {'name': 'user', 'description': 'Username for authenticated scan', 'type': 'string', 'required': False,
     'value': None},
    {'name': 'password', 'description': 'Password for authenticated scan', 'type': 'string', 'required': False,
     'value': None}
]


def version():
    return __version__


def requirements():
    return mod_requirements


def validations(options):
    """
    Validate if configuration for Burp is correct
    :param options: Configurations
    :return: Message and status of the validation
    """
    status = 'true'
    msg = ''
    __error = 'error'
    if options['version'] != 'pro' and options['headless']:
        msg = 'Headless mode can be used only in \'pro\' version'
        status = __error
    if options['scantype'] == 'pull' and options['task'] is None:
        msg = 'Task ID is required when scantype = pull'
        status = __error
    if options['headless'] and options['path'] is None:
        msg = 'Path is required on headless mode'
        status = __error
    if status == __error:
        print(f'[ X ] {msg}')
    return {'description': msg, 'status': status}


def run(reqs):
    """
    Start the execution of Burp scan
    :param reqs: Requirements to run Burp
    :return: Result of the execution
    """
    try:
        msg = 'Burp didn\'t started correctly,'
        msg = f'{msg} make sure the path is correct and the REST API is enabled in Burp'
        if reqs is None:
            return {'description': 'Errors found in the data provided', 'status': 'error'}
        Print('[ ! ] Parameters validated', 'green')
        Print('[ ! ] Loading Burp', 'green')
        options = dict()
        for req in reqs:
            if 'name' in req.keys():
                options[req['name']] = req['value']
        burp = Burp()
        validation = validations(options)
        if validation['status'] == 'error':
            return validation
        if options['headless']:
            burp.debug = True
            if not burp.start_burp(options['path']):
                Print(f'[ X ] {msg}')
                return {'description': msg, 'status': 'error'}
        correct_setup = burp.setup(uri=options['url'],
                                   api_key=options['apikey'],
                                   burp_ip=options['ip'],
                                   port=options['port'],
                                   username=options['user'],
                                   password=options['password'],
                                   crawl_config=None,
                                   audit_config=None,
                                   debug=True,
                                   headless=options['headless'])
        b_error = {'description': msg, 'status': 'error'}
        if not correct_setup:
            return b_error
        result = None
        if options['scantype'] in ['spider', 'active', 'full']:
            if burp.scan():
                while not burp.scan_completed():
                    sleep(3)
            else:
                result = b_error
        if options['scantype'] == 'pull' and isinstance(options['task'], int):
            burp.pull_issues(options['task'])
        issues_retrieved = burp.get_issues()
        if issues_retrieved is None:
            result = {'description': 'No issues returned from Burp', 'results': None, 'status': True}
        else:
            result = {'results': issues_retrieved, 'status': True}
        if options['headless']:
            burp.stop_burp()
        return result

    except Exception as ex:
        Print(f'[ X ] Error: {str(ex)}', 'red')
        return {'description': 'Error: ' + str(ex), 'status': 'error'}


if __name__ == '__main__':
    """
    This is for running this script as standalone tool for burp scanning
    """
    modes = ['pro_headless', 'api']
    parser = argparse.ArgumentParser(description='Burp Pro/Ent automation script',
                                     epilog='Example: burp.py --path burp-pro.jar --scan http://site')
    parser.add_argument('-m', '--mode', help=f'Mode: {modes}', choices=modes, required=True)
    parser.add_argument('-s', '--scan', help='Run scan on the supplied URL', required=True)
    parser.add_argument('-b', '--burpip', help='Defaults to 127.0.0.1', required=False)
    parser.add_argument('-j', '--path', help='For BurpPro, you can specify the jar path', required=False)
    parser.add_argument('-P', '--port', help='Defaults to 1337', required=False, type=int)
    parser.add_argument('-k', '--key', help='API Key', required=False)
    parser.add_argument('-u', '--user', help='User account for authenticated scans', required=False)
    parser.add_argument('-p', '--password', help='User password for authenticated scans', required=False)
    parser.add_argument('-c', '--crawl_config', help='Use a pre-defined scan config file', required=False)
    parser.add_argument('-a', '--audit_config', help='Use a pre-defined scan config file', required=False)
    args = parser.parse_args()
    burpscan = Burp()
    if args.mode == 'pro_headless':
        if args.path is None:
            print('[ X ] -j | --path : Required on headless mode')
            exit(1)
        if not burpscan.start_burp(args.path):
            print('[ X ] Unable to start burp')
            exit(1)
    burpscan.setup(uri=args.scan,
                   api_key=args.key,
                   burp_ip=args.burpip,
                   port=args.port,
                   username=args.user,
                   password=args.password,
                   crawl_config=args.crawl_config,
                   audit_config=args.audit_config,
                   debug=True)
    if burpscan.scan():
        while not burpscan.scan_completed():
            sleep(3)
        issues = burpscan.get_issues()
    if args.mode == 'pro_headless':
        burpscan.stop_burp()
