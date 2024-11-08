#!/usr/bin/python
"""
[properties]
@version: 1.0
@author: Daniel Hoffman (Aka. Z)
@name: Nessus
@id: nessus
@description: Run Nessus professional
@syntax: nessus
@type: integration
@impact: intrusive
@service: [ssh,ftp,smtp,smb,snmp,imap,pop,dns]
@return_type: vuln
[properties]
"""
import json
# region imports
import time
import requests  # type: ignore
import sys
import os
import subprocess
from datetime import datetime, timedelta
from typing import Any, Callable, Final
from requests import Response
from shlex import quote as shlex_quote
from enum import Enum

try:
    import urllib3
except ImportError as e:
    print(f"[ X ] Missing libraries need to be installed:  {e}")
    print("\tInstall python urllib3:")
    print("\t\t> pip install urllib3")
try:
    import xmltodict  # type: ignore
except ImportError as e:
    print('[ X ] Missing libraries need to be installed: {}'.format(e))
    print("\tInstall python xmltodict:")
    print("\t\t> pip install xmltodict")

# endregion


# region properties
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # noqa: S4830 for Nessus Self-signed certificate

mod_requirements: list[dict[str, Any]] = [
    {'name': 'nessus_url', 'description': 'URL from Nessus Server API', 'type': 'url',
     'required': True, 'value': None},
    {'name': 'username', 'description': 'Nessus account username', 'type': 'string', 'required': True, 'value': None},
    {'name': 'password', 'description': 'Nessus account password', 'type': 'string', 'required': True, 'value': None},
    {'name': 'scope', 'description': 'Scope to be scanned (IP, network range, domains)',
     'type': 'string', 'required': True, 'value': None},
    {'name': 'scan_policy', 'description': 'Name of the policy or template used for the scan',
     'type': 'string', 'required': True, 'value': 'Basic Network Scan'},
    {'name': 'folder_name', 'description': 'Folder where scans are hosted (scope/target folder)', 'type': 'string',
     'required': True, 'value': 'My Scans'},
    {'name': 'file_name', 'description': 'Name of the Scan', 'type': 'string',
     'required': False, 'value': 'My_Nessus_Scan'},
    {'name': 'action', 'description': 'Action required to be performed',
     'type': ['scan_pull_results', 'scan_only', 'pull_results', 'load_file', 'export_results'], 'required': False,
     'value': 'scan_pull_results'},
    {"name": "timeout", "description": "Maximum waiting time at end of scanning (in hours)", "type": "integer",
     "required": False, "value": 3},
    {"name": "local_nessus_file", "description": "Local Nessus file to parse in \'load_file\' mode", "type": "string",
      "required": False, "value": None}
]

requirements: Callable[[], list[dict[str, Any]]] = lambda: mod_requirements


def parse_reqs(reqs: list[dict[str, Any]]) -> dict[str, Any]:
    """
       Processes the dictionary list of requirements to extract specific key-value pairs.
        Parameters
        ----------
            reqs:   List[Dict[str, Any]]
                    A list of requirements dictionaries, where each dictionary can contain the keys 'name' and 'value'.
        Returns
        -------
            options:    dict[str, Any]
                        A dictionary in which each key is a value associated with 'name' in the input dictionaries,
                        and each value is the value associated with 'value' in the same dictionary. with 'value' in
                        the same dictionary. If 'value' is not present, an empty string is used as the default value.
        Examples
        --------
            parse_reqs(reqs=[{'name': 'nessus_url', 'value': "https://nessus.company.example:8834/"},
                             {'name': 'scope', 'value': '10.20.145.0/24'}])
        """
    options = dict()
    for req in reqs:
        if 'name' in req.keys():
            options[req.get('name', '')] = req.get('value', '')
    return options


# endregion


# region DataStructures
class Bcolors(Enum):
    """
    Enum for ANSI color codes

    Members
    -------
        GREEN:  (str)
                ANSI Color (green)
        RED:  (str)
                ANSI Color (red)
        YELLOW:  (str)
                ANSI Color (yellow)
        CYAN:  (str)
                ANSI Color (cyan)
        ENDC:  (str)
                ANSI code to reset default value
    Example
    --------
        print(f"{Bcolors.GREEN.value}This is a green text{Bcolors.ENDC.value}")
    """
    GREEN: str = '\033[92m'
    RED: str = '\033[91m'
    YELLOW: str = '\033[1;33m'
    ENDC: str = '\033[0m'
    CYAN: str = '\033[36m'


class Integration(object):
    """
    Integration class (c) Mario Robles
    This class parses the xml format of the ".nessus" file and builds a list of dictionaries for each issue detected.
    Each issue is represented by a dictionary
    """
    issues: list[dict] = []
    _port: str | int = '@port'

    def translate(self, input_file: str) -> list[dict] | None:
        try:
            xml_dict = Integration.get_xml_data(input_file)
            if xml_dict is None:
                return None
            xml_list = Integration.get_xml_list(xml_dict.get('NessusClientData_v2')  # type: ignore
                                                .get('Report').get('ReportHost', {}))

            if xml_list is None:
                return None
            issues_nessus = self.process_xml_list(xml_list)
            return issues_nessus
        except Exception as ex:
            print('[ X ] Something went wrong with the file: {}'.format(ex))
            return None

    @staticmethod
    def get_xml_data(input_file: str) -> dict | None:
        if not os.path.isfile(input_file) or not os.path.exists(input_file):
            return None
        with open(input_file) as xml_file:
            xml_dict = xmltodict.parse(xml_file.read())
        xml_file.close()
        return xml_dict

    @staticmethod
    def get_xml_list(xml_dict: dict) -> list[dict] | None:
        try:
            xml_list = xml_dict
            if isinstance(xml_list, dict):
                xml_list = [xml_list]
            elif not isinstance(xml_list, list):
                return None
            return xml_list
        except Exception as er:
            print(er)
            return None

    def process_xml_list(self, xml_list: list[dict]) -> list:
        for host in xml_list:
            self.process_issues(host)
        return self.issues

    def process_issues(self, host: dict) -> None:
        if not host:
            return
        current_host = host.get('@name')
        host_properties = host.get('HostProperties')
        _attack = 'No attack information is provided by Nessus, see the evidence for more details'
        _poc = 'This was discovered by Nessus, retest is usually performed running a new scan'
        report_items = Integration.get_xml_list(host.get('ReportItem'))  # type: ignore
        if report_items is None:
            return
        for report_issue in report_items:
            new_issue = dict()

            # Remove issues with port = 0
            if report_issue[Integration._port] != '0':
                # Fill initial data
                new_issue['issue_type'] = 'vulnerability'
                new_issue['vulnerability_type'] = 'Network'
                new_issue['scan_type'] = 'network scan'
                new_issue['affected resources'] = ''
                new_issue['attack'] = _attack
                new_issue['proof of concept'] = _poc
                new_issue['tool'] = 'Nessus'
                new_issue['evidence'] = ''
                new_issue['confidence'] = 'Moderate'
                new_issue['details'] = report_issue['synopsis']
                new_issue['description'] = report_issue['description']

                if 'plugin_name' in report_issue:
                    new_issue['type'] = report_issue.get('plugin_name')  # type: ignore
                if '@pluginID' in report_issue:
                    new_issue['external id'] = report_issue.get('@pluginID')  # type: ignore
                if '@severity' in report_issue:
                    severity = Integration.fill_severity(report_issue.get('@severity'))  # type: ignore
                    new_issue['severity'] = severity

                # Fill affected resources and initial evidence
                new_issue = Integration.fill_affected_resources(new_issue,
                                                                current_host,  # type: ignore
                                                                host_properties)

                # Fill with evidences
                new_issue = Integration.fill_evidence(report_issue, new_issue)

                # Fill with port, solution, protocol and transport
                new_issue = Integration.fill_network_fields(report_issue, new_issue)

                # Find cvss values
                new_issue = Integration.fill_cvss(report_issue, new_issue)

                # Fill remediation information
                new_issue = Integration.fill_remediation_fields(report_issue, new_issue)
                self.issues.append(new_issue)

    @staticmethod
    def fill_severity(severity: str) -> str:
        sev = ''

        if severity == '0':
            sev = 'Info'
        elif severity == '1':
            sev = 'Low'
        elif severity == '2':
            sev = 'Medium'
        elif severity == '3':
            sev = 'High'
        elif severity == '4':
            sev = 'Critical'

        return sev

    @staticmethod
    def fill_cvss(report_issue: dict, zirkul_issues: dict) -> dict:
        cvss = {'Info': {'cvss_score': 0, 'cvss_string': ''},
                'Low': {'cvss_score': 3.1, 'cvss_string': 'AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N'},
                'Medium': {'cvss_score': 5.3, 'cvss_string': 'AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'},
                'High': {'cvss_score': 8.2, 'cvss_string': 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N'},
                'Critical': {'cvss score': 10, 'cvss_string': 'AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'},
                }
        zirkul_issues['cvss'] = cvss[zirkul_issues.get('severity')].get('cvss_score')
        zirkul_issues['cvss string'] = cvss[zirkul_issues.get('severity')].get('cvss_string')
        if 'cvss_vector' in report_issue:
            zirkul_issues['cvss string'] = report_issue.get('cvss_vector')
        if 'cvss_base_score' in report_issue:
            zirkul_issues['cvss'] = report_issue.get('cvss_base_score')
        if 'cvss3_vector' in report_issue:
            zirkul_issues['cvss string'] = report_issue.get('cvss3_vector')
        if 'cvss3_base_score' in report_issue:
            zirkul_issues['cvss'] = report_issue.get('cvss3_base_score')
        if isinstance(zirkul_issues.get('cvss'), str):
            try:
                zirkul_issues['cvss'] = float(zirkul_issues.get('cvss'))
            except Exception as err:
                zirkul_issues['cvss'] = 0
                print(f"Error en fill_cvss: Exception {err}", file=sys.stderr)
        return zirkul_issues

    @staticmethod
    def fill_affected_resources(zirkul_issues: dict, current_host: str, host_properties: dict) -> dict:
        _name = '@name'
        _text = '#text'
        _affected_resources = 'affected resources'
        zirkul_issues[_affected_resources] = current_host
        if isinstance(host_properties, dict) and 'tag' in host_properties.keys() \
                and isinstance(host_properties.get('tag'), list):
            for att in host_properties.get('tag'):
                if _name in att.keys() and att.get(_name) == 'operating-system':
                    zirkul_issues['evidence'] = 'Operating System: {}'.format(att.get(_text))
                if _name in att.keys() and att.get(_name) == 'host-ip' and att.get(_text) != current_host:
                    zirkul_issues[_affected_resources] = '{} ({})'.format(current_host, att.get(_text))
        return zirkul_issues

    @staticmethod
    def fill_evidence(report_issue: dict, zirkul_issues: dict) -> dict:
        if 'plugin_output' in report_issue:
            if zirkul_issues['evidence'] == '':
                zirkul_issues['evidence'] = report_issue.get('plugin_output')
            else:
                zirkul_issues['evidence'] = '{}\n{}'.format(zirkul_issues.get('evidence'),
                                                            report_issue.get('plugin_output'))
        if len(zirkul_issues['evidence']) > 4095:
            zirkul_issues['evidence'] = zirkul_issues['evidence'][:4050]
            zirkul_issues['evidence'] = '{}\n--snip--'.format(zirkul_issues.get('evidence'))
        return zirkul_issues

    @staticmethod
    def fill_network_fields(report_issue: dict, zirkul_issues: dict) -> dict:
        _svc_name = '@svc_name'
        if Integration._port in report_issue:
            zirkul_issues['port'] = int(report_issue.get(Integration._port))
        if '@protocol' in report_issue:
            zirkul_issues['transport'] = report_issue.get('@protocol')
        if _svc_name in report_issue:
            if report_issue[_svc_name][-1] == '?':
                zirkul_issues['protocol'] = report_issue.get(_svc_name)[:-1]
            else:
                zirkul_issues['protocol'] = report_issue.get(_svc_name)
        if 'protocol' in zirkul_issues and zirkul_issues.get('protocol') == 'www':
            zirkul_issues['protocol'] = 'http'
            if 'port' in zirkul_issues and zirkul_issues.get('port') == 443:
                zirkul_issues['protocol'] = 'https'

        return zirkul_issues

    @staticmethod
    def fill_remediation_fields(report_issue: dict, zirkul_issues: dict) -> dict:
        zirkul_issues['remediation'] = 'No remediation provided by Nessus'
        if 'solution' in report_issue and str(zirkul_issues.get('remediation')).lower() in ['', 'n/a', 'none']:
            zirkul_issues['remediation'] = report_issue.get('solution')
        if zirkul_issues['severity'] == 'Info':
            zirkul_issues['remediation'] = 'No remediation is required'
        if 'see_also' in report_issue:
            ref = str(report_issue['see_also'])
            if ref.startswith('http://') or ref.startswith('https://'):
                zirkul_issues['references'] = [{'title': ref, 'url': ref}]
        return zirkul_issues


class NessusScan(object):
    """
    Customised management interface for Nessus Professional 6 via the API
    Attributes
    ----------
        console:    Callable -> terminal_console
                    Alias to static method terminal_console
        __url:  str
                    Nessus Server API URL
        __usr:  str
                    Nessus Account username
        __pwd:  str
                    Nessus Account password
        __folder_id:    int
                    Folder ID for the scan (Automatic procurement)
        __folder_name:  str
                    Name of the Folder where the scan is stored
        __name: str
                    Scan Name
        __policy:   int
                    Policy Scan ID (Automatic procurement)
        __policy_template_title:    str
                    Name of the Policy of templated used for the scan
        __template_uuid:    str
                    Template UUID (Automatic procurement)
        __scope:    str
                    Assigned Scope for scanning
        __scan_id:  int
                    Scan ID (Automatic procurement)
        __scan_uuid:    str
                    Scan UUID for be able to export scan (Automatic procurement from ID)
        __timeout: int
                    Timeout for scan_pull_results daemon in hours (default 3 hours)
        __headers:  dict[str, str]
                    HTTP Headers to authentication & Authorization into Nessus Server trough API
    Static Methods
    --------------
        cls.extract:    str | None
                    (txt: str, str_start: str, str_end: str)
                    Search for a determine text pattern
        cls.terminal_console:   None
                            (txt: str, col: str = '')
                            Preformat the stdout for printing it in stdout
    Methods
    -------
        __init__:       None
                        Constructor
        __set_config :    None
                        Configure the internal variables with their respective values
        load_config:    bool
                        Validate input data (requirements) and send it to config class variables
        get_token:      bool
                        Proceeds with server authentication and configures authentication and authorisation headers.
        __get_folders:  tuple[bool, list]
                        Gets all folders from server (auxiliary)
        __get_template_uuid_from_policy:    str | None
                                            Gets the UUID of the template from a policy (Auxiliary)
        __get_template_no_policy:   bool
                                    Performs template search based on the provided name
                                    (in case there is no matching policy) (auxiliary)
        __get_policy:   bool
                        Gets the policy ID by name
        get_folder_id:  None
                        Gets the ID of a folder based on its name
        create_folder:  None
                        Create a folder in case it does not exist with that name
        get_scan:       None

        __create_scan:    bool
                        A scan is created
        launch_scan:    None
                        The scan is launched
        scan_status:    tuple[bool, str]
                        Validate Scan status (progress)
        download_nessus_file:   None
                        To download temporal Nessus File to parse
        scan_pull_results:      None
    """
    # region staticMethods

    @staticmethod
    def delete_file(filepath: str) -> bool:
        if os.path.exists(filepath):
            os.remove(filepath)
            return True
        else:
            NessusScan.terminal_console(f"File {filepath} not found", "red")
            return False

    @staticmethod
    def extract(txt: str, str_start: str, str_end: str) -> str | None:
        """
        Method to search by strings patterns

        Parameters
        ---------
            txt:        str
                        text where the search will proceed
            str_start:  str
                        Pattern text prior to the desired text
            str_end:    str
                        Pattern text following to the desired text
        Return
        ------
            tmp:        str | None
                        desired text if found, None otherwise
        Example
        -------
            extract(txt="User-Agent: Zirkul-Agent - Nessus/1.0", str_start="Nessus/", str_end=r'"')
            -> 1.0
        """
        ini: int = txt.find(str_start)
        if ini == -1:
            return None
        tmp: str = txt[ini + len(str_start):]
        fin: int = tmp.find(str_end)
        if fin == -1:
            return None
        tmp = tmp[:fin]
        if tmp != '':
            return tmp
        return None


    @staticmethod
    def terminal_console(txt: str, col: str = '') -> None:
        """
        Prettier format console output

        Parameters
        ----------
            txt:    str
                    Text to print
            col:    str
                    Color Name
        Example
        -------
            print(f"Beautiful text {some_variable=}", "red")
        """
        match col:
            case 'red':
                message_color = Bcolors.RED
                txt = f"[ X ] {txt}"
            case 'green':
                message_color = Bcolors.GREEN
                txt = f"[ + ] {txt}"
            case 'yellow':
                message_color = Bcolors.YELLOW
                txt = f"[ ! ] {txt}"
            case 'CYAN':
                message_color = Bcolors.CYAN
                txt = f"[ - ] {txt}"
            case _:
                message_color = Bcolors.ENDC
                txt = f"[ * ] {txt}"
        if sys.platform == "win32":
            print(txt)
            return
        print(f"{message_color.value}{txt}{Bcolors.ENDC.value}")

    # endregion

    def __init__(self) -> None:
        self.console = NessusScan.terminal_console
        self.__url: str | None = None
        self.__usr: str | None = None
        self.__pwd: str | None = None
        self.__folder_id: int | None = None
        self.__folder_name: str | None = None
        self.__name: str | None = None
        self.__policy: int | None = None
        self.__policy_template_title: str | None = None
        self.__template_uuid: str | None = None
        self.__scope: str | None = None
        self.__scan_id: int | None = None
        self.__scan_uuid: str | None = None
        self.__timeout: int | None = None
        self.__interval: timedelta = timedelta(minutes=5)
        self.__scan_type: str | None = None
        self.__nessus_file: str | None = None
        self.__headers: dict[str, str] = {
            'Content-Type': 'application/json',
            'User-Agent': 'Zirkul-Agent - Nessus/1.0',
            'Accept': 'application/json',
            'Connection': 'keep-alive',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin'
        }

    def __set_config(self, url: str, name: str, user: str, paswd: str, folder_name: str,
                     policy_name: str, scope: str, scan_type: str, timeout: int = 3,
                     nessus_file: str | None = None) -> None:  # type: ignore
        """
            Setting up Nessus configuration
        Parameters
        ----------
            Obj properties:
                url:    str
                        Nessus server url
                user:   str
                        Nessus Account Username
                paswd:  str
                        Nessus Account Password
                folder_name:    str
                                Scan's folder name
                policy_name:    str
                                Name of the policy to use
                scope:          str
                                Target's scope for the scan
                timeout:        int
                                Waiting time for the completion of the scan
                                and the start of the download of the results (in hours)
                scan_type:      str
                                Type of scan/action to execute
        Example
        -------
            set_config(url="https://nessus.company.exmaple:8834", user="admin", paswd="superPassowrd123.@!",
                        folder_name='Project-1201', policy_name='External production no ping',
                        scope='uat.client.example, test.client.example, 10.125.46.0/16',
                        name='client-scan-name', timeout=3, scan_type="pull_results")
        """
        self.__url = url if url.endswith("/") else f"{url}/"
        self.__name = name
        self.__usr = user
        self.__pwd = paswd
        self.__folder_name = folder_name
        self.__policy_template_title = policy_name
        self.__scope = scope
        self.__headers['Origin'] = self.__url
        self.__headers['Referer'] = self.__url
        self.__timeout = timeout
        self.__nessus_file = nessus_file
        match scan_type:
            case "scan_only":
                self.__scan_type = scan_type
            case "pull_results":
                self.__scan_type = scan_type
            case "scan_pull_results":
                self.__scan_type = scan_type
            case "load_file":
                self.__scan_type = scan_type
            case "export_results":
                self.__scan_type = scan_type
            case _:
                self.console("Not valid argument, setting up default scan...", "yellow")
                self.__scan_type = "scan_pull_results"
        status: bool = self.get_token()
        if not status:
            self.console('It has not been possible to authenticate to the server!', 'red')
            self.console('Please check the configuration', 'yellow')
            self.console(f'username={self.__usr}  password={self.__pwd}  server-API-url={self.__url}', 'CYAN')
            return
        self.get_folder_id()
        self.__get_policy()

    def load_config(self, data: dict[str, str | int]) -> bool:
        """
            Loads config from json file (dict)
        Parameters
        ----------
            data:   dict[str, str | int]
                    Configuration json
        Example
        -------
            requirements: list[dict[str, str | int]]    # configuration incoming  from Agent
            reqs: dict[str, str | int] = parse_reqs(requirements)  # type: ignore
            Nessus_obj.load_config(reqs)
        """
        required: list[str] = ["nessus_url", "username", "password", "scope"]
        for x in required:
            if x not in data.keys():
                self.console(f'[ X ] {x} is required')
                return False
        self.__set_config(url=data.get("nessus_url"), user=data.get("username"),  # type: ignore
                          paswd=data.get("password"), scope=data.get("scope"),
                          policy_name=data.get("scan_policy", "Basic Network Scan"),
                          name=data.get("file_name", "My_Nessus_Scan"), folder_name=data.get("folder_name", "My Scans"),
                          timeout=data.get("timeout", 3), scan_type=data.get("action", "scan_pull_results"),
                          nessus_file=data.get('local_nessus_file', None))
        return True

    def get_token(self) -> bool:
        """
        This method gets:
            X-Api-Token:    Nessus API Authorization Token
            X-Cookie:       Nessus API Authentication Token

        Parameters
        ----------
            Obj properties:
                self.__url: str    (Nessus server url)
                self.__usr: str    (Username)
                self.__pwd: str    (User password)
        Returns
        -------
            True/False:    bool
                Boolean status of successful operation
        Example
        -------

        """
        response: Response = requests.get(
            url=f"{self.__url}nessus6.js",
            verify=False  # noqa: S4830
        )
        token: str = self.extract(response.text, r'Token",value:function(){return"', r'"')
        self.__headers["X-Api-Token"] = token
        response = requests.post(
            url=f"{self.__url}session",
            headers=self.__headers,
            json={
                "username": self.__usr,
                "password": self.__pwd
            },
            verify=False  # noqa: S4830
        )
        if response.status_code != 200:
            self.console(f"Error: {response.status_code}\n\t{response.text}", 'red')
            return False
        if (token := response.json().get('token', None)) is None:  # Walrus operator to reduce lines of code
            self.console("Error: for some reason token is None", 'red')
            return False
        self.__headers['X-Cookie'] = f"token={token}"
        return True

    # region Folders
    def __get_folders(self, already_regenerate: bool = False) -> tuple[bool, list]:
        """
            This method gets the Folders from the server.
            If it's necessary it tries to regenerate the authentication/authorization tokens
        Parameters
        ----------
            Obj properties:
                self.__url: str
                    Nessus server url
                self.__headers: dict[str, str]
                    request headers
            already_regenerate: bool
                Used to know if the tokens al ready has been regenerated or not to avoid infinite loop
        Returns
        -------
            result: tuple[bool, list]
                result[0]: bool
                    To know if operation was successful
                result[1]: list
                    Empty if was not successful
                    requests.json.get("folders") = folders json structure
                        folder_json.get("id"): int
                        folder_json.get("name"): str
                        return list[tuple[folder_id, folder_name] for folder in folders]
        """
        response: Response = requests.get(
            url=f"{self.__url}folders",
            headers=self.__headers,
            verify=False  # noqa: S4830
        )
        match response.status_code:
            case 200:
                temp_folders = response.json().get("folders")
                result = True, [(x.get("id"), x.get("name")) for x in temp_folders]
            case 401:
                if not already_regenerate:
                    self.get_token()
                    return self.__get_folders(already_regenerate=True)
                result = False, []
            case _:
                self.console(f"Error: {response.status_code}\n\t{response.text}", 'red')
                result = False, []
        return result

    def get_folder_id(self) -> None:
        """
        Gets Folder ID by Name

        Parameters
        ----------
            Obj properties:
                self.__url: str
                    Nessus server url
                self.__headers: dict[str, str]
                    request headers
                self.__folder_name: str
                    Folder name on the server
            """
        status, temp_folders = self.__get_folders()
        if not status or not temp_folders:
            self.console("Something was wrong with the authentication to the server", 'red')
            return
        for x, i in temp_folders:
            if self.__folder_name.lower() == i.lower():
                self.__folder_id = x
                self.__folder_name = i
                break
        if not self.__folder_id:
            self.console("No folder matching, setting up default Folder...", "yellow")
            for x, i in temp_folders:
                if i.lower() == "My Scans".lower():
                    self.__folder_id = x
                    self.__folder_name = i
                    break

    def create_folder(self, name: str) -> None:
        """
            Validates if folder name exists and assigns the ID to the variables,
            otherwise proceeds with the creation and storage of the ID
        Parameters
        ----------
                Obj properties:
                        self.__url: str
                            Nessus server url
                        self.__headers: dict[str, str]
                            request headers
                        self.__folder_name: str
                            Folder name on the server
        Example
        -------
               create_folder("MyNewFolder")
        """
        if self.__folder_id is not None and self.__folder_name == name:
            self.console(f"Folder {self.__folder_name} exist and is already in use!", 'yellow')
            return
        if self.__folder_name == "My Scans" or self.__folder_id is None:
            self.console("Checking existence on the server...", 'yellow')
            status, temp_folders = self.__get_folders()
            if not status or not temp_folders:
                self.console("Something was wrong with the authentication to the server", 'red')
                return
            tmp_folder = [(x, i) for x, i in temp_folders if i.lower() == name.lower()][0]
            if tmp_folder:
                self.console("Folder already exist", 'yellow')
                self.console(f"Folder ID: {tmp_folder[0][0]}", 'CYAN')
                self.console(f"Folder Name: {tmp_folder[0][1]}", 'CYAN')
                self.console('Setting up...', 'yellow')
                self.__folder_id = tmp_folder[0][0]
                self.__folder_name = tmp_folder[0][1]
                self.console("Locals updated!", 'yellow')
                self.console(f'Folder {self.__folder_name} in use!', 'yellow')
                return
        self.console(f"Creating folder: {name}", 'yellow')
        response: Response = requests.post(
            url=f"{self.__url}folders",
            json={"name": name},
            headers=self.__headers,
            verify=False  # noqa: S4830
        )
        match response.status_code:
            case 200:
                self.console("Success!", 'green')
                self.console("Changing locals...", 'yellow')
                self.__folder_name = name
                self.__folder_id = response.json().get('id')
                self.console(f"Folder Name: {self.__folder_name}", 'CYAN')
                self.console(f"Folder ID: {self.__folder_id}", 'CYAN')
            case _:
                self.console("Something went wrong!", 'red')
                self.console(f"Status code: {response.status_code}", 'red')
                self.console(f"Response data: {response.text}", 'yellow')

    # endregion

    # region Templates_and_Policies
    def __get_template_uuid_from_policy(self, data: list[dict]) -> str | None:
        """
                Gets Template UUID from a Policy object (json)
        Parameters
        ----------
                Obj properties:
                        self.__policy: int
                            Policy ID
                data:   list[dict]
                        List of all json policies from the server
        Returns
        -------
                UUID:   str
                        Template UUID used on the policy, None if not exist
        Example
        -------
                self.__get_templates_uuid_from_policy(json_response_policies)
        """
        for policy in data:
            if policy.get("id") == self.__policy:
                return policy.get("template_uuid")
        return None

    def __get_template_no_policy(self, already_regenerate: bool = False) -> bool:
        """
                Search for templates and gets the UUID if there is no policy
        Parameters
        ----------
                Obj properties:
                        self.__url: str
                            Nessus server url
                        self.__headers: dict[str, str]
                            request headers
                        self.__policy_template_title:  str
                                                Name of the policy or template to search for
                                                If there is no match, a Nessus default one is executed.
                    already_regenerate: bool
                        Used to know if the tokens al ready has been regenerated or not to avoid infinite loop
        Returns
        -------
                success:    bool
                            True if everything ok, False otherwise
        """
        response = requests.get(
            url=f"{self.__url}editor/scan/templates",
            headers=self.__headers,
            verify=False
        )
        match response.status_code:
            case 200:
                templates = response.json().get("templates")
            case 401:
                self.console('Unauthorized', 'red')
                if not already_regenerate:
                    self.get_token()
                    return self.__get_template_no_policy(already_regenerate=True)
                return False
            case _:
                self.console("Connections Issues", 'red')
                self.console('Aborting!...', 'yellow')
                return False
        templates = [(x.get("uuid"), x.get("title")) for x in templates]
        template: tuple | None = None
        for x, i in templates:
            if self.__policy_template_title.lower() == i.lower():
                template = (x, i)
                break
        if not template:
            self.console(f"There is no any Policy or Template with this name: {self.__policy_template_title}", 'red')
            self.console("Setting up a default one!", 'yellow')
            template = [x for x in templates if x[1].lower() == "Basic Network Scan".lower()][0]
        self.__template_uuid = template[0]  # type: ignore
        self.__policy_template_title = template[1]  # type: ignore
        #self.console(f"Template Name: {self.__policy_template_title}", 'CYAN')
        #self.console(f"Template UUID: {self.__template_uuid}", 'CYAN')
        return True

    def __get_policy(self, already_regenerate: bool = False) -> bool:
        """
                Gets the ID of the requested policy by name and the UUID of the template used,
                if there is no match with the policy it asks for a search in templates,
                if there is no match it assigns the defaults.
        Parameters
        ----------
                Obj properties:
                        self.__url: str
                            Nessus server url
                        self.__headers: dict[str, str]
                            request headers
                        self.__policy_template_title:  str
                                                Name for the Policy or template
                    already_regenerate: bool
                        Used to know if the tokens al ready has been regenerated or not to avoid infinite loop
        Returns
        -------
                True/False: bool
                        True if everything ok, False otherwise
        """
        response: Response = requests.get(
            url=f"{self.__url}policies",
            headers=self.__headers,
            verify=False  # noqa: S4830
        )
        match response.status_code:
            case 200:
                policies = response.json().get("policies")
                policies_simplified = [(x.get("id"), x.get("name")) for x in policies]
            case 401:
                self.console('Unauthorized', 'red')
                if not already_regenerate:
                    self.get_token()
                    return self.__get_policy(already_regenerate=True)
                return False
            case _:
                self.console("Connections Issues", 'red')
                self.console('Aborting!...', 'yellow')
                return False
        temp_policy: tuple | None = None
        for x, i in policies_simplified:
            if self.__policy_template_title.lower() == i.lower():
                temp_policy = (x, i)
                break
        if not temp_policy:
            return self.__get_template_no_policy()
        self.__policy = temp_policy[0]  # ID
        self.__policy_template_title = temp_policy[1]  # correct name
        self.__template_uuid = self.__get_template_uuid_from_policy(policies)
        #self.console(f"Policy Name: {self.__policy_template_title}", 'CYAN')
        #self.console(f"Policy ID: {self.__policy}", 'CYAN')
        #self.console(f"Template UUID: {self.__template_uuid}", 'CYAN')
        return True

    # endregion

    # region Scans
    def get_scan(self, already_regenerate: bool = False) -> bool:
        """
                Gets the scan ID by name
        Parameters
        ----------
                Obj properties:
                        self.__url: str
                            Nessus server url
                        self.__headers: dict[str, str]
                            request headers
                        self.__name: str
                            Scan name
                    already_regenerate: bool
                        Used to know if the tokens al ready has been regenerated or not to avoid infinite loop
        """
        response: Response = requests.get(
            url=f"{self.__url}scans/",
            headers=self.__headers,
            verify=False
        )
        match response.status_code:
            case 200:
                scans: list[dict] = [x for x in response.json().get('scans') if x.get("folder_id") == self.__folder_id]
                if not scans:
                    self.console("Everything is wrong!", 'red')
                    return False
                temp_scan: tuple | None = None
                for y, i in [(x.get("id"), x.get("name")) for x in scans]:
                    if i.lower() == self.__name.lower():
                        temp_scan = (y, i)
                        break
                if not temp_scan:
                    self.console(f"There are no scans with the Name '{self.__name}'" +
                                 f"into the folder '{self.__folder_name}'", 'red')
                    return False
                self.__scan_id = temp_scan[0]
                return True
            case 401:
                self.console("Unauthorized!", 'yellow')
                self.get_token()
                if not already_regenerate:
                    return self.get_scan(already_regenerate=True)
                self.console("Something went wrong with authorization tokens", 'red')
            case _:
                self.console("Something went wrong!", 'red')
                self.console(f"Error: {response.status_code}\t{response.text}", 'red')
        return False

    def __create_scan(self, already_regenerate: bool = False) -> bool:
        """
                Create a new scan
        Parameters
        ----------
                Obj properties:
                        self.__url: str
                            Nessus server url
                        self.__headers: dict[str, str]
                            request headers
                        self.__folder_id: int
                                    Identifier for the Folder
                        self.__Policy:  int
                                Policy identifier (if null the server auto assign one)
                        self.__template_uuid:  str
                                        UUID for template used (mandatory) (auto searched and assigned )
                    already_regenerate: bool
                        Used to know if the tokens al ready has been regenerated or not to avoid infinite loop
        Returns
        -------
                True/False: bool
                        True if everything's ok, False otherwise
        """
        self.get_folder_id()
        self.__get_policy()
        payload: dict[str, Any] = {
            "uuid": self.__template_uuid,
            "settings": {
                "scanner_id": 1,
                "name": self.__name,
                "enabled": False,  # Schedule
                "text_targets": self.__scope,
                "folder_id": self.__folder_id,
                "policy_id": self.__policy,  # if it's None in json it will be auto-assigned from the server
            }
        }
        response: Response = requests.post(
            url=f"{self.__url}scans",
            headers=self.__headers,
            json=payload,
            verify=False
        )
        match response.status_code:
            case 200:
                self.console("Success!", 'green')
                self.__scan_id = response.json().get('scan').get('id')
                self.console(f"ScanID: {self.__scan_id}", 'green')
            case 401:
                self.console("Unauthorized", 'red')
                if not already_regenerate:
                    self.get_token()
                    return self.__create_scan(already_regenerate=True)
                return False
            case _:
                self.console('Something went wrong!', 'red')
                self.console(f"Status Code: {response.status_code}\t{response.text}", 'red')
                return False
        return True

    def launch_scan(self, already_regenerate: bool = False) -> None:
        """
                Executes the scan
        Parameters
        ----------
                Obj properties:
                        self.__url: str
                            Nessus server url
                        self.__headers: dict[str, str]
                            request headers
                        self.__scan_id: int
                                Actual Scan ID (if scan already exists in Nessus Server)
                    already_regenerate: bool
                        Used to know if the tokens al ready has been regenerated or not to avoid infinite loop
        """
        if self.__scan_id is None:
            self.get_scan()
        response: Response = requests.post(
            url=f"{self.__url}scans/{self.__scan_id}/launch",
            headers=self.__headers,
            json={},
            verify=False
        )
        match response.status_code:
            case 200:
                self.__scan_uuid = response.json().get("scan_uuid")
                self.console(f"ScanID: {self.__scan_id}", 'CYAN')
                self.console(f"ScanUUID: {self.__scan_uuid}", 'CYAN')
            case 401:
                self.console("Unauthorized", 'yellow')
                if not already_regenerate:
                    self.get_token()
                    self.launch_scan(already_regenerate=True)
            case _:
                self.console("Something went wrong", 'red')

    def scan_status(self, already_regenerate: bool = False) -> tuple[bool, str]:
        """
        This method gets the Folders from the server.
        If it's necessary it tries to regenerate the authentication/authorization tokens
        Parameters
        ----------
                Obj properties:
                        self.__url: str
                            Nessus server url
                        self.__headers: dict[str, str]
                            request headers
                        self.__scan_id: int
                                 Actual Scan ID (if scan already exists in Nessus Server)
                    already_regenerate: bool
                        Used to know if the tokens al ready has been regenerated or not to avoid infinite loop
        Returns
        -------
                tuple[bool, str]
                    tuple[0] = Status of success (True) or failure (False)
                    tuple[1] = status string [completed, aborted, imported, killing, pending, running,
                                    resuming, canceling, cancelled, pausing, paused, stopping, stopped]
        """
        if self.__scan_id is None:
            self.get_scan()
        response: Response = requests.get(
            url=f"{self.__url}scans/{self.__scan_id}",
            headers=self.__headers,
            verify=False
        )
        match response.status_code:
            case 200:
                scan: dict[str, Any] = response.json()
            case 401:
                self.console("Unauthorized", 'yellow')
                if already_regenerate:
                    return False, ''
                self.get_token()
                return self.scan_status(already_regenerate=True)
            case _:
                self.console("Something went wrong", 'red')
                return False, ''
        return True, scan.get("info").get("status")  # type: ignore

    # endregion

    # region Files
    def download_nessus_file(self) -> bool:
        """
            Downloads scan Nessus file
        Parameters
        ----------
            object properties:
                self.__name:    str
                                scan Name
                self.__url:     str
                                Nessus Server API URL
                self.__headers: dict
                                Request headers
                self.__scan_id: int
                                Scan Identifier
        """
        data: dict[str, str] = {"format": "nessus"}
        self.__headers["Accept"] = "^/^"
        response: Response = requests.post(
            url=f"{self.__url}scans/{self.__scan_id}/export?limit=2500",
            headers=self.__headers,
            json=data,
            verify=False  # noqa: S4830
        )
        if response.status_code != 200:
            self.console(f"Could not be possible this action: Error code: {response.status_code}\t{response.text}",
                         'red')
            return False
        if (token := response.json().get("token")) is None:
            self.console("Something fail, there is no token", 'yellow')
            return False
        file_status: str = "loading"
        while True:
            validator: Response = requests.get(
                url=f"{self.__url}tokens/{token}/status",
                headers=self.__headers,
                verify=False
            )
            if validator.status_code != 200:
                self.console(f"There are some connections issues: {validator.status_code}", 'yellow')
                continue
            if (status := validator.json().get("status", None)) == "ready":
                file_status = status
                break
        if file_status != "ready":
            self.console("Was impossible download the results", 'red')
            return False
        response = requests.get(
            url=self.__url + f"tokens/{token}/download",
            headers=self.__headers,
            verify=False
        )
        match response.status_code:
            case 200:
                if self.__scan_type == "export_results" and self.__nessus_file is not None:
                    name = f"{self.__nessus_file}" if self.__nessus_file.endswith(
                        ".nessus") else f"{self.__nessus_file}.nessus"
                    with (open(name, "wb") as f):
                        f.write(response.content)
                else:
                    with open(f"{self.__name}.nessus", "wb") as f:
                        f.write(response.content)
                return True
            case _:
                self.console(f"Error downloading the file: {response.status_code}", 'red')
        self.__headers["Accept"] = "application/json"
        return False

    # endregion

    # region Main_Methods
    def pull_results(self) -> list[dict] | None:
        """
            Gets the scan results
        Parameters
        ----------
            object properties:
                self.__name:    str
                                scan Name
        Return
        ------
            Nessus results File (xml) translated to list[dict]
        """
        status: tuple[bool, str] = self.scan_status()
        if not status[0]:
            self.console("Scan status request is not successful!", 'red')
            return None
        if status[1] != "completed":
            self.console(f"Action invalid, current scan state: {status[1]}", 'red')
            return None
        download_status: bool = self.download_nessus_file()
        if not download_status:
            self.console("Something went wrong downloading the file", "yellow")
            return None
        tmp: Integration = Integration()
        data = tmp.translate(f"{self.__name}.nessus")
        time.sleep(0.5)
        if os.path.exists(f"{self.__name}.nessus"):
            self.delete_file(f"{self.__name}.nessus")
        return data

    def export_file(self) -> bool:
        status: tuple[bool, str] = self.scan_status()
        if not status[0]:
            self.console("Scan status requests is not success!", 'red')
            return False
        if status[1] != "completed":
            self.console(f"Action invalid, current scan state: {status[1]}", 'red')
            return False
        download_status: bool = self.download_nessus_file()
        if not download_status:
            self.console("Something went wrong downloading the file", "yellow")
            return False
        return True
    def scan_pull_results(self) -> list[dict] | None:
        """
            Create a new scan and gets the scan results
        Parameters
        ----------
            object properties:
                self.__name:    str
                                scan Name
                self.__timeout: int
                                Waiting timeout (hours)
                self.__interval: int
                                Interval to show status in console (in minutes)
        Return
        -----
            self.pull_results() -> list[dict]
        """
        try:
            create = self.__create_scan()
            if not create:
                self.console("Something went wrong, was impossible to create the scan ", "red")
            self.launch_scan()
            counter = 1
            self.console(f"Scan Name: '{self.__name}'", 'yellow')
            self.console(f"Start at: {(start := datetime.now())}", 'yellow')
            last_print_time: datetime = start
            status = self.scan_status()
            self.console(f"Status: {status[1]}", "CYAN")
            while True:
                current = datetime.now()
                elapsed = (current - start).total_seconds() / 3600
                if elapsed > self.__timeout:
                    self.console("Timeout!", 'yellow')
                    break
                if not status[0]:
                    self.console("Something Fail in the status", 'red')
                    break
                if status[1] in ["completed", "aborted", "canceled", "paused", "stopped"]:
                    self.console(f"Scan {status[1]}!", 'yellow')
                    break
                if current - last_print_time >= self.__interval:
                    self.console(f"Status: {status[1]}", "CYAN")
                    last_print_time = current
                counter = (counter % 5) + 1
                time.sleep(5)
                status = self.scan_status()
            if status[1] != "completed":
                self.console(f"Scan didn't complete successfully\tstatus: {status[1]}", "yellow")
                return None
            self.console(f"Status: {status[1]}", "CYAN")
            self.console(f"End at: {(p := datetime.now())}")
            self.console(f"Time elapsed: {(p - start).total_seconds() / 3600:.4f} h")
            results = self.pull_results()
            return results
        except (requests.exceptions.ConnectionError, requests.exceptions.ConnectTimeout,
                urllib3.exceptions.MaxRetryError, urllib3.exceptions.NameResolutionError) as err:
            self.console(f"Something went wrong: {err}", 'red')
            self.console("Retrying....", 'yellow')
            time.sleep(5)
            return self.scan_pull_results()

    def scan_only(self) -> list[dict]:
        """
            Create and launch a new scan
        Parameters
        ----------
            self.__scan_id: int
                            Scan Identifier
            self.__name:    str
                            Scan Name
            self.__folder_name: str
                            Scan's Folder name
        Return
        ------
            list[dict]
                ScanID, Scan Name, Folder_Name
        """
        self.__create_scan()
        self.launch_scan()
        return []

    def run_scan(self) -> list[dict]:
        """
            Run the Scan type chosen in action requirement
        Return
        -----
            list[dict] -> From Scans
        """
        response = list()
        match self.__scan_type:
            case "scan_only":
                response = self.scan_only()
            case "scan_pull_results":
                response = self.scan_pull_results()
            case "pull_results":
                response = self.pull_results()
            case 'load_file':
                if self.__nessus_file is None:
                    response = []
                else:
                    tmp: Integration = Integration()
                    response = tmp.translate(f"{self.__nessus_file}")
                    del tmp
            case 'export_results':
                if not self.__nessus_file:
                    self.__nessus_file = os.getcwd()
                    self.__nessus_file = os.path.join(self.__nessus_file, f"{self.__name}.nessus")
                if self.export_file():
                    self.console("File exported successfully", "green")
                    response = []
        return response
    # endregion


# endregion


def run(reqs: list[dict[str, Any]]) -> dict:
    nessus_scan = NessusScan()
    try:
        nessus_config: dict[str, Any] = parse_reqs(reqs)
        if not nessus_config:
            return {'description': 'Errors found in the data provided', 'status': 'error'}
        nessus_scan.load_config(nessus_config)
        result = nessus_scan.run_scan()
        respuesta: dict = {'results': result, 'status': True}
        home_dir = os.path.expanduser("~")
        desktop = os.path.join(home_dir, "Desktop")
        with open(f"{os.path.join(desktop, 'respuesta.json')}", "w") as f:
            json.dump(respuesta, f, indent=4)
        nessus_scan.console("Successful execution of the plugin", "green")
        nessus_scan.console("Response format {results: <json_data>, status: true}", "yellow")
        return respuesta
    except Exception as err:
        nessus_scan.console(f"Error: {err}", "red")
        return {'description': f'Error: {err}', 'status': 'error'}
