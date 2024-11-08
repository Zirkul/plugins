#!/usr/bin/python
"""
[properties]
@version: 1.0.1
@author: Daniel Hoffman (Aka. Z)
@name: MobSF
@id: mobsf
@description: Mobile Security Framework
@syntax: mobsf
@type: integration
@impact: intrusive
@service: None
@return_type: vuln
[properties]
"""

# region imports
import requests
from requests import Response
from typing import Any, Literal, Callable, Final
from enum import Enum
import json
import os
import re
# endregion

# region properties
Scan_Type: Final = Literal["xapk", "apk", "zip", "ipa", "appx"]

mod_requirements: list[dict[str, Any]] = [
    {'name': 'payload', 'description': 'Path to (IPA, APK, JSON) file, according to the action',
     'type': 'file', 'required': False, 'value': None},
    {'name': 'api_url', 'description': 'URL used for connecting to MobSF',
     'type': 'url', 'required': True, 'value': "http://localhost:8000"},
    {'name': 'api_key', 'description': 'The API key required by MobSF',
     'type': 'string', 'required': True, 'value': "look for it at /api_docs endpoint"},
    {'name': 'action', 'description': 'The action to be performed by the module',
     'type': ['full_scan', 'pull_results', 'import_json_file', 'export_json_file'], 'required': True,
     'value': 'full_scan'},
    {'name': 'hash', 'description': 'MD5 hash from an existing scan ("pull_scan" and "export_json")', 'type': 'string',
     'required': False, 'value': None}
]

requirements: Callable[[], list[dict[str, Any]]] = lambda: mod_requirements


def parse_reqs(reqs: list[dict[str, Any]]) -> dict[str, str]:
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
        """
    options = dict()
    for req in reqs:
        if 'name' in req.keys():
            options[req.get('name', '')] = req.get('value', '')
        elif 'console' in req.keys():
            options['console'] = req.get('console', '')
            options['scanner'] = req.get('scanner', '')
    return options


# endregion

# region Data-Structures
class Action(Enum):
    FULL_SCAN: Final[str] = "full_scan"
    PULL_RESULTS: Final[str] = "pull_results"
    IMPORT_JSON_FILE: Final[str] = "import_json_file"
    EXPORT_JSON_FILE: Final[str] = "export_json_file"


class Mobsf(object):
    """
    MobSF Integration Interface via API

    Attributes
    ----------
        __server:           str
                MobSF server URL      (Required)
        __api_key:          str
                MobSF Api Key         (Required)
        __app:              str
                Application File path (Required)
        __app_name:         str
                Application File Name (Autogenerate)
        __app_hash:         str
                Application MD5 Hash  (Autogenerate)
        __app_scan_type:    str
                Static Analysis type  (Autogenerate)
                Literal["xapk", "apk", "zip", "ipa", "appx"]
        __app_analyzer :    Scan_type
                Analyzer Type         (Autogenerate)
    Properties
    ---------
        self.server         -> self.__server
        self.app            -> self.__app
        self.app_hash       -> self.__app_hash
        self.app_name       -> self.__app_name
        self.app_analyzer   -> self.__app_analyzer
        self.app_scan_type  -> self.__app_scan_type
    Methods
    -------
        load_config:    bool
                    Loads dict/json Configuration File
        upload:         bool
                    Uploads the app file to MobSF server
        scan:           bool
                    Launch Static Scan to the uploaded app
        get_json:       bool
                    Downloads json report file
    """
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
        if col == '':
            print(txt, col)
        else:
            print(txt)

    def __init__(self) -> None:
        self.__server: str | None = None
        self.__api_key: str | None = None
        self.__app: str | None = None
        self.__app_hash: str | None = None  # MD5 File Hash
        self.__app_name: str | None = None
        self.__app_scan_type: Scan_Type | None = None
        self.__app_analyzer: str | None = None
        self.__possible_files: list[str] = []
        self.__action: Action = Action.FULL_SCAN
        self.__action_hash: str | None = None
        self.__temp_report: str = ''
        self.__error: str = ''
        self.console: object = Mobsf.terminal_console
        self.scanner: str = "mobsf"
    # region cls_properties

    @property
    def app(self) -> str:
        return f"{self.__app}"

    @property
    def server(self) -> str:
        return f"{self.__server}"

    @property
    def app_hash(self) -> str:
        return f"{self.__app_hash}"

    @property
    def app_name(self) -> str:
        return f"{self.__app_name}"

    @property
    def app_scan_type(self) -> Scan_Type | None:
        return self.__app_scan_type

    @property
    def app_analyzer(self) -> str:
        return f"{self.__app_analyzer}"

    @property
    def error(self) -> str:
        return f"{self.__error}"

    @error.setter
    def error(self, value: str) -> None:
        self.__error = value
    # endregion

    def load_config(self, data: list[dict[str, Any]]) -> bool:
        """
            Loads config to the module
        Args
        ----
            data:   list[dict[str, Any]]
                    requirements in Zirkul Agent format
        """
        if not data:
            self.console("[ X ] There is no data", "red")
            return False
        local_requirements = parse_reqs(data)
        if not local_requirements:
            return False
        self.console = local_requirements.get("console", Mobsf.terminal_console)
        self.scanner = local_requirements.get("scanner", "mobsf")
        self.console("[ ! ] Loading data...", "orange")
        self.__app = local_requirements.get("payload")
        self.__server = local_requirements.get("api_url")
        if not self.__server.endswith('/'):
            self.__server = f'{self.__server}/'
        self.__api_key = local_requirements.get("api_key")
        self.__action = Action(local_requirements.get("action"))
        self.__action_hash = local_requirements.get("hash")
        if not self.__action_hash and self.__action in {Action.PULL_RESULTS}:
            self.console("[ X ] Hash is required for this action", "red")
            self.console(f"[ ! ] Action: {self.__action}", "orange")
            return False
        self.console("[ + ] Data loaded!", "green")
        return True

    def no_results(self) -> str:
        message: str = "[ ! ] No issues found"
        self.console(message, "orange")
        return message

    def run_action(self) -> list[dict] | None:
        result: list[dict] | None = None
        self.console("[ - ] Choosing Action...", "blue")
        match self.__action:
            case Action.FULL_SCAN:
                self.console(f"[ ! ] Action: {self.__action}", "orange")
                result_issues: list[dict] | None = self.full_scan()
                if result_issues is None:
                    self.error = self.no_results()
                    return []
                result = result_issues
            case Action.PULL_RESULTS:
                self.console(f"[ ! ] Action: {self.__action}", "orange")
                result_issues: list[dict] | None = self.pull_results()
                if result_issues is None:
                    self.error = self.no_results()
                    return []
                result = result_issues
            case Action.IMPORT_JSON_FILE:
                self.console(f"[ ! ] Action: {self.__action}", "orange")
                result_issues: list[dict] | None = self.import_json()
                if result_issues is None:
                    self.error = self.no_results()
                    return []
                result = result_issues
            case Action.EXPORT_JSON_FILE:
                self.console(f"[ ! ] Action: {self.__action}", "orange")
                status: bool = self.export_json()
                if not status:
                    self.error = "[ X ] Export JSON failed"
                    self.console(self.error, "red")
                    return []
                result = []
            case _:
                self.error = "[ x ] Unknown Action"
                self.console(self.error, "red")
        return result

    def full_scan(self) -> list[dict] | None:
        """
        Full Scan Process
        This performed the following actions:
            Upload application to MObSF
            Launch Scan
            Download JSON report as temporally report
            Parse and analyse the JSON report
            Remove the temporally report file
            return the results of the report already analyzed
        Return:
        ------
            list[dict] | None
        """
        integrator: Integration = Integration()
        if not self.__api_key:
            self.error = "[ x ] API Key is required for this action"
            self.console(self.error, "red")
            return None
        if not self.__server:
            self.error = "[ x ] Server URL is required"
            self.console(self.error, "red")
            return None
        if not self.__app:
            self.error = "[ x ] Application file is required for this action"
            self.console(self.error, "red")
            return None
        status = self.upload()
        if not status:
            self.error = "[ x ] Upload failed"
            self.console(self.error, "red")
            return None
        status = self.scan_status()
        if not status:
            self.error = "[ x ] Scan failed"
            self.console(self.error, "red")
            return None
        status = self.get_json()
        if not status:
            self.error = "[ x ] JSON Report failed"
            self.console(self.error, "red")
            return None
        self.console("[ ! ] Processing JSON Report...", "orange")
        result_issues: list[dict] | None = integrator.translate(self.__temp_report)
        self.console(f"[ ! ] Removing Temporary JSON Report {self.__temp_report}...", "orange")
        os.remove(self.__temp_report)
        if result_issues is None:
            self.error = self.no_results()
            return []
        return result_issues

    def pull_results(self) -> list[dict] | None:
        """
        Pulled results from MobSF
        Return:
        ------
            list[dict] | None
        """
        integrator: Integration = Integration()
        if not self.__action_hash:
            self.error = "[ x ] MD5 Hash is required for this action"
            self.console(self.error, "red")
            return None
        if not self.__api_key:
            self.error = "[ x ] API Key is required for this action"
            self.console(self.error, "red")
            return None
        if not self.__server:
            self.error = "[ x ] Server URL is required for this action"
            self.console(self.error, "red")
            return None
        self.__app_hash = self.__action_hash
        status = self.get_json()
        if not status:
            self.error = "[ x ] JSON Report failed"
            self.console(self.error, "red")
            return None
        self.console("[ ! ] Processing JSON Report...", "orange")
        result_issues: list[dict] | None = integrator.translate(self.__temp_report)
        self.console(f"[ ! ] Removing Temporary JSON Report {self.__temp_report}...", "orange")
        os.remove(self.__temp_report)
        if result_issues is None:
            self.error = self.no_results()
            return []
        return result_issues

    def import_json(self) -> list[dict] | None:
        """
        Import JSON File
        Use Translation capabilities to process the JSON file and create issues
        Return:
        ------
            list[dict] | None
                if Success or not
        """
        if not self.__app:
            self.error = "[ x ] JSON file (payload) is required for this action"
            self.console(self.error, "red")
            return None
        if not self.__app.endswith(".json"):
            self.error = "[ x ] JSON file is required for this action"
            self.console(self.error, "red")
            return None
        if not Mobsf.is_json(self.__app):
            self.error = "[ x ] Invalid JSON file"
            self.console(self.error, "red")
            return None
        self.console(f"[ + ] {self.__app} Looks like a valid JSON file", "green")
        integrator: Integration = Integration()
        self.console("[ ! ] Trying to process...", "orange")
        result_issues: list[dict] | None = integrator.translate(self.__app)
        if result_issues is None:
            self.error = self.no_results()
            return []
        self.console("[ + ] Process finished successful", "green")
        if len(result_issues) == 0:
            self.console("[ ! ] Issues array length is 0, could be not a MObSF JSON Report or has no issues to report",
                         "orange")
        return result_issues

    def export_json(self) -> bool:
        """
        Export JSON Report
        Requires:
        --------
            API KEY:    str
                        MobSF API Key
            Server URL: str
                        MobSF Server URL
            Hash:       str
                        MD5 Hash of the scan
        Return:
        -------
            bool
                True if success False otherwise
        """
        if not self.__api_key:
            self.error = "[ x ] API key is required for this action"
            self.console(self.error, "red")
            return False
        if not self.__server:
            self.error = "[ x ] Server URL is required for this action"
            self.console(self.error, "red")
            return False
        if self.__action_hash:
            self.__app_hash = self.__action_hash
            self.__app_name = f"{self.__app_hash}.json"
        elif self.__app.endswith(".ipa") or self.__app.endswith(".apk"):
            val = self.upload()
            if not val:
                self.error = "[ x ] Upload failed"
                self.console(self.error, "red")
                return False
            val = self.scan_status()
            if not val:
                self.error = "[ x ] Scan failed"
                self.console(self.error, "red")
                return False
        self.console("[ ! ] Trying to download JSON Report...", "orange")
        json_file = self.download_json()
        if not json_file:
            self.error = "[ X ] JSON Report failed"
            self.console(self.error, "red")
            return False
        self.__temp_report = f"{self.app_name.rpartition('.')[0]}.json" if self.app_name else "report.json"
        try:
            with open(self.__temp_report, "w") as temp_report:
                json.dump(json_file, temp_report, indent=4)
        except (IOError, json.JSONDecodeError) as err:
            self.error = f"[ X ] Error: {err}"
            self.console(self.error, "red")
            return False
        self.console(f"[ + ] JSON Report saved as {self.__temp_report}", "green")
        return True

    @staticmethod
    def is_json(file_path: str) -> bool:
        """
            Check if file is a valid JSON file
        Args
        ----
            file_path:  str
                        File path to the JSON file
        Return
        ------
            bool
                True if file is a valid JSON file, False otherwise
        """
        if not os.path.isfile(file_path):
            return False
        try:
            with open(file_path, 'r') as f:
                json.load(f)
        except json.JSONDecodeError:
            return False
        return True

    def upload(self, file: str = ...) -> bool:  # type: ignore
        """
            Uploads File to be scanned
            Designed to be used with the same original configuration files,
            it allows to modify the file to be scanned.
        Args
        ----
            file: str   = ... (Ellipsis)
                        Variable not assigned   -> Not Required
        Return
        ------
                True/False      bool
                        True if success False otherwise
        Example
        ------
                    mymobsf = MobSF()
                    mymobsf.load_config(<Config Dictionary>)
                    mymobsf.upload() or mymobsf.upload("new_file.apk")
        """
        if file is ...:
            file = self.app
        else:
            self.__app = file
        headers = {
            "Authorization": self.__api_key,
        }
        response: Response = requests.post(
            url=f"{self.server}api/v1/upload",
            headers=headers,
            files={"file": (file, open(file, 'rb'), 'Application/octet-stream')}
        )
        if response.status_code != 200:
            self.console(f"[ X ] Error: {response.status_code}\t{response.json()}", "red")
            return False
        self.console(f"[ - ] File uploaded successful: {response.status_code}", "blue")
        self.__app_hash = response.json().get("hash")
        self.__app_name = response.json().get("file_name")
        self.__app_scan_type = response.json().get("scan_type")
        self.__app_analyzer = response.json().get("analyzer")
        if self.__app_scan_type == "appx":
            self.console("[ X ] Windows app file not supported!", "red")
            return False
        return True

    def scan_status(self) -> bool:
        """
                    Launch Scan
        Return
        ------
                True/False      bool
                        True if success False otherwise
        Example
        ------
                    mymobsf = MobSF()
                    mymobsf.load_config(<Config Dictionary>)
                    mymobsf.upload()
                    if not mymobsf.scan_status():
                        print("[ X ] Everything bad")
        """
        self.console("[ ! ] Launching Scan...", "orange")
        response: Response = requests.post(
            url=f"{self.server}api/v1/scan",
            headers={
                "Authorization": self.__api_key
            },
            data={
                "scan_type": self.app_scan_type,
                "file_name": self.app_name,
                "hash": self.app_hash,
                "re_scan": 0
            }
        )
        if response.status_code != 200:
            self.console(f"[ X ] Error: Status Code = {response.status_code}\t{response.json()}", "red")
            return False
        self.console("[ + ] Scan Launched successful!", "green")
        return True

    def download_json(self) -> bool | dict[str, Any]:
        """
        Downloads JSON Scan Report
        Return
        ------
                False      bool
                        if not success
                dict[str, Any]  dict
                        if success
        """
        if not self.app_hash:
            self.console("[ X ] MD5 File Hash it's required", "red")
            return False
        response: Response = requests.post(  # Establishing connection to MobSF
            url=f"{self.server}api/v1/report_json",
            headers={
                "Authorization": self.__api_key
            },
            data={
                "hash": self.app_hash
            }
        )
        if response.status_code != 200:
            self.error = f"[ X ] Error: Downloading the json {response.status_code}"
            self.console(self.error, "red")
            self.console(f"[ - ] Status Code: {response.status_code}\t{response.json()}", "blue")
            return False
        return response.json()

    def get_json(self) -> bool:
        """
                            Downloads json scan report
                Return
                ------
                        True/False      bool
                                True if success False otherwise
                Example
                ------
                            mymobsf = MobSF()
                            mymobsf.load_config(<Config Dictionary>)
                            mymobsf.upload()
                            mymobsf.scan_status()
                            if not mymobsf.get_json():
                                print("[ X ] Everything bad")
                """
        data: dict[str, Any] | bool = self.download_json()
        if data is False or not isinstance(data, dict):
            self.error = "[ X ] JSON Report failed"
            self.console(self.error, "red")
            return False
        if not self.__app_scan_type:
            if data.get("app_type").lower() == "swift":
                self.__app_scan_type = "ipa"
            else:
                self.__app_scan_type = "apk"
        self.console("[ ! ] Getting JSON Report...", "orange")
        files = data.get("file_analysis")
        self.console("[ - ] Extracting Files from 'file_analysis'...", "blue")
        if files:  # Check if there are files to  recover in file_analysis key
            for tentative_file in files:
                x = tentative_file.get("files")
                if isinstance(x, str) and chr(0x20) not in x:
                    self.__possible_files.append(x)
                elif isinstance(x, list) and all(isinstance(s, str) for s in x):
                    self.__possible_files.extend(
                        [s for s in x if chr(0x20) not in s]
                    )
                elif isinstance(x, list) and all(isinstance(s, dict) for s in x):
                    self.__possible_files.extend(
                        [s.get("file_path") for s in x if chr(0x20) not in s.get("file_path")]
                    )
            del files  # Deleting the variable (Release memory)
        files = data.get("urls")
        self.console("[ - ] Extracting Files from 'urls'...", "blue")
        if files:  # Check if there are files to be recovered in urls key
            for tentative_file in files:
                x = tentative_file.get("path")  # Extracting the path from the dictionary
                if isinstance(x, str) and chr(0x20) not in x:
                    self.__possible_files.append(x)
                elif isinstance(x, list) and all(isinstance(s, str) for s in x):
                    self.__possible_files.extend(
                        [s for s in x if chr(0x20) not in s]
                        # List comprehension for filtering by whitespaces
                    )
        temp: dict[str, dict] = {}
        self.__possible_files = list(filter(lambda s: not s.endswith(".plist"), self.__possible_files))
        self.console("[ - ] Preparing Code Analysis...", "blue")
        if data.get("app_type") in ["Swift", "iOS (Objective-C)"]:
            self.__possible_files.append("classdump.txt")
        for i in self.__possible_files:
            status_code: int
            response_data: dict
            if not i.split("/", 1)[0].endswith(".app"):
                status_code, response_data = self.get_source(i)
            else:
                status_code, response_data = self.get_source(i.split("/", 1)[1])
            if status_code and status_code == 200 and response_data:
                temp[i] = response_data
        if not data.get("code_analysis"):
            data["code_analysis"] = {"recovered_files": temp}
        else:
            data["code_analysis"].update({"recovered_files": temp})
        self.console("[ ! ] Generating Temporary JSON Report...", "orange")
        if not self.app_name or self.app_name == 'None':
            self.__app_name = data.get("file_name", f"{self.app_hash}.json")
        self.__temp_report = f"{self.app_name.rpartition('.')[0]}.json"
        with open(self.__temp_report, "w") as temp_report:
            json.dump(data, temp_report, indent=4)
        self.console(f"[ + ] Temporal JSON Report: {self.__temp_report}", "green")
        return True

    def get_source(self, tentative_file: str) -> tuple[int, dict] | tuple[None, None]:
        """
        Downloads the source code of the file
        Args:
        -----
            tentative_file: str
                            File path to the file
        Return:
        ------
            tuple[int, dict] if success otherwise tuple[None, None]
        Example:
        -------
            status_code, response_data = self.get_source("file_path")
        """
        if not self.app_hash:
            self.console("[ X ] MD5 File Hash it's required", "red")
            return None, None
        response: Response = requests.post(
            url=f"{self.__server}api/v1/view_source",
            headers={
                "Authorization": self.__api_key
            },
            data={
                "hash": self.__app_hash,
                "file": tentative_file,
                "type": self.__app_scan_type
            }
        )
        if response.status_code != 200:
            self.console(f"[ X ] Error: Downloading the source from {tentative_file} file", "red")
            self.console(f"[ - ] Status Code {response.status_code}", "blue")
            return None, None
        if "file extension not supported" in response.json().get("file").lower():
            return None, None
        self.console(f"[ + ] source downloaded from {tentative_file} file", "green")
        return response.status_code, response.json()


Printer: Callable[[str, str], None] = lambda txt, col: print(txt, col)


class Integration(object):
    def translate(self, input_file: str) -> list[dict] | None:
        if not os.path.isfile(input_file):
            return None
        data_object: dict[str, Any] = self.load_json(input_file)
        if not data_object:
            return None
        vulnerabilities: list = self.extract_vulnerabilities(data_object)
        if not vulnerabilities:
            return None

        return vulnerabilities

    @staticmethod
    def load_json(input_file: str) -> dict[str, Any] | None:
        """
         Loads MobSF JSON Report
         Args:
        ------
            input_file: str
                        File path to the JSON file
        Return:
        -------
            dict[str, Any] | None
        Example:
        -------
            data: dict[str, Any] = Integration.load_json(input_file)
        """
        try:
            with open(input_file, 'r') as f:
                return json.load(f)
        except (IOError, json.JSONDecodeError) as err:
            Printer(f"[ X ] Error: {err}", 'red')
            return None

    def extract_vulnerabilities(self, data: dict[str, Any]) -> list:
        """
        Extracts Vulnerabilities from MobSF JSON Report
        Args:
        -----
            data:   dict[str, Any]
                    JSON Data from MobSF
        Return:
        ------
            vulnerabilities:    list
                                List of dictionary containing the vulnerabilities
        Example:
        -------
            vulnerabilities: list[dict] = Integration.extract_vulnerabilities(data)
        """
        vulnerabilities: list = []
        if data.get("app_type") in ["apk", "xapk"]:
            vulnerabilities.extend(self.android_permissions(data))
            vulnerabilities.extend(self.android_certificate(data))
            vulnerabilities.extend(self.android_obfuscation(data))
            vulnerabilities.extend(self.android_manifest(data))
        elif data.get("app_type") in ["Swift", "iOS (Objective-C)"]:
            vulnerabilities.extend(self.ios_permissions(data))
            vulnerabilities.extend(self.ios_ats(data))
            vulnerabilities.extend(self.ios_binary(data))
            vulnerabilities.extend(self.ios_macho_analysis(data))
            vulnerabilities.extend(self.ios_certificate(data))
            vulnerabilities.extend(self.ios_obfuscated(data))
        else:
            Printer(f"[ X ] Not recognized {data.get('app_type')}", 'red')
            return []
        return vulnerabilities

    @staticmethod
    def clean_string(txt: str, t: str = '') -> str:
        if t == "title":
            txt = txt.replace("_", " ").capitalize()
            # erase every html/xml tags
            txt = re.sub(r'<[^>]*>', '', txt)
            # clean Android [components:some.component] data
            txt = re.sub(r'\[.*\]', '', txt)
        else:
            # html tags like <br> change it for \n
            txt = txt.replace("<br>", "\n")
            # erase every html/xml tags
            txt = re.sub(r'<[^>]*>', '', txt)
        return  txt


    @staticmethod
    def generate_issue(issue: str = '', severity: str = '', details: str = '', confidence: str = 'Low',
                       evidence: str = '', cwe: str = '', owasp: str = '', cvss: int | float = 0.0,
                       cvss_string: str = '', vuln_type: str = "Code", description: str = (
                "This is an autogenerated samble description for mobile issues unknown till now.\n\n"
                "Pleas check the issue information and documentation from OWASP, NVD, CWE for more details.\n"
                "We are working to improve the information and the description of the issues, feel free to "
                "advise us about the improvements."
            )
                       ) -> dict[str, str | int | float]:
        """
        Issue Template to standardize the output
         Args:
        ------
            issue:  str
                    Vulnerability (Issue) name
            severity:   str
                    Severity of the vulnerability
            details:    str
                    Details about the vulnerability
            confidence: str
                    Confidence level of the vulnerability
            evidence:   str
                    Evidence of the vulnerability
            cwe:    str
                    Common Weakness Enumeration
            owasp:  str
                    OWASP Top 10
            cvss:   int | float
                    Common Vulnerability Scoring System
            cvss_string:    str
                    Common Vulnerability Scoring System String
        Return:
        ------
            dict[str, str | int | float]
        Example:
        -------
            issue: dict[str, str | int | float] = Integration.generate_issue(issue, severity, details, confidence,
                                                                            evidence, cwe, owasp, cvss, cvss_string)
        """
        return {
            "issue_type": "vulnerability",
            "vulnerability_type": vuln_type,
            "scan_type": "static scan",
            "type": issue,
            "severity": severity,
            "description": description,
            "details": details,
            "confidence": confidence,
            "tool": "MobSF",
            "remediation": "Not provided by MobSF",
            "evidence": evidence,
            "cwe": cwe,
            "owasp": owasp,
            "cvss": cvss,
            "cvss string": cvss_string,
        }

    # region android
    @staticmethod
    def android_permissions(data: dict[str, Any]) -> list[dict]:
        """
           Extracts Android Permissions Finding
        Args:
        ----
            data:   dict[str, Any]
                    JSON Data from MobSF
        Return:
        ------
            result  list[dict]
                    List of dictionary containing the vulnerabilities
        Example:
        -------
            result: list[dict] = Integration.android_permissions(data)
        """
        result: list = []
        for key, item in data.get("permissions").items():
            match item.get("status"):
                case "dangerous":
                    severity = "Medium"
                case "normal":
                    severity = "Info"
                case _:
                    severity = "Low"
            issue = Integration.generate_issue(
                issue="Android Application asks for too many permissions", severity=severity, details=(
                    f"The application is requesting the permission "
                    f"\"{key}\" ({item.get('description')}) which is "
                    f"normal.\n\nThe reason provided is:\n"
                    f"{item.get('info')}"
                    ), confidence="Moderate", cvss=4.5, cvss_string="AV:P/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:L",
                cwe="CWE-250", owasp="M8:2024", description=(
                    "Android assigns a distinct system identity (Linux user ID and group ID) to every installed app. "
                    "Because each Android app operates in a process sandbox, apps must explicitly request access to "
                    "resources and data that are outside their sandbox. They request this access by declaring the "
                    "permissions they need to use system data and features. Depending on how sensitive or critical the "
                    "data or feature is, the Android system will grant the permission automatically or ask the user "
                    "to approve the request.\n\nApplications should follow the principle of least privilege, "
                    "which is basically to only use the minimum number of permissions needed for the "
                    "application to work."
                )
            )
            if issue:
                result.append(issue)
        return result

    @staticmethod
    def android_certificate(data: dict[str, Any]) -> list[dict]:
        """
        Extracts Android Certificate Findings

        Args:
        ----
            data:   dict[str, Any]
                    JSON Data from MobSF
        Return:
        ------
            result  list[dict]
                    List of dictionary containing the vulnerabilities
        Example:
        -------
            result: list[dict] = Integration.android_certificate(data)
        """
        if not data or not isinstance(data, dict):
            return []
        certificate_analysis: dict[str, Any] = data.get("certificate_analysis")
        if not certificate_analysis or not isinstance(certificate_analysis, dict):
            return []
        certificate_findings: list[dict] = certificate_analysis.get("certificate_findings")
        if not certificate_findings or not isinstance(certificate_findings, list):
            return []
        if not all(isinstance(x, list) for x in certificate_findings):
            return []
        result: list[dict] = []
        for x in data.get("certificate_analysis").get("certificate_findings"):
            finding: dict[str, str | int | float] | None = None
            if x[0].lower() == "warning" and "Janus vulnerability".lower() in x[1].lower():
                finding = Integration.generate_issue(
                    issue="Application vulnerable to Janus", severity="High", details=Integration.clean_string(x[1]),
                    confidence="Moderate", cwe="CWE-434", owasp="M10:2024", cvss=7.8,
                    cvss_string="AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", vuln_type="Mobile", description=(
                        "The Janus vulnerability stems from the ability to add extra bytes to APK files and DEX files."
                        "\n\nThe attacker can place a malicious DEX file at the start of the APK file, depending on "
                        "the target application, this could allow the hacker to access sensitive information stored "
                        "on the device or even take over the device entirely.\n\n"
                        "Janus affects Android devices (Android 5.0 < 8.1) when signed with signature scheme v1."
                    )
                )
            elif x[0].lower() == "bad" and "Application signed with a debug certificate".lower() in x[1].lower():
                finding = Integration.generate_issue(
                    issue="Application signed with a debug certificate", severity="High", confidence="Moderate",
                    cwe="CWE-928", owasp="M9:2016", cvss=7.5, details=Integration.clean_string(x[1]),
                    cvss_string="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L", description=(
                        "Debugging was enabled on the app which makes it easier for reverse engineers to hook a "
                        "debugger to it. This allows dumping a stack trace and accessing debugging helper classes.\n\n"
                        "Any application can open this UNIX socket and thus trick any debuggable application into "
                        "connecting to it. Therefore, shipping a debuggable application means that anyone with "
                        "physical access to the device can execute arbitrary code under that debuggable application's "
                        "permission If the application holds sensitive data, it will be fairly straightforward to "
                        "extract them from the application."
                    )
                )
            elif x[0].lower() == "warning" and "signed with SHA1withRSA".lower() in x[1].lower():
                finding = Integration.generate_issue(
                    issue="Weak Encryption: Inadequate RSA Padding", severity="High", confidence="Low", cwe="CWE-326",
                    details=Integration.clean_string(x[1]), owasp="M9:2024", cvss=7.5,
                    cvss_string="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L", description=(
                        "The method EncryptString() in PasswordEncryptionDecryption.cs performs public key RSA "
                        "encryption without OAEP padding, thereby making the encryption weak."
                    )
                )
            if finding:
                result.append(finding)
        return result

    @staticmethod
    def android_manifest(data: dict[str, Any]) -> list[dict]:
        manifest: dict = data.get("manifest_analysis")
        if not manifest:
            return []
        findings: list[dict] = manifest.get("manifest_findings")
        if not findings:
            return []
        if not isinstance(findings, list):
            Printer(f"Error: invalid format to findings: {type(findings)}", "red")
            return []
        result: list[dict] = []
        components: Callable[[list[str], str], int] = lambda v, y: sum([len(v), len(y.splitlines())])
        cvss_blueprint: dict[str, tuple[int | float, str]] = {
            "Moderate": (5.3, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
            "Critical": (9,"AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H"),
            "High": (7.2, "AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N"),
            "Low": (3.9, "AV:P/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:L"),
            "Info": (0, "")
        }
        for x in findings:
            if not isinstance(x, dict):
                continue
            issue: dict[str, str | int | float] | None = None
            severity: str = x.get("severity", "").capitalize()
            if not severity or severity == "Warning":
                severity = "Low"
            confidence: str
            if severity in ("Critical", "High") and components(x.get("component",0), x.get("name")) > 4:
                confidence = "Strong"
            elif severity == "Medium" and components(x.get("component",0), x.get("name")) > 1:
                confidence = "Moderate"
            else:
                confidence = "Low"
            issue = Integration.generate_issue(
                issue=Integration.clean_string(x.get("rule"), 'title'), severity=severity, confidence=confidence,
                details=f"{x.get('title')}\n{x.get('description')}", vuln_type="Mobile", evidence=(
                    f"{json.dumps({'Name': x.get('name'), 'component': x.get('component', '')}, indent=4)}"
                ), cwe="CWE-250", cvss_string=cvss_blueprint.get(severity)[1], cvss=cvss_blueprint.get(severity)[0]
            )
            result.append(issue)
        return result

    @staticmethod
    def android_obfuscation(data: dict[str, Any]) -> list[dict]:
        """
        Extracts Android Obfuscation Findings
        Args:
        -----
            data:   dict[str, Any]
                    JSON Data from MobSF
        Return:
        ------
            result  list[dict]
                    List of dictionary containing the vulnerabilities
        Example:
        -------
            result: list[dict] = Integration.android_obfuscation(data)
        """
        if not isinstance(data, dict):
            return []
        code_analysis = data.get("code_analysis")
        if not isinstance(code_analysis, dict):
            return []
        recovered_files = code_analysis.get("recovered_files")
        if not isinstance(recovered_files, dict):
            return []
        if not all(isinstance(x, dict) for x in recovered_files.values()):
            return []
        blueprint: dict[str, type] = {
            "title": str,
            "file": str,
            "data": str,
            "type": str,
            "sqlite": dict,
            "version": str
        }
        if not all(key in recovered and isinstance(recovered[key], value)
                   for key, value in blueprint.items() for recovered in recovered_files.values()):
            return []
        keywords: list[str] = ["package", "import", "load", "class", "method", "function",
                               "public", "final", "extends", "service", "override"]
        result: list[dict] = []
        temp: set[str] | list[str] = set()
        for i, x in recovered_files.items():
            if not x.get("data"):
                continue
            if any(y in x.get("data").lower() for y in keywords) and len(x.get("title")) > 4:
                temp.add(i)
        if temp:
            temp = list(temp)
            result.append(
                Integration.generate_issue(
                    issue="Reverse Engineering (Lack of obfuscation)", severity="High",
                    details=(
                        "The product does not use or incorrectly uses a protection mechanism that "
                        "provides defenses against Reverse Engineering."
                    ), description=(
                        "An attacker will typically download the target app from an app store and analyze it within "
                        "its own local environment using a different set of tools.\n\n"
                        "An attacker must perform analysis of the final parent binary to determine its original "
                        "string table, source code, libraries, algorithms, and built-in application resources.\n\n"
                        "An application is said to be susceptible to reverse engineering if an attacker can do "
                        "any of the following:\n\n"
                        "- Clearly understand the contents of the string table of a binary\n\n"
                        "- Accurately perform cross-functional analysis\n\n"
                        "- Obtain a reasonably accurate recreation of the binary's source code Although most "
                        "applications are susceptible to reverse engineering, it is important to examine the "
                        "potential business impact of reverse engineering when considering whether or not to "
                        "mitigate this risk. Check out the examples below for a small taste of what reverse engineering"
                        " can do on its own."
                    ),
                    evidence=f"{temp[0]}",
                    confidence="Low", cwe="CWE-693", owasp="M7:2024", cvss=8.5,
                    cvss_string="AV:L/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:L"
                )
            )
        return result

    # endregion

    # region ios
    @staticmethod
    def ios_permissions(data: dict[str, Any]) -> list[dict]:
        """
        Extracts iOS Permissions Findings
        Args:
        -----
            data:   dict[str, Any]
                    JSON Data from MobSF
        Return:
        ------
            result  list[dict]
                    List of dictionary containing the vulnerabilities
        Example:
        -------
            result: list[dict] = Integration.ios_permissions(data)
        """
        if not data or not isinstance(data, dict):
            return []
        permissions = data.get("permissions")
        if not permissions or not isinstance(permissions, dict):
            return []
        blueprint: dict[str, type] = {
            "description": str,
            "status": str,
            "info": str
        }
        if not all(key in x and isinstance(x[key], value) for x in permissions.values()
                   for key, value in blueprint.items()):
            return []
        result: list = []
        for key, item in data.get("permissions").items():
            severity: str
            match item.get("status"):
                case "dangerous":
                    severity = "Medium"
                case "normal":
                    severity = "Info"
                case _:
                    severity = "Low"
            issue: dict[str, str | int | float] = Integration.generate_issue(
                issue="iOS Application asks for too many permissions", severity=severity, details=(
                    f"The application is requesting the permission "
                    f"\"{key}\" ({item.get('description')}) which is normal.\n\n"
                    f"The reason provided is:\n"
                    f"{item.get('reason')}"
                ), confidence="Moderate", cvss=4.5, cvss_string="AV:P/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:L",
                cwe="CWE-250", owasp="M8:2024", description=(
                    "The app requires access to different components and data that can be overused or used by "
                    "potentially malicious apps. User privacy is paramount. To help people trust your app, it's "
                    "crucial to be transparent about what privacy-related data and resources you need and how you use "
                    "them. For example, you must request permission to access:\n\n"
                    "- Personal data, including location, health, financial, contact, and other personally "
                    "identifiable information.\n\n"
                    "- User-generated content such as emails, messages, calendar data, contacts, game information, "
                    "Apple Music activity, HomeKit data, and audio, video, and photo content.\n\n"
                    "- Protected resources such as Bluetooth peripherals, home automation features, Wi-Fi connections,"
                    " and local networks.\n\n"
                    "- Device capabilities such as camera and microphone."
                )
            )
            if issue:
                result.append(issue)
        return result

    @staticmethod
    def ios_ats(data: dict[str, Any]) -> list[dict]:
        """
        Extracts iOS ATS Findings
        Args:
        -----
            data:   dict[str, Any]
                    JSON Data from MobSF
        Return:
        ------
            result  list[dict]
                    List of dictionary containing the vulnerabilities
        Example:
        -------
            result: list[dict] = Integration.ios_ats(data)
        """
        result: list = []
        ats_analysis: dict = data.get("ats_analysis")
        temp_data: list[dict] = ats_analysis.get("ats_findings") if ats_analysis else []
        if not temp_data:
            return result
        for x in temp_data:
            issue: dict[str, str | int | float] | None = None
            if "App Transport Security AllowsArbitraryLoads is allowed".lower() == x.get("issue").lower():
                issue = Integration.generate_issue(
                    issue="Application Transport Security (ATS) with AllowsArbitraryLoads enabled",
                    severity="Low", details=Integration.clean_string(x.get("description")), confidence="Moderate",
                    vuln_type="Mobile", description=(
                        "App Transport Security restrictions are disabled for all network connections. "
                        "Disabling ATS means that unsecured HTTP connections are allowed. HTTPS connections are also "
                        "allowed and are still subject to default server trust evaluation. However, extended security "
                        "checks like requiring a minimum Transport Layer Security (TLS) protocol versionare disabled. "
                        "This setting is not applicable to domains listed in NSExceptionDomains."
                    )
                )
            elif "Insecure communication to ".lower() in x.get("issue").lower():
                issue = Integration.generate_issue(
                    issue="Insecure communication allowed", severity="Medium", confidence="Moderate",
                    details=Integration.clean_string(x.get("description")),
                    evidence=x.get("issue"), vuln_type="Mobile", description=(
                        "Set the value for this key to True to allow insecure HTTP loads for the given domain, or "
                        "to be able to loosen the server trust evaluation requirements for HTTPS connections to the "
                        "domain, as described in Performing Manual Server Trust Authentication.\n\n"
                        "Using this key doesn’t by itself change default server trust evaluation requirements for HTTPS"
                        " connections. Using only this key also doesn’t change the TLS or forward secrecy requirements"
                        " imposed by ATS. As a result, you might need to combine this key with the "
                        "NSExceptionMinimumTLSVersion or NSExceptionRequiresForwardSecrecy key in certain cases.\n\n"
                        "This key is optional. The default value is False."
                    )
                )
            elif "NSIncludesSubdomains set to TRUE for ".lower() in x.get("issue").lower():
                issue = Integration.generate_issue(
                    issue="ATS exceptions for subdomains", severity="Low", evidence=x.get("issue"),
                    details=Integration.clean_string(x.get("description")), confidence="Moderate"
                )

            elif "NSExceptionRequiresForwardSecrecy set to NO for ".lower() in x.get("issue").lower():
                issue = Integration.generate_issue(
                    issue="Perfect Forward Secrecy Not Enforced", severity="Low",
                    details=Integration.clean_string(x.get("description")), confidence="Moderate",
                    evidence=x.get("issue"), vuln_type="Code", description=(
                        "Perfect Forward Secrecy (PFS), also called forward secrecy (FS), refers to an encryption "
                        "system that changes the keys used to encrypt and decrypt information frequently and "
                        "automatically. This ongoing process ensures that even if the most recent key is obtained,"
                        " a minimal amount of sensitive data is exposed.\n\n"
                        "This key is optional. The default value is YES, which limits the accepted ciphers to those "
                        "that support PFS through Elliptic Curve Diffie-Hellman Ephemeral (ECDHE) key Exchange."
                    )
                )
            elif "NSExceptionMinimumTLSVersion set to ".lower() in x.get("issue").lower():
                issue = Integration.generate_issue(
                    issue="Insecure communication allowed to deprecated protocol", severity="Low",
                    details=Integration.clean_string(x.get("description")), confidence="Moderate",
                    evidence=x.get("issue"), description=(
                        "Set the value for this key to True to allow insecure HTTP loads for the given domain, "
                        "or to be able to loosen the server trust evaluation requirements for HTTPS connections "
                        "to the domain, as described in Performing Manual Server Trust Authentication.\n\n"
                        "Using this key doesn’t by itself change default server trust evaluation requirements "
                        "for HTTPS connections. Using only this key also doesn’t change the TLS or forward secrecy "
                        "requirements imposed by ATS. As a result, you might need to combine this key with the "
                        "NSExceptionMinimumTLSVersion or NSExceptionRequiresForwardSecrecy key in certain cases."
                        "\n\nThis key is optional. The default value is False."
                    )
                )
            if issue:
                result.append(issue)
        return result

    @staticmethod
    def ios_binary(data: dict[str, Any]) -> list[dict]:
        """
        Extracts iOS Binary Analysis Findings
        Args:
        -----
            data:   dict[str, Any]
                    JSON Data from MobSF
        Return:
        ------
            result  list[dict]
                    List of dictionary containing the vulnerabilities
        Example:
        -------
            result: list[dict] = Integration.ios_binary(data)
        """
        if not data or not isinstance(data, dict):
            return []
        bin_analysis: dict[str, dict] = data.get("binary_analysis")
        if not bin_analysis:
            return []
        binary_analysis: dict[str, dict] = bin_analysis.get("findings")
        if not binary_analysis:
            return []
        issue_blueprint: dict[str, type] = {
            "detailed_desc": str,
            "severity": str,
            "cvss": int | float,
            "cwe": str,
            "masvs": str,
            "owasp-mobile": str
        }
        if not all(key in x and isinstance(x[key], value) for x in binary_analysis.values()
                   for key, value in issue_blueprint.items()):
            return []
        result: list = []
        for x, i in binary_analysis.items():
            issue: dict[str, str | int | float] | None = None
            if "Logging function".lower() in x.lower() and "for logging".lower() in i.get("detailed_desc").lower():
                owasp: str = "M9:2024"
                masvs: str = i.get('masvs', "MSTG-STORAGE-3")
                issue = Integration.generate_issue(
                    issue="Log Forging", severity=i.get("severity", "High").capitalize(),
                    details=Integration.clean_string(i.get("detailed_desc")), confidence="Low", evidence=(
                        f"This issue is related to MASVS section {masvs} "
                        f"and OWASP Mobite Top 10 section {owasp} "
                    ), owasp=owasp, cwe=i.get("cwe", "CWE-532"),  cvss=6.8,
                    cvss_string="AV:A/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H", description=(
                        "The method Logit() in LogUtil.cs writes unvalidated user input to the log on "
                        "line 204. An attacker could take advantage of this behavior to forge log entries or "
                        "inject malicious content into the log."
                    )
                )
            elif ("insecure Random function".lower() in x.lower() and
                  "insecure Random function".lower() in i.get("detailed_desc").lower()):
                masvs: str = i.get('masvs', "MSTG-CRYPTO-6")
                owasp: str = "M10:2024"
                issue = Integration.generate_issue(
                    issue="Weak Random Number Generator", severity=i.get("severity", "Medium").capitalize(),
                    details=Integration.clean_string(i.get("detailed_desc")), evidence=(
                        f"This issue is related to MASVS section {masvs} "
                        f"and OWASP Mobile Top 10 section {owasp}"
                    ), owasp=owasp, cwe=i.get("cwe", "CWE-330"), cvss=5.5,
                    cvss_string="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", description=(
                        "The standard use of pseudo-random number generators [PRNGs] is bad practice when "
                        "implementing security mechanisms since the attacker can guess the logic behind and "
                        "predict the generated random numbers. In this case, the confidentiality and/or integrity "
                        "of the application may be affected."
                    )
                )
            elif ("use of malloc function".lower() in x.lower() and
                  "The binary may use _malloc".lower() in i.get("detailed_desc").lower()):
                owasp: str = "M7:2024"
                masvs: str = i.get('masvs', "MSTG-CODE-8")
                issue = Integration.generate_issue(
                    issue="Memory Leak", severity=i.get("severity", "High").capitalize(), confidence="Low",
                    details=Integration.clean_string(i.get("detailed_desc")), evidence=(
                        f"This issue is related to MASVS section {masvs} "
                        f"and OWASP Mobile Top 10 section {owasp}"
                    ), owasp=owasp, cwe=i.get("cwe", "CWE-401"), cvss=7.5,
                    cvss_string="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", description=(
                        "Memory leaks occur when a program allocates memory from the system but fails to return it, "
                        "which can lead to a system running out of memory. This can cause the system to slow down or "
                        "crash, and can also lead to data corruption or loss."
                    )
                )
            elif ("insecure API".lower() in x.lower() and
                  "insecure API".lower() in i.get("detailed_desc").lower()):
                owasp = "M8:2024"
                masvs = i.get('masvs', "MSTG-CODE-8")
                issue = Integration.generate_issue(
                    issue="Binary makes use of insecure API(s)", severity=i.get("severity", "High").capitalize(),
                    confidence="Moderate", details=Integration.clean_string(i.get("detailed_desc")), evidence=(
                        f"This issue is related to MASVS section {masvs} "
                        f"and OWASP Mobile Top 10 section {owasp}"
                    ),
                    owasp=owasp, cwe=i.get("cwe", "CWE-676"), cvss=7.5,
                    cvss_string="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", description=(
                        "The use of insecure APIs can lead to buffer overflows, which can be exploited by attackers to "
                        "execute arbitrary code. This can lead to a system crash, data corruption, or the execution of"
                        " malicious code."
                    )
                )
            else:
                issue = Integration.generate_issue(
                    issue=x, severity=i.get("severity", "Low"), cvss=i.get("cvss"),
                    cwe=i.get("cwe"), details=Integration.clean_string(i.get("detailed_desc")), confidence="Low"
                )
            if issue:
                result.append(issue)
        return result

    @staticmethod
    def ios_certificate(data: dict[str, Any]) -> list[dict]:
        """
        Extracts iOS Certificate Analysis Findings
        Args:
        -----
            data:   dict[str, Any]
                    JSON Data from MobSF
        Return:
        ------
            result  list[dict]
                    List of dictionary containing the vulnerabilities
        Example:
        -------
            result: list[dict] = Integration.ios_certificate(data)
        """
        result: list[dict] = []
        if not data or not isinstance(data, dict):
            Printer("[ X ] - No data provided", 'red')
            return []
        file_analysis: list[dict] | None = data.get("file_analysis", None)
        if not file_analysis or not isinstance(file_analysis, list):
            Printer("[ X ] - No file analysis", 'red')
            return []
        recovered_files: dict[str, dict] | None = data.get("code_analysis", {}).get("recovered_files", None)
        if not recovered_files or not isinstance(recovered_files, dict):
            Printer("[ X ] - No recovered files in cert analysis", 'red')

        for x in file_analysis:
            if not isinstance(x, dict):
                continue
            if "Certificate/Key Files Hardcoded inside the App".lower() in x.get('issue').lower():
                files: str = '\n'.join(file.get('file_path') for file in x.get('files'))
                evidence: str = "Check the files:\n" + '\n'.join(efile.get("file_path") for efile in x.get("files"))
                issue: dict[str, str | int | float]
                issue = Integration.generate_issue(
                    issue="Key Management: Hardcoded Encryption Key", severity="High", evidence=evidence,
                    cwe="CWE-321", owasp="M9:2024", cvss=7.8, details=(
                        "Using a hard-coded cryptographic key significantly increases the risk "
                        "that encrypted data may be recovered. If someone gains access to the "
                        "source code or the environment where the key is stored, they can "
                        "easily extract the key and decrypt the data. Therefore, it's crucial "
                        "to use more secure key management practices to protect sensitive "
                        "information."
                    ), cvss_string="AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", description=(
                        "Hardcoded encryption keys can compromise security in a way that cannot be easily remedied."
                    )
                )
                issue["file name"] = files
                break
        return result

    @staticmethod
    def ios_obfuscated(data: dict[str, Any]) -> list[dict]:
        """
        Extracts iOS Obfuscation Findings
        Args:
        -----
            data:   dict[str, Any]
                    JSON Data from MobSF
        Return:
        ------
            result  list[dict]
                    List of dictionary containing the vulnerabilities
        Example:
        -------
            result: list[dict] = Integration.ios_obfuscated(data)
        """
        if not data or not isinstance(data, dict):
            return []
        code_analysis = data.get("code_analysis", None)
        if not code_analysis or not isinstance(code_analysis, dict):
            return []
        recovered_files = code_analysis.get("recovered_files", None)
        if not recovered_files or not isinstance(recovered_files, dict):
            return []
        keywords: list[str] = ["public", "public method", "Protocol", "private", "@interface", "@implementation",
                               "class", "method", "function", "public", "final", "extends", "service", "override",
                               "import", "load", "class", "function", "extends", "NSObject<OS_dispatch_queue>",
                               "dispatch_queue_t", "dispatch_async", "dispatch_sync", "dispatch_once",
                               "dispatch_after", "dispatch_group_t", "dispatch_group_async", "dispatch_group_notify", ]
        result: list[dict] = []
        for i, x in recovered_files.items():
            if not x.get("data"):
                continue
            if any(y in x.get("data").lower() for y in keywords) and len(x.get("title")) > 4:
                scope: str = x.get('data').split('\n')[0]
                issue = Integration.generate_issue(
                    issue="Reverse Engineering (Lack of obfuscation)", severity="High",
                    details=(
                       "Code obfuscation as a defence-in-depth measure is important to"
                       " increase the resilience of applications against reverse "
                       "engineering and specific client-side attacks. \n"
                       "It adds an additional layer of security to the application, "
                       "making it more difficult for attackers to successfully reverse"
                       " engineering and extract valuable intellectual property or "
                       "sensitive data from it."
                    ), confidence="Low", cwe="CWE-693", owasp="M7:2024", cvss=8.5,
                    cvss_string="AV:L/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:L", evidence=scope, description=(
                        "An attacker will typically download the target app from an app store and analyze "
                        "it within its own local environment using a different set of tools.\n\n"
                        "An attacker must perform analysis of the final parent binary to determine its "
                        "original string table, source code, libraries, algorithms, and built-in application resources."
                        "\n\nAn application is said to be susceptible to reverse engineering if an attacker can do "
                        "any of the following:\n\n"
                        "- Clearly understand the contents of the string table of a binary\n\n"
                        "- Accurately perform cross-functional analysis\n\n"
                        "- Obtain a reasonably accurate recreation of the binary's source code Although "
                        "most applications are susceptible to reverse engineering, it is important to examine "
                        "the potential business impact of reverse engineering when considering whether or "
                        "not to mitigate this risk. Check out the examples below for a small taste of what "
                        "reverse engineering can do on its own."
                    )
                )
                issue["file name"] = i
                result.append(issue)
        return result

    @staticmethod
    def ios_macho_analysis(data: dict[str, Any]) -> list[dict]:
        """
        Extracts iOS Mach-O Analysis Findings
        Args:
        -----
            data:   dict[str, Any]
                    JSON Data from MobSF
        Return:
        ------
            result  list[dict]
                    List of dictionary containing the vulnerabilities
        Example:
        -------
            result: list[dict] = Integration.ios_macho_analysis(data
        """
        if not data or not isinstance(data, dict):
            return []
        macho_analysis = data.get("macho_analysis", None)
        if not macho_analysis or not isinstance(macho_analysis, dict):
            return []
        result: list[dict] = []
        for x, i in macho_analysis.items():
            if not isinstance(i, dict):
                continue
            flag: str | None = None
            match x:
                case "nx":
                    flag = "has_nx"
                case "pie":
                    flag = "has_pie"
                case "arc":
                    flag = "has_arc"
                case "stack_canary":
                    flag = "has_canary"
                case "rpath":
                    flag = "has_rpath"
                case "code_signature":
                    flag = "has_code_signature"
                case "encrypted":
                    flag = "is_encrypted"
                case "symbol":
                    flag = "is_stripped"
            issue: dict[str, str | int | float] | None = None
            if i.get(flag) is False:
                issue = Integration.generate_issue(
                    issue="Insufficient Binary Protection", severity="High", confidence="Moderate",
                    details=Integration.clean_string(i.get("description")), evidence=(
                        json.dumps({x: {flag: i.get(flag), "severity": i.get("severity")}}, indent=4)
                    ), owasp="M7:2023", cwe="CWE-693", cvss=8.2,
                    cvss_string="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N", description=(
                        "The lack of binary protections within a mobile application exposes the application and its "
                        "owner to a wide variety of technical and business risks if the underlying application "
                        "is insecure or exposes sensitive intellectual property. The lack of binary protections "
                        "results in a mobile application that an adversary can quickly analyze, reverse engineer, "
                        "and modify.\n\n"
                        "An application binary could be subject to two types of attacks:\n\n"
                        "- Reverse engineering: The application binary is decompiled and scanned "
                        "for valuable information such as secret keys, algorithms, or vulnerabilities.\n\n"
                        "- Code manipulation: The application binary is manipulated, for example, to remove license "
                        "checks, bypass paywalls, or obtain other user benefits. Alternatively, the application can "
                        "be manipulated to contain malicious code."
                    )
                )
            if issue:
                result.append(issue)
        return result
    # endregion


# endregion

def run(reqs: list[dict[str, Any]]) -> dict:
    """
    Runs the MobSF Scan
    Args:
    ----
        reqs:   list[dict[str, Any]]
                List of dictionaries containing the required parameters
    Return:
    ------
        dict[str, Any]
    Example:
    -------
        response: dict[str, Any] = run(reqs)
    """
    mobsf: Mobsf = Mobsf()
    try:
        if not mobsf.load_config(reqs):
            return {"description": "Invalid Configuration", "status": "error"}
        global Printer
        Printer = mobsf.console
        result_issues = mobsf.run_action()
        if result_issues is None:
            return {"description": mobsf.error, "status": "error"}
        response = {"results": result_issues, "status": True}
        #for i in json.dumps(response, indent=4).split("\n"):
        #    mobsf.console(f"[ - ] => {i}", "blue")
        return response
    except Exception as err:
        return {"description": f"Error: {err}", "status": "error"}


if __name__ == "__main__":
    myobj = Mobsf()
    integration: Integration = Integration()
    myobj.load_config([
        {'name': 'api_url', 'value': "https://mobsf.live/"},
        {'name': 'api_key', 'value': "<API-Key Here>"},
        {'name': 'payload', 'value': r"AndroGoat.apk"}
    ])
    myobj.upload()
    myobj.scan_status()
    if not myobj.get_json:
        print("[ X ] - Something went wrong with the JSON file")
    file: str = f"{myobj.app_name.rpartition('.')[0]}.json"
    issues: list[dict] | None = integration.translate(file)
    if not issues:
        print("[ X ] - No issues found")
    os.remove(file)
    print(json.dumps(issues, indent=4))
    with open("result.json", "w") as f:
        json.dump(issues, f, indent=4)

