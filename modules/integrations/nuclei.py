#!/usr/bin/python
"""
[properties]
@version: 1.0.1
@author: Daniel Hoffman (Aka. Z)
@name: Nuclei
@id: nuclei
@description: Nuclei vulnerability scanner
@syntax: nuclei
@type: integration
@impact: intrusive
@service: None
@return_type: vuln
[properties]
"""
import time
# region imports
from typing import Any, Callable, Final
from shlex import quote as shlex_quote
from dataclasses import dataclass
from functools import wraps
from enum import Enum
import subprocess
import logging
import inspect
import json
import sys
import os
# endregion

# region required
VERSION: Final[str] = "1.0.1"

mod_requirements: list[dict[str, Any]] = [
    {'name': 'target', 'description': 'Target host/url', 'type': 'string', 'required': False, 'value': None},
    {'name': 'targets_file', 'description': 'File containing the list of targets', 'type': 'file', 'required': False,
     'value': None},
    {'name': 'template', 'description': 'Template file to be used (default will be used if omitted)', 'type': 'string',
     'required': False, 'value': None},
    {'name': 'user_agent', 'description': 'User-Agent to be used in the request', 'type': 'string', 'required': True,
     'value': f"Zirkul/Nuclei {VERSION}"},
    {"name": "concurrency", "description": "Maximum number of concurrent requests", "type": "integer",
     "required": False, "value": 20},
    {"name": "proxy", "description": "Proxy used to send requests", "type": "string", "required": False, "value": None},
    {"name": "action", "description": "Action to be performed", "type": ["scan", "scan_export_json_file",
                                                                         "import_json_file"],
     "required": True, "value": "scan"},
    {"name": "options", "description": "Custom settings using nuclei command line options", "type": "string",
     "required": False, "value": "-headless"},
    {"name": "json_file", "description": "Local JSON file name (Just for import/export actions)", "type": "string",
     "required": False, "value": None},
    {"name": "scan_type", "description": "Type of vulnerability scan", "type": "string", "required": True,
     "value": "Dynamic Scan"},
    {"name": "nuclei_path", "description": "If nuclei is not in path, add custom path (e.g. C:\\binaries\\nuclei.exe)",
     "type": "file", "required": False, "value": None},
    {"name": "prefix", "description": "Specific execution Shell Context (In Windows it's better with pwsh)",
     "type": ["pwsh", "cmd", "bash", "sh", "none"], "required": False, "value": "none"}
]

# For Debug purposes Prints the Python Version
requirements: Callable[[], list[dict[str, Any]]] = lambda: mod_requirements

out_handler = logging.StreamHandler(sys.stdout)
out_handler.setLevel(logging.INFO)
separator: str = "\033[1;37m-->\033[0m"
formatter: str = (
    f"[\033[36mLine\033[0m] \033[95m%(z_lineno)d\033[0m\t{separator}\t%(message)s"
)
logging.basicConfig(level=logging.INFO, handlers=[out_handler], format=formatter)


def parse_reqs(reqs: list[dict[str, Any]]) -> dict[str, Any]:
    required: dict[str, Any] = {}
    for req in reqs:
        if "name" in req.keys():
            required[req.get('name')] = req.get('value')
        if "console" in req.keys() and "scanner" in req.keys():
            required["console"] = req.get("console")
            required["scanner"] = req.get("scanner")
    return required


def exist_nuclei() -> bool:
    flag: bool = False
    try:
        result_command: subprocess.CompletedProcess = subprocess.run(
            [f"{nuclei_path}", "-h"],
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        if result_command.returncode == 0:
            flag = True
    except Exception as err:
        console(f"[ X ] Error: {err}", "red")
        flag = False
    return flag


def debug_console(message: str, color: str) -> None:
    # get line from previous frame
    frame_info = inspect.getouterframes(inspect.currentframe())[1]
    match color:
        case "red":
            logging.error(f"\033[31m{message}\033[0m", extra={"z_lineno": frame_info.lineno})
        case "orange":
            logging.warning(f"\033[33m{message}\033[0m", extra={"z_lineno": frame_info.lineno})
        case "green":
            logging.info(f"\033[92m{message}\033[0m", extra={"z_lineno": frame_info.lineno})
        case "blue":
            logging.info(f"\033[94m{message}\033[0m", extra={"z_lineno": frame_info.lineno})
        case _:
            logging.critical(f"\033[35m{message}\033[0m\t|\tNo color {color}",
                             extra={"z_lineno": frame_info.lineno})


def command_printer(func: Callable) -> Callable:
    @wraps(func)
    def wrapper(*args, **kwargs) -> str:
        local_result: subprocess.CompletedProcess = func(*args, **kwargs)
        console(f"Execution Status Code: {local_result.returncode}", "orange")
        console("stdout:", "orange")
        for line in local_result.stdout.decode("utf-8").rstrip("\n").splitlines():
            console(f"[ - ] => {line}", "blue")
        if local_result.stderr:
            console("stderr:", "orange")
            for line in local_result.stderr.decode("utf-8").rstrip("\n").splitlines():
                console(f"[ X ] => {line}", "red")
        return local_result.stdout.decode("utf-8").rstrip("\n")
    return wrapper


def create_dummy_scanner():
    dummy = lambda: None  # noqa
    console("[ ! ] Adding run_shell_command function to scanner", "orange")
    dummy.run_shell_command = command_printer(lambda x: subprocess.run(
        x.split(chr(0x20)),  # noqa
        shell=True,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    ))
    return dummy
# endregion

# region Integration
class Integration(object):

    @staticmethod
    def translate(*, input_file: str) -> list[dict] | None:
        console("[ ! ] Process: translate", "orange")
        if not input_file:
            console("[ X ] Error: No input file provided", "red")
            return None
        if not Integration.valid_json_file(input_file):
            console("[ X ] Error: Invalid JSON file", "red")
            return None
        try:
            console("[ - ] Reading JSON file...", "blue")
            data: list[dict] = Integration.get_json_data(json_file=input_file)
            if not data:
                console("[ X ] Error: No data found in JSON file", "red")
                return None
            console("[ - ] Processing issues...", "blue")
            issues: list[dict[str, str | int | float]] = Integration.process_issues(issues=data)
            return issues
        except Exception as e:
            console(f"[ X ] Error: {e}", "red")
            return None

    @classmethod
    def process_issues(cls, issues: list[dict[str, Any]]) -> list[dict[str, str | int | float]]:
        console("[ ! ] Process: process_issues", "orange")
        if not isinstance(issues, list):
            console("[ X ] Issues is not a list", "red")
            return []
        local_result: list[dict[str, str | int | float]] = []
        for issue in issues:
            if not issue:
                continue
            if not isinstance(issue, dict):
                continue
            info: dict[str, Any] = issue.get('info', {})
            affected: str = cls.get_affected_resources(
                url=issue.get('host'),
                ip=issue.get('ip', "")
            )
            classification: dict = info.get("classification", {})
            details: str
            if info:
                details = info.get("description", info.get("name"))
            else:
                details = issue.get("template-id")
            issue_blueprint: dict[str, str | int | float] = cls.gen_issue_blueprint(
                issue_type=(issue.get('type'), int(issue.get('port', 80))), details=details,
                severity=info.get("severity", "low"), evidence=Integration.generate_evidence(issue),
                affected_resource=affected, attack=issue.get("curl-command", f"nuclei -u {issue.get('host')}"),
                confidence=Integration.calculate_confidence(
                    severity=info.get("severity", "low"), curl_command=issue.get("curl-command", ""),
                    extracted_results=issue.get("extracted-results", []), metadata=info.get("metadata", {}),
                    classification=info.get("classification", {}), remediation=info.get("remediation", "")
                ), vtype=info.get("name", issue.get("template-id")), port=int(issue.get("port", 80))
            )
            if issue_blueprint.get("port") not in (80, 443):
                issue_blueprint['scan_type'] = "Network scan"
            if issue_blueprint.get("vulnerability_type") == "web":
                issue_blueprint["url"] = issue.get("url")
                if not issue_blueprint.get("url"):
                    issue_blueprint["url"] = f"{issue.get('scheme', 'http')}://{issue.get('host')}"
                if issue.get("request"):
                    issue_blueprint["request"] = issue.get("request")
                if issue.get("response"):
                    issue_blueprint["response"] = issue.get("response")
            issue_blueprint['protocol'] = cls.choose_protocol(issue_blueprint)
            if info.get("remediation"):
                if info.get("reference"):
                    ref: str = '\n'.join(info.get('reference'))
                    issue_blueprint["remediation"] = (
                        f"{info.get('remediation')}"
                        "\n"
                        f"Reference:{ref}"
                    )
                else:
                    issue_blueprint["remediation"] = info.get("remediation")
            issue_blueprint["references"] = [{
                "title": f"Nuclei Template {issue.get('template-id')}",
                "url": f"https://nuclei-templates.netify.app/#q={issue.get('template-id')}"
            }]
            if classification:
                if classification.get("cve-id"):
                    issue_blueprint["cve"] = classification.get("cve-id")[0]
                if classification.get("cwe-id"):
                    issue_blueprint["cwe"] = classification.get("cwe-id")[0]
                if classification.get("cvss-score"):
                    issue_blueprint["cvss"] = classification.get("cvss-score")
                else:
                    issue_blueprint["cvss"] = 0
                if classification.get("cvss-metrics"):
                    issue_blueprint["cvss string"] = classification.get("cvss-metrics")
            local_result.append(issue_blueprint)
        return local_result

    @staticmethod
    def choose_protocol(issue: dict) -> str:
        if issue.get("vulnerability_type") == "web":
             return "http"
        service: dict[int, str] = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns', 80: 'http', 88: 'kerberos', 110: 'pop3',
            111: 'rpcbind', 135: 'msrpc', 139: 'netbios', 143: 'imap', 389: 'ldap', 443: 'https', 445: 'smb',
            465: 'smtps', 1433: 'mssql', 1521: 'oracle', 3306: 'mysql', 3389: 'rdp', 5432: 'postgresql', 5900: 'vnc',
            5984: 'couchdb', 5985: 'winrm', 6379: 'redis', 8080: 'http', 8443: 'https', 9090: 'http', 9091: 'https'
        }
        return service.get(issue.get('port', 80), 'Unknown')

    @staticmethod
    def generate_evidence(issue: dict[str, Any]) -> str:
        timestamp: str = issue.get('timestamp', "")
        matcher_name: str = issue.get('matcher-name', "")
        extracted_results: list = issue.get("extracted-results", [])
        metadata: dict = issue.get("info").get("metadata", {})
        results: str = ""
        if timestamp:
            results += (
                f"Timestamp: {timestamp.split('T')[0].replace('-', '/')} "
                f"{timestamp.split('T')[1].rpartition('-')[0]} "
                f"UTC{''.join(timestamp.split('T')[1].rpartition('-')[1:])}"
            )
        if matcher_name:
            results += f"\nMatcher Name: {matcher_name}"
        if extracted_results:
            results += "\nExtracted Results:"
            for i in extracted_results:
                results += f"\n\t{i}"
        if metadata.get("verified") is True:
            results += "\nMetadata:"
            for key, value in metadata.items():
                results += f"\n\t{key}:"
                if isinstance(value, list):
                    for v in value:
                        results += f"""\n\t\t{str(v).replace('"', '`')}"""
                if isinstance(value, dict):
                    for k, v in value.items():
                        results += f"""\n\t\t{k}: {str(v).replace('"', '`')}"""
                else:
                    results += f"""\n\t\t{str(value).replace('"', '`')}"""
        return results

    @staticmethod
    def get_affected_resources(url: str = "", ip: str = "") -> str:
        if ":" in url:
            url = url.split(":")[0]
        response: str
        if url and ip:
            response = f"{url}\n({ip})"
        elif url and not ip:
            response = url
        elif ip and not url:
            response = ip
        else:
            response = ""
        return response

    @staticmethod
    def get_json_data(json_file: str) -> list[dict]:
        data: list[dict] = []
        if Integration.valid_json_file(json_file):
            with open(json_file, 'r') as f:
                data = json.load(f)
        return data

    @staticmethod
    def valid_json_file(file: str) -> bool:
        local_result: bool = False
        console("[ - ] Checking if file is valid JSON...", "blue")
        if os.path.isfile(file):
            try:
                json_file: dict
                with open(file, 'r') as f:
                    json_file = json.load(f)
                if json_file:
                    local_result = True
                    console("[ + ] Is JSON file", "green")
            except Exception as e:
                console(f"[ X ] Error: {e}", "red")
                local_result = False
        return local_result

    @staticmethod
    def vuln_by_blueprint(*, vulnerability_type: str, port: int) -> str:
        local_result: str
        if vulnerability_type in ["http", "https"] or port in [80, 443]:
            local_result = "web"
        else:
            local_result = "network"
        return local_result

    @staticmethod
    def gen_issue_blueprint(*, issue_type: tuple[str, int] = None, details: str = "", severity: str = "",
                            attack: str = "", affected_resource: str = "", evidence: str = "", confidence: str = "Low",
                            vtype: str = "", port: int = 80, description: str = (
                    "This is a sample vulnerability description, you can replace it with the actual description"
                    "\n\nIf you're seeing this message, it means that the description still is not available"
                    " please feel free to add it or contact us for update this issue."
            )
                            ) -> dict[str, str | int | float]:
        return {
            "issue_type": "vulnerability",
            "vulnerability_type": Integration.vuln_by_blueprint(vulnerability_type=issue_type[0], port=issue_type[1]),
            "scan_type": SCAN_TYPE,
            "type": vtype,
            "description": description,
            "details": details,
            "severity": severity,
            "affected resources": affected_resource,
            "port": port,
            "transport": "TCP",
            "tool": "Nuclei",
            "attack": attack,
            "evidence": evidence,
            "proof of concept": (
                "Follow the steps below to reproduce this vulnerability:\n"
                "1.Use a cybersecurity linux distribution such as Kali or ParrotOS to ensure that the tools "
                "are available.\n"
                "2.From the terminal command line console, run the following command:\n"
                f"{attack}\n"
                "3.Note in the results shown in the evidence, you can compare it with the tool output.\n"
            ),
            "remediation": "Not provided by Nuclei",
            "confidence": confidence
        }

    @staticmethod
    def calculate_confidence(*, severity: str = "", curl_command: str = "",
                             extracted_results: list | None = None, metadata: dict[str, Any] | None = None,
                             classification: dict[str, Any] | None = None,  remediation: str | None = None) -> str:
        priority_confidence: str
        confidence_score: int = 0
        severities: dict[str, list[str]] = {
            "Moderate": ["critical", "high", "medium"],
            "Low": ["low", "info"]
        }
        for key, value in severities.items():
            if severity in value:
                priority_confidence = key
                break
        if not priority_confidence:  # noqa
            priority_confidence = "Low"
        conditions = [
            extracted_results,
            curl_command,
            metadata.get("verified"),
            metadata.get("product"),
            metadata.get("vendor"),
            metadata.get("shodan-query"),
            classification,
            classification.get("cvss-score"),
            classification.get("cvss-metrics"),
            classification.get("cwe-id"),
            classification.get("cve-id"),
            remediation,
        ]
        confidence_score += sum([1 for c in conditions if c])
        confidence: str
        if priority_confidence == "Moderate" and confidence_score >= 7:  # noqa
            confidence = "Strong"
        elif priority_confidence == "Moderate" and 1 <= confidence_score < 7:
            confidence = "Moderate"
        elif priority_confidence == "Low" and confidence_score < 1:
            confidence = "False Positive"
        else:
            confidence = priority_confidence
        return confidence


# endregion

# region data-structures
class Action(Enum):
    SCAN = "scan"
    SCAN_EXPORT_JSON_FILE = "scan_export_json_file"
    IMPORT_JSON_FILE = "import_json_file"

@dataclass
class Nuclei(object):
    user_agent: str = f"Zirkul/Nuclei {VERSION}"
    target: str = ""
    targets_file: str = ""
    template: list[str] | None = None
    nuclei_path: str = "nuclei"
    concurrency: int = 20
    proxy: str = ""
    options: str = ""
    json_file: str = "EXPORTED.json"
    action: Action = Action.SCAN
    scan_type: str = "Dynamic scan"
    prefix: str = "none"
# endregion


def extract(txt: str, str_start: str, str_end: str) -> str | None:
    ini: int = txt.find(str_start)
    if ini == -1:
        return None
    tmp: str = txt[ini + len(str_start):]
    fin: int = tmp.rfind(str_end)
    if fin == -1:
        return None
    tmp = tmp[:fin]
    if tmp != '':
        return tmp
    return None

def run_scan(command: str) -> dict | str:  # noqa
    try:
        if not exist_nuclei():
            console('Nuclei not found in the system', 'red')
            return {"description": "Nuclei not found in the system", "status": "error"}
        console("[ ! ] Running Nuclei scanner...", "orange")
        output: str = scanner.run_shell_command(command)
        if output:
            return output
        else:
            return {"description": "Apparently there are no issues", "results": [], "status": False}
    except Exception as e:
        console(f"[ X ] Error: {e}", "red")


def format_template(template: str) -> list[str] | None:
    if not template:
        return []
    return template.replace(" ", ",").replace("\n", ",").split(",")


def create_scan_command(nuclei_obj: Nuclei) -> str | None:
    base_command: str = nuclei_obj.nuclei_path
    if nuclei_obj.target and not nuclei_obj.targets_file:
        base_command += f" -u {nuclei_obj.target}"
    elif nuclei_obj.targets_file and not nuclei_obj.target:
        base_command += f" -l {nuclei_obj.targets_file}"
    elif nuclei_obj.target and nuclei_obj.targets_file:
        console(f"[ ! ] Both target and targets_file are defined, using target {nuclei_obj.target}", "orange")
        base_command += f" -u {nuclei_obj.target}"
    base_command += " -nc -silent"
    if nuclei_obj.proxy:
        base_command += f" --proxy {nuclei_obj.proxy}"
    if nuclei_obj.user_agent:
        base_command += f" -H 'User-Agent: {nuclei_obj.user_agent}'"
    if nuclei_obj.concurrency:
        base_command += f" -c {nuclei_obj.concurrency}"
    if nuclei_obj.template:
        if isinstance(nuclei_obj.template, list):
            template = ",".join(nuclei_obj.template)
            base_command += f" -t {template}"
    if nuclei_obj.json_file:
        base_command += f" -je {nuclei_obj.json_file}"
    if nuclei_obj.options:
        # to prevent RCE
        if not is_valid_command(nuclei_obj.options):
            return None
        base_command += f" {shlex_quote(nuclei_obj.options)}"
    match nuclei_obj.prefix:
        case "pwsh":
            base_command = f"powershell -Command {base_command}"
        case "cmd":
            base_command = f"cmd /c {base_command}"
        case "bash":
            base_command = f"bash -c \"{base_command}\""
        case "sh":
            base_command = f"sh -c \"{base_command}\""
        case _:
            pass
    return base_command


def is_valid_command(command_prospect: str) -> bool:
    if not command_prospect:
        return False
    alpha: str = r"abcdefghijklmnñopqrstuvwxyzáéíóúäëïöüàèìòùç"
    numbers: str = r"0123456789"
    chars: str = r""":#=+-_@,./ \"'~"""
    allowed: str = f"{alpha}{alpha.upper()}{numbers}{chars}"
    if not all(c in allowed for c in command_prospect):
        return False
    return True


def import_from_json_file(json_file: str) -> list[dict] | None:
    console(f"[ ! ] Action: {Action.IMPORT_JSON_FILE}", "orange")
    console("[ - ] Contacting to translator...", "blue")
    result_translated = Integration.translate(input_file=json_file)
    if result_translated is None:
        console("[ X ] Error: Something wrong happened in translation process!", "red")
    return result_translated


def please_pwsh():
    console("[ X ] The plugin wasn't able to get the output file from nuclei", "red")
    console("[ ! ] This is a known issue in Windows environments", "orange")
    console(("[ ! ] Try using the option 'prefix: \"pwsh\"' for running nuclei with powershell, "
             "however keep in mind powershell should be available in your system"), "orange")

def launch_scan(nuclei_obj: Nuclei) -> dict:
    results: list[dict] | None
    command_failure: str = "Something failed in command construction process"
    no_tmp: str = "Temporary file has not been created"
    command_to_launch: str = create_scan_command(
        nuclei_obj
    )
    match nuclei_obj.action:
        case Action.SCAN:
            if not command_to_launch:
                return {"description": command_failure, "status": "error"}
            console(f"[ - ] Launching scan with command: {command_to_launch}", "blue")
            output_command: dict | str = run_scan(command_to_launch)
            if isinstance(output_command, dict):
                if output_command.get("status") == "error":
                    return output_command
            if not os.path.exists(nuclei_obj.json_file):
                if isinstance(output_command, str):
                    if os.name == "nt" or sys.platform == "win32":
                        please_pwsh()
                    return {"description": no_tmp, "status": 'error'}
                if isinstance(output_command, dict) and output_command.get("status") is False:
                    return output_command
            results = Integration.translate(input_file=nuclei_obj.json_file)
            time.sleep(1.25)
            os.remove(nuclei_obj.json_file)
        case Action.SCAN_EXPORT_JSON_FILE:
            if not command_to_launch:
                return {"description": command_failure, "status": "error"}
            console(f"[ - ] Launching scan with command: {command_to_launch}", "blue")
            output_command: dict | str = run_scan(command_to_launch)
            if isinstance(output_command, dict):
                if output_command.get("status") == "error":
                    return output_command
            if not os.path.exists(nuclei_obj.json_file):
                if isinstance(output_command, str):
                    if os.name == "nt" or sys.platform == "win32":
                        please_pwsh()
                    return {"description": no_tmp, "status": 'error'}
                if isinstance(output_command, dict) and output_command.get("status") is False:
                    return output_command
            results = Integration.translate(input_file=nuclei_obj.json_file)
            console(f"[ + ] JSON file exported: {nuclei_obj.json_file}", "green")
        case Action.IMPORT_JSON_FILE:
            results = import_from_json_file(nuclei_obj.json_file)
        case _:
            console(nuclei_obj.action, "red")
            return {"description": "Action not found", "status": "error"}
    if results is None:
        return {"description": "The import process failed", "status": "error"}
    return {"results": results, "status": True}


def run(reqs: list[dict[str, Any]]) -> dict[str, Any]:
    if not reqs:
        return {"description": "No requirements found", "status": "error"}
    command_concatenation: str = r"Command concatenation is not allowed, avoid using characters like: < > ; | &"
    required: dict[str, Any] = parse_reqs(reqs)
    nuclei_obj: Nuclei = Nuclei()
    global console  # noqa
    global scanner  # noqa
    global SCAN_TYPE  # noqa
    global nuclei_path  # noqa
    try:
        console = required.get('console') if 'console' in required.keys() else debug_console  # type: Callable
        scanner = required.get('scanner') if 'scanner' in required.keys() else None  # type: Any
        SCAN_TYPE = required.get("scan_type")
        if not SCAN_TYPE:
            SCAN_TYPE = nuclei_obj.scan_type
        else:
            nuclei_obj.scan_type = SCAN_TYPE
        concurrency: int = required.get('concurrency')
        if concurrency and concurrency != nuclei_obj.concurrency:
            nuclei_obj.concurrency = concurrency
        action: str = required.get('action')
        if action in Action._value2member_map_ and action != nuclei_obj.action:
            nuclei_obj.action = Action(action)
        bin_path: str = required.get("nuclei_path")
        if bin_path:
            if not os.path.isfile(bin_path):
                return {"description": f"Nuclei's path specified is not valid as {bin_path}", "status": "error"}
            nuclei_obj.nuclei_path = bin_path
        nuclei_path = nuclei_obj.nuclei_path
        prefix: str = required.get('prefix')
        if prefix and prefix != nuclei_obj.prefix:
            nuclei_obj.prefix = prefix
        local_file: str = required.get('json_file')
        if local_file and not is_valid_command(local_file):
            return {"description": f"[json_file] - {command_concatenation}", "status": "error"}
        if local_file and nuclei_obj.action in [Action.SCAN_EXPORT_JSON_FILE, Action.IMPORT_JSON_FILE]:
            nuclei_obj.json_file = local_file
        target: str = required.get('target')
        if target and not is_valid_command(target):
            return {"description": f"[target] - {command_concatenation}", "status": "error"}
        targets_file: str = required.get('targets_file')
        if targets_file and not is_valid_command(targets_file):
            return {"description": f"[targets_file] - {command_concatenation}", "status": "error"}
        if nuclei_obj.action in [Action.SCAN, Action.SCAN_EXPORT_JSON_FILE]:
            if not (target or targets_file):
                return {"description": "There is no target defined", "status": "error"}
            elif target and not targets_file:
                nuclei_obj.target = target
            elif targets_file and not target:
                nuclei_obj.targets_file = targets_file
            elif target and targets_file:
                console("[ ! ] Both target and targets_file are defined, using target", "orange")
                nuclei_obj.target = target
                nuclei_obj.targets_file = targets_file
        template: str = required.get('template')
        if template and not is_valid_command(template):
            return {"description": f"[template] - {command_concatenation}", "status": "error"}
        if template and isinstance(template, str):
            nuclei_obj.template = format_template(template)
        user_agent: str = required.get('user_agent')
        if user_agent and not is_valid_command(user_agent):
            return {"description": f"[user_agent] - {command_concatenation}", "status": "error"}
        proxy: str = required.get('proxy')
        if proxy and not is_valid_command(proxy):
            return {"description": f"[proxy] - {command_concatenation}", "status": "error"}
        options: str = required.get('options')
        if options and not is_valid_command(options):
            return {"description": f"[options] - {command_concatenation}", "status": "error"}
        nuclei_obj.options = options
        if scanner is None:
            console('[ X ] Scanner not defined', 'red')
            console("[ ! ] Creating a limited scanner version", "orange")
            scanner = create_dummy_scanner() # noqa
            if user_agent and user_agent != nuclei_obj.user_agent:
                nuclei_obj.user_agent = user_agent
            if proxy:
                nuclei_obj.proxy = proxy
        else:
            if user_agent and user_agent != nuclei_obj.user_agent:
                nuclei_obj.user_agent = user_agent
                console(f"Changing User Agent to: {nuclei_obj.user_agent}", "orange")
            elif user_agent == nuclei_obj.user_agent and user_agent != scanner.user_agent:
                nuclei_obj.user_agent = f"{scanner.user_agent} Nuclei/{VERSION}"
                console(f"[ ! ] Changing User Agent to: {nuclei_obj.user_agent}", "orange")
            if scanner.proxy and not proxy:
                console("[ ! ] Scanner proxy detected!", "orange")
                console(f"[ - ] Using scanner proxy: {scanner.proxy}", "blue")
                nuclei_obj.proxy = scanner.proxy
            elif proxy and scanner.proxy and proxy != scanner.proxy:
                console("[ ! ] Proxy configuration mismatch from scanner proxy!", "orange")
                console(f"[ - ] Keeping custom configuration proxy: {proxy}", "blue")
                nuclei_obj.proxy = proxy
            elif proxy and not scanner.proxy:
                nuclei_obj.proxy = proxy
        final_results: dict = launch_scan(nuclei_obj)
        console("[ + ] Plugin Finished!", "green")
        return final_results
    except Exception as e:
        console(f"[ X ] Error: {e}", "red")
        return {"description": f"Error: {e}", "status": "error"}


if __name__ == '__main__':
    test_cases = {
        # Válidos
        "comando": True,
        "comando123": True,
        "comando-1": True,
        "ruta/al/archivo.txt": True,
        "comando:argumento=valor": True,
        "comando argumento": True,
        "comando con guiones y _": True,
        "ruta/'con espacio'/archivo.txt": True,
        r"C:\Users\usuario\archivo.txt": True,

        # Inválidos
        "": False,
        "comando;": False,
        "comando&argumento": False,
        "comando|archivo": False,
        "comando<archivo>": False,
        "comando$": False,
        "comando!argumento": False,
        "comando\nargumento": False,
    }

    for command, expected in test_cases.items():
        result = is_valid_command(command)
        print(f"Command: {command} -> {result}")
        assert result == expected, f"Error: '{command}' returned {result}, expected {expected}"
