#!/usr/bin/python
"""
[properties]
@version: 1.0.1
@author: Daniel Hoffman (Aka. Z)
@name: OWASP Dependency Check
@id: dependency-check
@description: Software Composition Analysis performed with OWASP Dependency Check CLI
@syntax: dependency-check
@type: integration
@impact: safe
@service: None
@return_type: vuln
[properties]

"""

# region imports
from typing import Callable, Any
from collections import Counter
from functools import wraps
import subprocess
import logging
import inspect
import json
import time
import sys
import os
import re

# endregion

# region constants
mod_requirements: list[dict] = [
    {'name': 'repository_path', 'description': 'Path where the source code is located', 'type': 'string',
     'required': True, 'value': None},
    {'name': 'output', 'description': 'Directory path for exported results', 'type': 'string',
     'required': False, 'value': None},
    {'name': 'export_format', 'description': 'Format to export the results', 'type': ['HTML', 'JSON', 'XML', 'JUNIT',
                                                                                      'SARIF', 'JENKINS', 'GITLAB',
                                                                                      'ALL'], 'required': False,
     'value': 'JSON'},
    {'name': 'auto_update', 'description': ('Enable/Disable automatic updating of the NVD-CVE, '
                                            'hosted-suppressions and RetireJS'), 'type': ['yes', 'no'],
     'required': True, 'value': 'no'},
    {'name': 'nvd_apikey', 'description': 'NVD Data Base API Key', 'type': 'string', 'required': False, 'value': None},
    {'name': 'project_name', 'description': 'Name of the project to be scanned', 'type': 'string', 'required': False,
     'value': "MyProject"},
    {'name': 'experimental', 'description': 'Enable/Disable experimental analyzers', 'type': ['yes', 'no'],
     'required': False, 'value': 'no'},
    {'name': 'suppression_file', 'description': 'Path to the suppression file', 'type': 'file',
     'required': False, 'value': None},
    {'name': 'advance_help', 'description': 'Enable/Disable advanced help', 'type': ['yes', 'no'], 'required': False,
     'value': 'no'},
    {'name': 'custom_path', 'description': 'If Dependency-Check is not in OS PATH, specify the path', 'type': 'file',
     'required': False, 'value': None},
]
requirements: Callable[[], list[dict]] = lambda: mod_requirements

out_handler = logging.StreamHandler(sys.stdout)
out_handler.setLevel(logging.INFO)
separator: str = "\033[1;37m-->\033[0m"
formatter: str = (
    f"[\033[36mLine\033[0m] \033[95m%(z_lineno)d\033[0m\t{separator}\t%(message)s"
)
logging.basicConfig(level=logging.INFO, handlers=[out_handler], format=formatter)

global console
console: Callable[[str, str], None]

def parse_requirements(reqs: list[dict[str, Any]]) -> dict[str, Any]:
    required: dict[str, Any] = {}
    for req in reqs:
        if "name" in req.keys():
            required[req.get('name')] = req.get('value')
        if "console" in req.keys() and "scanner" in req.keys():
            required["console"] = req.get("console")
            required["scanner"] = req.get("scanner")
    return required


def debug_console(message: str, color: str) -> None:
    # get line from previous frame
    frame_info = inspect.getouterframes(inspect.currentframe())[1]
    list_text: list[str] = list(filter(lambda x: x,
                                       re.split(r"(\[ [+-X!] \])",
                                                message, maxsplit=1)))
    prefix: str
    if len(list_text) == 2:
        match list_text[0]:
            case "[ + ]":
                prefix = "[ \033[92m+\033[0m ]"
                message = list_text[1]
            case "[ - ]":
                prefix = "[ \033[94m-\033[0m ]"
                message = list_text[1]
            case "[ ! ]":
                prefix = "[ \033[33m!\033[0m ]"
                message = list_text[1]
            case "[ X ]":
                prefix = "[ \033[31mX\033[0m ]"
                message = list_text[1]
            case _:
                prefix = ""
    else:
        prefix = ""
    match color:
        case "red":
            logging.error(f"{prefix}\033[31m{message}\033[0m", extra={"z_lineno": frame_info.lineno})
        case "orange":
            logging.warning(f"{prefix}\033[33m{message}\033[0m", extra={"z_lineno": frame_info.lineno})
        case "green":
            logging.info(f"{prefix}\033[92m{message}\033[0m", extra={"z_lineno": frame_info.lineno})
        case "blue":
            logging.info(f"{prefix}\033[94m{message}\033[0m", extra={"z_lineno": frame_info.lineno})
        case _:
            logging.critical(f"{prefix}\033[35m{message}\033[0m\t|\tNo color {color}",
                             extra={"z_lineno": frame_info.lineno})


def command_printer(func: Callable) -> Callable:
    @wraps(func)
    def wrapper(*args, **kwargs) -> str:
        result: subprocess.CompletedProcess = func(*args, **kwargs)
        if result.returncode == 0:
            console(f"[ + ] Return Code: {result.returncode}", "orange")
        else:
            console(f"[ X ] Return Code: {result.returncode}", "orange")
        if result.stdout.decode("utf-8").rstrip("\n").splitlines():
            console("[ ! ] Standard Output:\n", "orange")
            for line in result.stdout.decode("utf-8").rstrip("\n").splitlines():
                console(f"[ - ] =>  {line}", "blue")
        if result.stderr.decode("utf-8").rstrip("\n").splitlines():
            console("[ ! ] Standard Error:\n", "orange")
            for line in result.stderr.decode("utf-8").rstrip("\n").splitlines():
                console(f"[ X ] =>  {line}", "red")
        return (f"stdout:\n{result.stdout.decode('utf-8').rstrip('\n')}"
                f"\n\nstderr:\n{result.stderr.decode('utf-8').rstrip('\n')}")

    return wrapper


def create_mini_scanner() -> Callable:
    mini_scanner: Callable[[], None] = lambda: None
    mini_scanner.run_shell_command: Callable[[str], str] = command_printer(lambda cmd: subprocess.run(  # noqa
        cmd.split(' '),
        shell=True,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    ))
    return mini_scanner


def get_dependency_check_path(req_path: str) -> str | None:
    command_refix: str = "/bin/bash" if os.name != "nt" else "cmd.exe /c"
    command_suffix: str = "-v"
    possibles: list[str] = [
        "dependency-check",
        "dependency-check.sh",
        "dependency-check.bat",
    ]
    try:
        if req_path:
            possibles.append(f"{command_refix} {req_path}")
        for possible in possibles:
            command_result = subprocess.run(
                list(filter(None, f"{possible} {command_suffix}".split(' '))),  # noqa
                shell=True,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            if command_result.returncode == 0:
                return ' '.join(command_result.args[:-1])
    except Exception as e:
        console(f"Error finding Dependency Check: {e}", "red")
        return None


def extract(txt: str, str_start: str, str_end: str) -> str | None:
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


# endregion

# region Operation

def valid_apikey(key: str) -> bool:
    alpha: str = "abcdefghijklmnopqrstuvwxyz"
    numbers: str = "0123456789"
    allowed = f"{alpha}{alpha.upper()}{numbers}-"
    if all(x in allowed for x in key):
        return True
    return False

def create_command(base_command: str, reqs: dict[str, Any]) -> str | None:
    if not base_command or not isinstance(base_command, str):
        console("Invalid base command", "red")
        return None
    if not reqs or not isinstance(reqs, dict):
        console("Invalid requirements", "red")
        return None
    command: str = f"{base_command} --prettyPrint"
    command += f" --scan {reqs.get('repository_path')}"
    if reqs.get("output"):
        command += f" --out {reqs.get('output')}"
    if reqs.get("export_format"):
        if reqs.get("export_format") != "JSON":
            command += f" -f {reqs.get('export_format')} -f JSON"
        else:
            command += f" -f {reqs.get('export_format')}"
    else:
        command += " --format JSON"
    if reqs.get("auto_update") == "no":
        command += " --noupdate"
    elif reqs.get("auto_update") == "yes":
        if reqs.get("nvd_apikey") and valid_apikey(reqs.get("nvd_apikey")):
            command += f" --nvdApiKey {reqs.get('nvd_apikey')}"
    if reqs.get("project_name"):
        command += f" --project '{reqs.get('project_name')}'"
    if reqs.get("experimental") == "yes":
        command += " --enableExperimental"
    if reqs.get("suppression_file"):
        command += f" --suppression {reqs.get('suppression_file')}"
    if reqs.get("advance_help") == "yes":
        command += " --advancedHelp"
    console(f"Running command: {command}", "green")
    return f"{command} --disableYarnAudit"


# endregion

# region Translator

class Integration(object):

    @classmethod
    def translate(cls, input_file: str) -> list[dict] | None:
        if not input_file:
            console("[ X ] No input file receive", "red")
            return None
        if not cls.valid_json(input_file):
            console("[ X ] Invalid json file", "red")
            return None
        data: dict | None = cls.load_json(input_file)
        if data is None:
            console("[ X ] Error loading json file", "red")
            return None
        console(f"[ ! ] Report Schema: {cls.report_schema(data)}", "orange")
        for i in cls.scan_info(data).splitlines():
            console(f"[ - ] {i}", "blue")
        console(f"[ - ] {cls.project_info(data)}", "blue")
        issues: list[dict] = cls.dependencies(data)
        if not issues:
            return []
        return issues

    @staticmethod
    def valid_json(input_file: str) -> bool:
        if not os.path.isfile(input_file):
            console("[ X ] Input json file not exist!", "red")
            return False
        try:
            mydict: dict
            with open(input_file, "r", encoding="utf-8") as myfile:
                mydict = json.load(myfile)
            if not mydict:
                console("[ X ] Apparently there is no anything into the json file", "red")
                return False
            return True
        except Exception as err:
            console("[ X ] Error checking json file", "red")
            console(f"Error: {err}", "red")
            return False

    @staticmethod
    def load_json(input_file: str) -> dict | None:
        if not input_file or not isinstance(input_file, str):
            return None
        try:
            data: dict
            with open(input_file, "r", encoding="utf-8") as myfile:
                data = json.load(myfile)
                return data
        except Exception as err:
            console("[ X ] Something went wrong in json loading process", "red")
            console(f"[ X ] Error: {err}", "red")
            return None

    @staticmethod
    def report_schema(data: dict) -> str:
        return data.get("reportSchema", "Unknown report Schema")

    @staticmethod
    def scan_info(data: dict) -> str:
        to_return: str
        scan_info: dict = data.get("scanInfo", {})
        if not scan_info:
            return ''
        engine_version: str = scan_info.get("engineVersion", "Unknown")
        data_source: list = scan_info.get("dataSource", [])
        to_return = f"Engine Version: {engine_version}"
        if not data_source:
            return to_return
        boundary: str = "\033[35m|\033[0m"
        length: int = max(len(j) for f in data_source for j in f.values())
        for i in data_source:
            timestamp: str = f"\033[36mTimestamp:\033[0m {i.get('timestamp', 'Unknown')}"
            source: str = f"\033[36mData Source:\033[0m {i.get('name', 'Unknown')}"
            if len(source) > length:
                length = len(source)+8
            if len(timestamp) > length:
                length = len(timestamp)+8
            to_return += f"\n\033[35m+{''.center(length-7, '=')}+\033[0m"
            to_return += f"\n{boundary} {source} {' '*(length - len(source))}{boundary}"
            to_return += f"\n{boundary} {timestamp} {' '*(length - len(timestamp))}{boundary}"
            to_return += f"\n\033[35m+{''.center(length-7, '=')}+\033[0m"

        return to_return

    @staticmethod
    def project_info(data: dict) -> str:
        if not data:
            return ""
        project_info: dict = data.get("projectInfo", {})
        if not project_info or not isinstance(project_info, dict):
            console("[ X ] Project Info not found", "red")
            return ""
        to_return: str = project_info.get("name")
        if to_return == "" or to_return is None:
            to_return = "Unknown"
        to_return += f" ({project_info.get('reportDate', 'Unknown report date')})"
        return to_return

    @classmethod
    def dependencies(cls, data: dict) -> list[dict]:
        if not data:
            console("[ X ] No dependencies receive", "red")
            return []
        dependencies: list[dict] = data.get("dependencies", [])
        if not dependencies:
            console("[ - ] No dependencies found", "orange")
            return dependencies
        vulnerabilities: list[dict]
        vulnerabilities, _ = cls.filter_vulnerabilities(dependencies)
        if not vulnerabilities:
            console("[ - ] No vulnerabilities found", "orange")
        issues: list[dict] = cls.vuln_to_issues(vulnerabilities)
        info: dict = cls.dependencies_list_issue(dependencies)
        if info:
            issues.append(info)
        return issues

    @classmethod
    def dependencies_list_issue(cls, list_dep: list[dict]) -> dict:
        if not list_dep or not isinstance(list_dep, list):
            return {}
        total_dep: list = []
        for _, dep in enumerate(list_dep):
            if dep.get("isVirtual") is False:
                cache: dict = {
                    "isVirtual": dep.get("isVirtual"),
                    "fileName": dep.get("fileName"),
                }
                if dep.get("packages"):
                    pack: str = ""
                    for i in dep.get("packages", []):
                        pack += f"{i.get('id')}\n"
                    cache["packages"] = pack.rstrip('\n')
                total_dep.append(cache)
        print_deps: Callable[[dict], str] = lambda i: (
            f"File Name: {i.get('fileName')}\tPackage: {i.get('packages')}" if "packages" in i
            else f"File Name: {i.get('fileName')}"
        )
        issue: dict = cls.issue_generator(
            issue_type="Informational Code Dependencies Detected List",
            severity="Info", confidence="Strong", remediation="Not required", evidence="\n".join(
                map(print_deps, total_dep)
            ), description=(
                "Informational issue to inform about dependencies detected in the application code. "
                "This list provides insights into the various components and libraries utilized, helping "
                "developers understand the interconnections and potential impacts on the application's functionality "
                "and maintainability."
            ),
            details=(
                "This is only for informational purposes, no action is required."
                "\n\nIn this issue will be evidenced a list of dependencies detected in the application code."
            ), references=[]
        )


        return issue
    @staticmethod
    def format_severity(sev: str):
        severity: str
        match sev:
            case "CRITICAL":
                severity = "Critical"
            case "HIGH":
                severity = "High"
            case "MEDIUM" | "MODERATE":
                severity = "Medium"
            case "LOW":
                severity = "Low"
            case _:
                severity = "Info"
        return severity

    @staticmethod
    def format_confidence(conf: str):
        confidence: str
        match conf:
            case "CONFIRMED":
                confidence = "Strong"
            case "HIGH" | "MEDIUM" | "HIGHEST":
                confidence = "Moderate"
            case "LOW" | _:
                confidence = "Low"
        return confidence

    @classmethod
    def vuln_to_issues(cls, vuln: list[dict]) -> list[dict]:
        if not vuln or not isinstance(vuln, list):
            return []
        issues: list[dict] = []
        for i in vuln:
            try:
                evidence, sev = cls.evidence_generator(i)
                if not sev:
                    sev = ("Low", "Low")
                cvss, cvss_string = cls.get_cvss(i)
                cwe_set = cls.get_cwes(i)
                description: str = ""
                if i.get("description"):
                    description = f"{i.get('description')}\n"
                for j in i.get("vulnerabilities", []):
                    if j.get("description"):
                        description += f"{j.get('description')}\n"
                m_cve: str = f"{i.get('vulnerabilities', [])[0].get('name', '')}"
                if not m_cve.upper().startswith("CVE-"):
                    m_cve = ""
                issue: dict = cls.issue_generator(
                    issue_type="Vulnerable and outdated code dependencies",
                    cvss=float(cvss),
                    cvss_string=cvss_string,
                    cwe=list(cwe_set)[0],
                    evidence=evidence,
                    description=(
                        "Vulnerable and outdated code dependencies occur when an application relies on "
                        "third-party libraries or components that have known security vulnerabilities or "
                        "are no longer actively maintained. Such dependencies can expose the application "
                        "to various security risks, including:\n\n"

                        "- **Exploitation of Known Vulnerabilities**: Attackers can leverage unpatched "
                        "vulnerabilities in outdated libraries to compromise the application or its data.\n"
                        "- **Lack of Security Updates**: Abandonware or outdated libraries may not receive "
                        "crucial security patches, increasing the risk of exploitation.\n"
                        "- **Compatibility Issues**: Using outdated dependencies can lead to compatibility "
                        "problems with newer technologies or frameworks, complicating development and "
                        "maintenance efforts.\n\n"

                        "It is essential to regularly review and update dependencies to ensure the application "
                        "remains secure and robust. Utilize tools like dependency scanners to identify vulnerable "
                        "packages and prioritize updates to mitigate risks effectively."
                    ),
                    details=description,
                    severity=cls.format_severity(sev[0]),
                    confidence=cls.format_confidence(sev[1]),
                    references=cls.generate_references(i, cwe_set),
                    cve=m_cve,
                    remediation=(
                        "1. **Identify Dependencies**: Use dependency management tools to list all current "
                        "libraries and components.\n"
                        "2. **Check for Vulnerabilities**: Use vulnerability databases (e.g., CVE, NVD) to "
                        "check if any dependencies have known vulnerabilities.\n"
                        "3. **Update Dependencies**: Regularly update to the latest stable versions of libraries "
                        "and components.\n"
                        "4. **Replace Deprecated Libraries**: Substitute deprecated or abandoned libraries with "
                        "actively maintained alternatives.\n"
                        "5. **Monitor Dependencies**: Implement automated tools that alert you to newly discovered "
                        "vulnerabilities in your dependencies."
                    )
                )
                issues.append(issue)
            except:
                pass
        return issues

    @staticmethod
    def generate_references(issue: dict, cwes: set[str]) -> list[dict]:
        if not issue or not isinstance(issue, dict):
            return []
        if not cwes or not isinstance(cwes, set):
            return []
        references: list[dict] = []
        cve_ref: set[str] = set()
        for i in cwes:
            references.append({
                "title": f"{i}",
                "url": f"https://cwe.mitre.org/data/definitions/{i.split('-')[1]}.html"
            })
        if issue.get("packages"):
            for i in issue.get("packages"):
                references.append({
                    "title": f"Package: {i.get('id')}",
                    "url": f"{i.get('url')}"
                })
        if issue.get("vulnerabilities"):
            for i in issue.get("vulnerabilities"):
                if i.get("name").upper().startswith("CVE-"):
                    cve_ref.add(i.get("name"))
        for i in cve_ref:
            references.append({
                "title": f"NVD {i}",
                "url": f"https://nvd.nist.gov/vuln/detail/{i}"
            })
            references.append({
                "title": f"MITRE {i}",
                "url": f"https://www.cve.org/CVERecord?id={i}"
            })
        return references

    @staticmethod
    def get_cwes(issue: dict):
        if not issue or not isinstance(issue, dict):
            return ""
        vuln: list[dict] = issue.get("vulnerabilities", [])
        storage: set = set()
        for i in vuln:
            for j in i.get("cwes", []):
                storage.add(j)
        return storage

    @staticmethod
    def get_cvss(issue: dict):
        if not issue or not isinstance(issue, dict):
            return 0, ""
        vuln: list[dict] = issue.get("vulnerabilities", [])
        storage: list = []
        try:
            for j in vuln:
                if j.get("cvssv3"):
                    i = j.get("cvssv3")
                    storage.append(
                        (i.get("baseScore"),(f"AV:{i.get('attackVector', 'N')[0]}/"
                        f"AC:{i.get('attackComplexity', 'N')[0]}/"
                        f"PR:{i.get('privilegesRequired', 'N')[0]}/"
                        f"UI:{i.get('userInteraction', 'N')[0]}/"
                        f"S:{i.get('scope', 'N')[0]}/"
                        f"C:{i.get('confidentialityImpact', 'N')[0]}/"
                        f"I:{i.get('integrityImpact', 'N')[0]}/"
                        f"A:{i.get('availabilityImpact', 'N')[0]}"))
                    )
                elif j.get("cvssv2"):
                    i = j.get("cvssv2")
                    storage.append(
                        (i.get("score"),(f"CVSSv2:AV:{i.get('accessVector', 'N')[0]}/"
                        f"AC:{i.get('accessComplexity', 'N')[0]}/"
                        f"Au:{i.get('authentication', 'N')[0]}/"
                        f"C:{i.get('confidentialityImpact', 'N')[0]}/"
                        f"I:{i.get('integrityImpact', 'N')[0]}/"
                        f"A:{i.get('availabilityImpact', 'N')[0]}"))
                    )
        except:
            pass
        if not storage:
            return 0, ""
        return max(storage, key=lambda x: x[0])

    @classmethod
    def evidence_generator(cls, issue: dict) -> tuple[str, tuple[str, str] | None]:
        if not issue or not isinstance(issue, dict):
            return "", None
        evidence: str = f"Is virtual Dependency: {issue.get('isVirtual', False)}\n"
        md5: str = issue.get("md5", "")
        if md5:
            evidence += f"MD5: {md5}\n"
        sha1: str = issue.get("sha1", "")
        if sha1:
            evidence += f"SHA1: {sha1}\n"
        sha256: str = issue.get("sha256", "")
        if sha256:
            evidence += f"SHA256: {sha256}\n"
        packages: set[str] = set()
        vuln_data: list[dict] = issue.get("vulnerabilities", [])
        vuln_sources: set[str] = set()
        vuln_names: set[str] = set()
        vuln_severity: list[str] = []
        vuln_confidence: list[str] = []
        if issue.get("packages"):
            for i in issue.get("packages"):
                packages.add(i.get("id", ""))
        evidence += cls.__packages_evidence_auxiliary(packages)
        if vuln_data:
            for i in vuln_data:
                vuln_sources.add(i.get("source", "").upper())
                vuln_names.add(i.get("name", "").upper())
                vuln_severity.append(i.get("severity", "").upper())
        evidence = cls.__vuln_sources_evidence_auxiliary(vuln_sources)
        evidence += cls.__vuln_name_evidence_auxiliary(vuln_names)
        evidence_collected: dict = issue.get("evidenceCollected", {})
        severity: str = Counter(vuln_severity).most_common(1)[0][0]
        if issue.get("relatedDependencies"):
            evidence += cls.__related_dependencies_evidence_auxiliary(issue.get("relatedDependencies", []))
        if not evidence_collected:
            return evidence, (severity, "Low")
        vendor_evidence: list[dict[str, str]] = evidence_collected.get("vendorEvidence", [])
        if vendor_evidence:
            e, k =  cls.__vendor_evidence_axuliary(vendor_evidence)
            evidence += e
            vuln_confidence.extend(k)
        product_evidence: list[dict[str, str]] = evidence_collected.get("productEvidence", [])
        if product_evidence:
            e, k = cls._product_evidence(product_evidence)
            evidence += e
            vuln_confidence.extend(k)
        version_evidence: list[dict[str, str]] = evidence_collected.get("versionEvidence", [])
        if version_evidence:
            e, k = cls.__version_evidence_auxiliary(version_evidence)
            evidence += e
            vuln_confidence.extend(k)
        confidence: str = Counter(vuln_confidence).most_common(1)[0][0]
        return evidence, (severity, confidence)

    @staticmethod
    def __related_dependencies_evidence_auxiliary(related: list[dict[str, str | bool]]) -> str:
        try:
            if related:
                evidence = "Related Dependencies:\n"
                for i in related:
                    evidence += (
                        f"\tFile Name: {i.get('fileName', '')}\n"
                        f"is Virtual: {i.get('isVirtual', False)}\n"
                        f"file Path: {i.get('filePath', '')}\n"
                        f"Packages IDs: {i.get('packageIds', '')}\n"
                    )
                    evidence += f"{''.center(30, '-')}\n"
                return evidence
            return ''
        except:
            return ''
    @staticmethod
    def __packages_evidence_auxiliary(packages: set[str]) -> str:
        try:
            if packages:
                evidence = "Packages:\n"
                for i in packages:
                    evidence += f"\t{i}\n"
                evidence += f"{''.center(30, '-')}\n"
                return evidence
            return ''
        except:
            return ''
    @staticmethod
    def __vuln_name_evidence_auxiliary(vuln_names: set[str]) -> str:
        try:
            if vuln_names:
                evidence = "Vulnerabilities:\n"
                for i in vuln_names:
                    evidence += f"\t{i}\n"
                evidence += f"{''.center(30, '-')}\n"
                return evidence
            return ''
        except:
            return ''
    @staticmethod
    def __vendor_evidence_axuliary(vendor_evidence: list[dict[str, str]]) -> tuple[str, list[str]]:
        try:
            evidence: str = "Vendor Evidence:\n"
            vuln_confidence: list[str] = []
            for i in vendor_evidence:
                evidence += (f"\tName: {i.get('name', '')}\n"
                             f"\tSource: {i.get('source', '')}\n"
                             f"\tConfidence: {i.get('confidence', '')}\n"
                             f"\tValue: {i.get('value', '')}\n")
                vuln_confidence.append(i.get("confidence", "").upper())
                evidence += f"{''.center(30, '-')}\n"
            return evidence, vuln_confidence
        except:
            return '', []
    @staticmethod
    def __vuln_sources_evidence_auxiliary(vuln_sources: set[str]) -> str:
        try:
            if vuln_sources:
                evidence = "Vulnerability Sources:\n"
                for i in vuln_sources:
                    evidence += f"\t{i}\n"
                evidence += f"{''.center(30, '-')}\n"
                return evidence
            return ''
        except:
            return ''
    @staticmethod
    def __version_evidence_auxiliary(version_evidence: list[dict[str, str]]) -> tuple[str, list[str]]:
        try:
            evidence = "Version Evidence:\n"
            vuln_confidence = []
            for i in version_evidence:
                evidence += (f"\tName: {i.get('name', '')}\n"
                             f"\tSource: {i.get('source', '')}\n"
                             f"\tConfidence: {i.get('confidence', '')}\n"
                             f"\tValue: {i.get('value', '')}\n")
                evidence += f"{''.center(30, '-')}\n"
                vuln_confidence.append(i.get("confidence", "").upper())
            return evidence, vuln_confidence
        except:
            return '', []
    @staticmethod
    def _product_evidence(product_evidence: list[dict[str, str]]) -> tuple[str, list[str]]:
        try:
            evidence = "Product Evidence:\n"
            vuln_confidence = []
            for i in product_evidence:
                evidence += (f"\tName: {i.get('name', '')}\n"
                             f"\tSource: {i.get('source', '')}\n"
                             f"\tConfidence: {i.get('confidence', '')}\n"
                             f"\tValue: {i.get('value', '')}\n")
                vuln_confidence.append(i.get("confidence", "").upper())
                evidence += f"{''.center(30, '-')}\n"
            return evidence, vuln_confidence
        except:
            return '', []

    @staticmethod
    def issue_generator(issue_type: str, vuln_type: str = "Code", severity: str = "Low", confidence: str = "Low",
                        cve: str = "", cwe: str = "", cvss: int | float = 0, cvss_string: str = "", evidence: str = "",
                        references: list[dict] = None, description: str = "" , details: str = "",
                        remediation: str = "Check the official documentation") -> dict:
        return {
            "issue_type": "vulnerability",
            "vulnerability_type": vuln_type,
            "scan_type": "static scan",
            "type": issue_type,
            "severity": severity,
            "confidence": confidence,
            "description": description,
            "details": details,
            "tool": "OWASP Dependency Check",
            "remediation": remediation,
            "evidence": evidence,
            "cvss": round(cvss, 1),
            "cvss string": cvss_string,
            "cve": cve,
            "cwe": cwe,
            "references": references
        }

    @staticmethod
    def filter_vulnerabilities(data: list[dict]) -> tuple[list[dict], list[dict]]:
        try:
            if not data or not isinstance(data, list):
                console("[ X ] No data receive", "red")
                return [], []
            if not all(isinstance(x, dict) for x in data):
                console("[ X ] The received data has not a compatible format!", "red")
                return [], []
            with_vuln: list[dict] = []
            without_vuln: list[dict] = []
            for i in data:
                (with_vuln if "vulnerabilities" in i else without_vuln).append(i)
            return with_vuln, without_vuln
        except:
            return [], []
# endregion


# region main

def run(reqs: list[dict[str, Any]]) -> dict[str, Any]:
    local_requirements: dict[str, Any] = parse_requirements(reqs)
    global scanner
    global console
    scanner = local_requirements.get("scanner", create_mini_scanner())  # type: Any
    console = local_requirements.get("console", debug_console)  # type: Callable[[str,str], None]
    try:
        dependency_check_path: str = get_dependency_check_path(local_requirements.get("custom_path"))
        if not dependency_check_path:
            return {"description": "Dependency Check not found in PATH", "status": "error"}
        command: str = create_command(dependency_check_path, local_requirements)
        output: str = scanner.run_shell_command(command)
        path: str = extract(output, "Writing JSON report to: ", "\n").rstrip('\r')
        time.sleep(1)
        issues: list[dict] = Integration.translate(path)
        if local_requirements.get("export_format") != "JSON":
            console("[ ! ] Removing the JSON temporary file", "orange")
            os.remove(path)
        if not issues:
            return {"description": "No vulnerabilities found", "results": [], "status": False}
        return {"results": issues, "status": True}
    except Exception as e:
        console(f"Error running OWASP Dependency Check: {e}", "red")
        return {"description": f"Error running OWASP Dependency Check: {e}", "status": "error"}
# endregion
