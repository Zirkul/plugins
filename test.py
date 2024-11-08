#!/usr/bin/python
import argparse
import importlib.util
import json
import os.path
import sys


class Tester:
    def __init__(self):
        self.return_types = ["vuln", "asset", "null", "boolean"]
        self.services = ["ssh", "telnet", "ftp", "smtp", "pop", "imap", "dns", "web", "http", "https", "smb", "ldap"]
        self.mod_types = ["integration", "exploit", "tool"]
        self.data_types = ["string", "boolean", "integer", "port", "url", "ipaddress", "ip", "domain", "domainorip",
                           "directory", "dir", "file"]
        self.mod_requirements = ["name", "description", "required", "type", "value"]
        self.author = ""
        self.name = ""
        self.mod_id = ""
        self.description = ""
        self.syntax = ""
        self.mod_type = ""
        self.impact = ""
        self.service = ""
        self.return_type = ""
        self.module = None

    def import_module(self, fpath, python_script_name):
        if python_script_name.endswith(".py"):
            print("[ + ] Loading file")
            with open("{}{}".format(fpath, python_script_name)) as f:
                content = f.read().splitlines()
            fread = False
            print("[ + ] Validating file structure")
            for line in content:
                if line.startswith("[properties]"):
                    if fread:
                        break
                    else:
                        fread = True
                if fread:
                    if line.startswith("@author:"):
                        self.author = line.replace("@author:", "").strip()
                    elif line.startswith("@name:"):
                        self.name = line.replace("@name:", "").strip()
                    elif line.startswith("@id:"):
                        self.mod_id = line.replace("@id:", "").strip()
                    elif line.startswith("@description:"):
                        self.description = line.replace("@description:", "").strip()
                    elif line.startswith("@syntax:"):
                        self.syntax = line.replace("@syntax:", "").strip()
                    elif line.startswith("@type:"):
                        self.mod_type = line.replace("@type:", "").strip()
                    elif line.startswith("@impact:"):
                        self.impact = line.replace("@impact:", "").strip()
                    elif line.startswith("@service:"):
                        self.service = line.replace("@service:", "").strip()
                    elif line.startswith("@return_type:"):
                        self.return_type = line.replace("@return_type:", "").strip()
            # Validations
            if fread:
                last_error = ""
                if self.name == "":
                    last_error = '{}: Module name is required'.format(python_script_name)
                    print('[ X ] {}'.format(last_error))
                if self.mod_id == "":
                    last_error = '{}: Module ID is required'.format(python_script_name)
                    print('[ X ] {}'.format(last_error))
                if self.description == "":
                    last_error = '{}: Module description is required'.format(python_script_name)
                    print('[ X ] {}'.format(last_error))
                if self.syntax == "":
                    last_error = '{}: Module syntax is required'.format(python_script_name)
                    print('[ X ] {}'.format(last_error))
                if self.mod_type not in self.mod_types:
                    last_error = '{}: Module type is required'.format(python_script_name)
                    print('[ X ] {}'.format(last_error))
                if self.impact not in ["safe", "intrusive", "dos"] and self.mod_type == "exploit":
                    last_error = '{}: The @impact attribute is required for exploit modules and is either missing or ' \
                                 'invalid: {}'.format(python_script_name, self.impact)
                    print('[ X ] {}'.format(last_error))
                if self.service not in self.services and self.mod_type == "exploit":
                    last_error = '{}: The @service attribute is required for exploit modules and is either missing ' \
                                 'or invalid: {}'.format(python_script_name, self.service)
                    print('[ X ] {}'.format(last_error))
                if self.return_type not in self.return_types:
                    last_error = '{}: Module return type is empty or invalid: {}'.format(python_script_name,
                                                                                         self.return_type)
                    print('[ X ] {}'.format(last_error))
                if last_error == "":
                    try:
                        print("[ + ] File structure is good")
                        print(f"""
                        Name: {self.name}
                        Author: {self.author}
                        Module ID: {self.mod_id}
                        Description: {self.description}
                        Syntax: {self.syntax}
                        Type: {self.mod_type}
                        Impact: {self.impact}
                        Service: {self.service}
                        Return type: {self.return_type}
                        """)
                        full_path = "{}/{}{}".format(os.getcwd(), fpath, python_script_name)
                        print("[ + ] Loading runtime module")
                        name = python_script_name.replace(".py", "")

                        spec = importlib.util.spec_from_file_location(name, full_path)
                        plugin = importlib.util.module_from_spec(spec)
                        sys.modules[name] = plugin
                        spec.loader.exec_module(plugin)
                        setattr(plugin, 'name', name)
                        self.module = plugin

                        requirements = self.get_requirements()
                        print("[ + ] Validating module requirements")
                        for r in requirements:
                            for r_key in self.mod_requirements:
                                if r_key not in r.keys():
                                    print("[ X ] Attribute '{}' is required for module requirements".format(r_key))
                            if "type" in r.keys():
                                if r["type"] not in self.data_types and not isinstance(r["type"], list):
                                    print("[ X ] Invalid data type '{}' on :{}".format(r["type"], r))
                        print("[ + ] Module validation completed")
                        return self.module
                    except Exception as ex:
                        print('[ ! ] Error loading module: {}'.format(self.name))
                        print('[ ! ] {}'.format(ex))
                else:
                    print('[ X ] Process stopped due to errors in the module structure')

    def validate_vuln(self, vuln):
        failed = False
        if isinstance(vuln, dict):
            vuln_results = [vuln]
        elif isinstance(vuln, list):
            vuln_results = vuln
        else:
            print('[ X ] The results returned by the plugin are not dict or list of dicts')
            return False
        print("[ ! ] Results to process: {}".format(len(vuln)))
        c = 1
        for each_vuln in vuln_results:
            print("[ ! ] Working on {} of {}".format(c, len(vuln)))
            vuln_good = self.__validate_vuln_dict(each_vuln)
            c += 1
            if not vuln_good:
                failed = True
        if failed:
            return False
        else:
            return True

    def __validate_vuln_dict(self, vuln):
        if not isinstance(vuln, dict):
            return False
        new_vuln = self.__new_issue(vuln)
        if new_vuln is None:
            print("[ - ] Result: Failed")
            return False
        else:
            print("[ + ] Result: Ok")
            return True

    def __new_issue(self, vuln):
        if not isinstance(vuln, dict):
            print('[ X ] Issue data format is not a dictionary')
            return None
        required_params = ['scan_type', 'issue_type', 'type', 'vulnerability_type', 'details', 'severity', 'confidence',
                           'tool', 'remediation']
        base_attributes = ['issue_type', 'type', 'severity', 'evidence', 'tool',
                           'references', 'details', 'remediation', 'owasp', 'cve', 'cwe', 'wasc', 'cvss', 'cvss string',
                           'external id', 'introduced date', 'last found', 'closed date', 'description',
                           'affected resources']
        code_attributes = ['file name', 'line of code'] + required_params + base_attributes
        web_attributes = ['url', 'port', 'protocol', 'transport', 'parameters', 'attack', 'proof of concept',
                          'request', 'response'] + required_params + base_attributes
        all_attributes = required_params + base_attributes + code_attributes + web_attributes
        new_vuln = dict()
        vulnerability_types = ['web', 'mobile', 'network', 'code', 'social', 'desktop', 'facility']
        scan_types = ['dynamic scan', 'network scan', 'static scan', 'sca', 'pentest', 'red team', 'iast', 'rasp']
        confidence_types = ['confirmed', 'strong', 'moderate', 'low', 'false positive']
        severity_types = ['critical', 'high', 'medium', 'low', 'informational']
        if not self.__validate_from_list('vulnerability_type', vuln, vulnerability_types):
            return None
        if not self.__validate_from_list('scan_type', vuln, scan_types):
            return None
        if not self.__validate_from_list('confidence', vuln, confidence_types):
            return None
        if not self.__validate_from_list('severity', vuln, severity_types):
            return None
        vulnerability_type = vuln['vulnerability_type'].lower()
        failed = Tester.__missing_required(required_params, vuln)
        for k, v in vuln.items():
            if k.lower() not in all_attributes:
                print("[ ! ] This parameter is not supported and will be ignored: {}".format(k))
            elif k.lower() in required_params and v in ['', None]:
                print("[ X ] The value is required for: {} = {}".format(k, v))
                failed = True
            elif (vulnerability_type == 'web' and k not in web_attributes) or \
                    (vulnerability_type == 'code' and k not in code_attributes):
                print(f"[ ! ] Unsupported parameter for {vulnerability_type} results will be ignored: {k}")
                failed = True
            else:
                new_vuln[k] = v
        if failed:
            return None
        return new_vuln

    @staticmethod
    def __validate_from_list(name, vuln, types):
        if name not in vuln.keys():
            print(f'[ X ] Missing {name}')
            return False
        if not isinstance(vuln[name], str) or \
                vuln[name].lower() not in types:
            print(f'[ X ] {name} is not valid: {vuln[name]}')
            print(f'      Allowed values: {types}')
            return False
        return True

    @staticmethod
    def __missing_required(required, vuln):
        failed = False
        keys = [x.lower() for x in vuln.keys()]
        for r in required:
            if r not in keys:
                print("[ X ] The following required parameter is missing: {}".format(r))
                failed = True
        return failed

    def run_module(self, requirements):
        try:
            return self.module.run(requirements)
        except Exception as ex:
            print('[ X ] Unable to run the module: {}'.format(ex))

    def get_requirements(self):
        try:
            return self.module.requirements()
        except Exception as ex:
            print('[ X ] Unable to get module requirements: {}'.format(ex))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Test your module')
    parser.add_argument('-p', '--path',
                        metavar='path',
                        type=str,
                        help='Relative path to the integration from this folder, ie: modules/integrations/',
                        required=True)
    parser.add_argument('-s', '--script',
                        metavar='script',
                        type=str,
                        help='The name of the script you want to test, ie: my-exploit.py',
                        required=True)
    parser.add_argument('-r', '--requirements',
                        metavar='requirements',
                        type=str,
                        help='The json file with the requirements to be sent, ie: reqs.json',
                        required=True)
    args = parser.parse_args()

    module_path = args.path
    script_name = args.script
    reqs = args.requirements
    if module_path is not None and script_name is not None and reqs is not None:
        json_data = None
        if not os.path.isdir(module_path):
            print('[ X ] The path specified does not exist')
            exit()
        if not os.path.isfile("{}{}".format(module_path, script_name)):
            print('[ X ] The script specified does not exist')
            exit()
        if not os.path.isfile(reqs):
            print('[ X ] The requirements file specified does not exist')
            exit()
        else:
            try:
                with open(reqs) as json_file:
                    json_data = json.load(json_file)
            except Exception as e:
                print("[ X ] Error loading the json data: {}".format(e))
        tester = Tester()
        module = tester.import_module(module_path, script_name)
        if module is not None:
            allgood = True
            reqs = tester.get_requirements()
            for req in reqs:
                req_found = False
                print("[ ! ] Validating requirement: {}".format(req["name"]))
                for req_key in tester.mod_requirements:
                    if req_key not in req.keys():
                        print("[ X ] Attribute '{}' is required for module requirements".format(req_key))
                        allgood = False
                for new_req in json_data:
                    if "name" not in new_req.keys():
                        print("[ X ] Missing 'name' attribute in the requirement: \n   {}".format(new_req))
                        allgood = False
                        exit()
                    elif req["name"] == new_req["name"]:
                        req_found = True
                        if req["required"] != new_req["required"]:
                            print("[ X ] Requirement '{}' has different definitions: {} != {}".format(req["name"],
                                                                                                      req["required"],
                                                                                                      new_req[
                                                                                                          "required"]))
                            allgood = False
                        if req["type"] != new_req["type"]:
                            print("[ X ] Requirement '{}' has different definitions: {} != {}".format(req["name"],
                                                                                                      req["type"],
                                                                                                      new_req[
                                                                                                          "type"]))
                            allgood = False
                        if (new_req["value"] is None or new_req["value"] == "") and req["required"]:
                            print("[ X ] Requirement '{}' has None or empty values".format(req["name"]))
                            allgood = False
                        if isinstance(req["type"], list) and new_req["value"] not in req["type"]:
                            print("[ X ] Requirement '{}' has an invalid value '{}'".format(req["name"],
                                                                                            new_req["value"]))
                            allgood = False
                if not req_found:
                    print("[ X ] Requirement '{}' is missing".format(req["name"]))
                    allgood = False
            if not allgood:
                print("[ X ] You need to fix some problems before continuing with the process")
                exit()
            print("[ ! ] Provided requirements are: Ok")
            print("[ ! ] Running the module now")
            results = tester.run_module(json_data)
            print("[ ! ] Module function completed")
            print("[ ! ] Return type: {}".format(tester.return_type))
            if isinstance(results, dict) and "status" in results.keys():
                if results["status"] == "error":
                    if "description" not in results.keys():
                        results["description"] = "No error details provided by module"
                    print("[ X ] Error received from module: {}".format(results["description"]))
                elif tester.return_type == "boolean":
                    if results["status"] is False:
                        print("[ ! ] Result: False")
                    else:
                        print("[ ! ] Result: True")
                elif tester.return_type == "null":
                    print("[ ! ] Result: Nothing is expected to be returned")
                elif tester.return_type == "asset":
                    print("[ ! ] Result: Processing assets is still in the TODO list")
                elif tester.return_type == "vuln":
                    print("[ ! ] Validating vulnerability results")
                    if "results" not in results.keys():
                        results["results"] = None
                        print("[ X ] No 'results' object in response")
                    result_data = results["results"]
                    analysis = tester.validate_vuln(result_data)
                    if analysis:
                        print("[ ! ] Vulnerability data: Ok")
                    else:
                        print("[ X ] Vulnerability data: Failed")
                else:
                    print("[ X ] Unexpected results: Failed")
            elif results is None:
                print("[ X ] Nothing returned")
            else:
                print("[ X ] Unexpected results: Failed")
            print("[ ! ] Module process completed")
