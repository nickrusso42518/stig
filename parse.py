from os import path
from glob import glob
import sys
import yaml
from ciscoconfparse import CiscoConfParse

def print_rule_result(rule_data, rule_result, brief=True):
    if brief:
        print('{0: <10} {1: <62} {2}'.format(
            rule_data['vuln_id'], rule_data['desc'], rule_result['success']))
    else:
        print('----------------------------------------------------------')
        print('Vuln ID:     {}'.format(rule_data['vuln_id']))
        print('Severity:    {}'.format(rule_data['severity']))
        print('Description: {}'.format(rule_data['desc']))
        for k, v in rule_result['iter'].items():
            print('{0} objects:'.format(k))
            for obj in v:
                print('  - {}'.format(obj.text))
        print('Success:     {}'.format(rule_result['success']))

def check(parse, rule):
    if rule['check']['parent']:
        return _check_hier(parse, rule)
    return _check_global(parse, rule)

def _check_global(parse, rule):
    objs = parse.find_objects(rule['check']['text'])
    success = len(objs) == rule['check']['text_cnt']
    if success:
        pass_objs = objs
        fail_objs = []
    else:
        fail_objs = objs
        pass_objs = []
    return {'success': success, 'iter': {'pass': pass_objs, 'fail': fail_objs, 'na': []}}

def _check_hier(parse, rule):
    pass_objs = []
    fail_objs = []
    na_objs = []
    parents = parse.find_objects(rule['check']['parent'])

    for parent in parents:
        if rule['check']['when'] == True or parent.re_search_children(rule['check']['when']):
            search = parent.re_search_children(rule['check']['text'])
            if len(search) == rule['check']['text_cnt']:
                pass_objs.append(parent)
            else:
                fail_objs.append(parent)
        else:
            na_objs.append(parent)

    #  TODO: should that really be >= instead of just > ?? think isatap absence
    success = len(pass_objs) >= 0 and len(fail_objs) == 0
    return {'iter':{'pass': pass_objs, 'fail': fail_objs, 'na': na_objs}, 'success': success}

def main(argv):
    brief = int(argv[1]) == 1 if len(argv) > 1 else True
    parse = CiscoConfParse('test.txt')
    rule_files = sorted(glob('rules/*.yml'))
    for rule_file in rule_files:
        with open(rule_file, 'r') as stream:
            try:
                rule_data = yaml.safe_load(stream)
                vuln_str = path.basename(rule_file).split('.')[0]
                rule_data.update({'vuln_id': vuln_str})
                rule_result = check(parse, rule_data)
                print_rule_result(rule_data, rule_result, brief=brief)
            except yaml.YAMLError as exc:
                print(exc)

if __name__ == '__main__':
    main(sys.argv)
