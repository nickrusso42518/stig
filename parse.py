from os import path
from glob import glob
import argparse
import yaml
from ciscoconfparse import CiscoConfParse

def print_rule_result(rule_data, rule_result, verbosity=0):
    if verbosity == 0:
        print('{0: <10} {1: <62} {2}'.format(
            rule_data['vuln_id'], rule_data['desc'], rule_result['success']))
    elif verbosity == 1:
        print('----------------------------------------------------------------------')
        print('Vuln ID:     {}'.format(rule_data['vuln_id']))
        print('Severity:    {}'.format(rule_data['severity']))
        print('Description: {}'.format(rule_data['desc']))
        for k, v in rule_result['iter'].items():
            print('{0} objects:'.format(k))
            for obj in v:
                print('  - {}'.format(obj.text))
        print('Success:     {}'.format(rule_result['success']))
    elif verbosity == 2:
        csv_str = '{0},{1},{2},{3}'.format(
            rule_data['vuln_id'], rule_data['severity'], rule_data['desc'], rule_result['success'])
        for k, v in rule_result['iter'].items():
            str_list = [line.text for line in v]
            csv_str += ',' + '~'.join(str_list)
        print(csv_str)

def check(parse, rule):
    if rule['check']['parent']:
        return _check_hier(parse, rule)
    return _check_global(parse, rule)

def _check_global(parse, rule):
    objs = parse.find_objects(rule['check']['text'])
    if len(objs) == rule['check']['text_cnt']:
        success = 'PASS'
        pass_objs = objs
        fail_objs = []
    else:
        success = 'FAIL'
        pass_objs = []
        fail_objs = objs
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

    if fail_objs:
        success = 'FAIL'
    elif na_objs and not pass_objs:
        success = 'N/A'
    else:
        success = 'PASS'
    return {'iter':{'pass': pass_objs, 'fail': fail_objs, 'na': na_objs}, 'success': success}

def process_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('config_file', help='configuration text file to scan',
                        type=str)
    parser.add_argument("-v", "--verbosity", type=int, choices=[0, 1, 2],
                        help="0 for brief, 1 for details, 2 for CSV rows", default=0)
    return parser.parse_args()

def main():
    args = process_args()
    parse = CiscoConfParse(args.config_file)
    stig_objs = parse.find_objects(r'!@#stig:\S+')
    stigs = [obj.text.split(':')[1] for obj in stig_objs]
    rule_files = sorted(glob('rules/*.yml'))
    for rule_file in rule_files:
        with open(rule_file, 'r') as stream:
            try:
                rule_data = yaml.safe_load(stream)
            except yaml.YAMLError as exc:
                print(exc)

            # Find out if the rule is needed
            overlap = [v for v in stigs if v in rule_data['part_of_stig']]
            if not overlap:
                continue
            vuln_str = path.basename(rule_file).split('.')[0]
            rule_data.update({'vuln_id': vuln_str})
            rule_result = check(parse, rule_data)
            print_rule_result(rule_data, rule_result, verbosity=args.verbosity)

if __name__ == '__main__':
    main()
