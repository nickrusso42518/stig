'''
Filename: stig.py
Version: Python 3.6.5
Author: Nicholas Russo (njrusmc@gmail.com)
Description: Performs a fast but imperfect scan of Cisco IOS configuration
             files against specific rule sets corresponding to the STIGs
             specified in the file. The tool provides a variety of outputs
             available depending on user preference. The tool does NOT yet
             create a standard STIG checklist .ckl file (XCCDF) and only
             outputs plain text or CSV.
'''
from os import path
from glob import glob
import argparse
import yaml
from ciscoconfparse import CiscoConfParse

def print_rule_result(rule_data, rule_result, verbosity=0):
    '''
    Print the test result to stdout based on verbosity:
      0: One line per rule showing the vuln ID, description, and result
      1: Verbose output showing all rule info, including pass/fail objects
      2: CSV format, one rule per line, including pass/fail objects

    The rule_data parameter was read in from the YAML rule file, and the
    rule_result parameter is a dictionary containing the results of the test.
    '''
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
            rule_data['vuln_id'], rule_data['severity'],
            rule_data['desc'], rule_result['success'])
        for k, v in rule_result['iter'].items():
            str_list = [line.text for line in v]
            csv_str += ',' + '~'.join(str_list)
        print(csv_str)

def check(parse, rule):
    '''
    Wrapper function that determines whether the text to check has
    parents (hierarchical check) or has no parents (global check).
    '''
    if rule['check']['parent']:
        return _check_hier(parse, rule)
    return _check_global(parse, rule)

def _check_global(parse, rule):
    '''
    Finds all objects matching the search text, then counts the number of
    times the text was found in global config. If the match count equals
    the specified text_cnt, the test succeeds and the objects matched
    are considered pass objectives. Otherwise, the test fails and the
    objects matched are considered fail objects.

    Note that the "when" condition is never evaluated here.
    '''
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
    '''
    Get all subjects under the specified parent from the rule data. If
    "when" is a boolean True then the test is always performed. If "when" is
    a string, it is treated as a search regex to look for other child elements
    before running the test. For example, proxy-ARP disabled is only relevant
    when the interface has an IP address, so "ip(backslash)s+address" is a
    valid "when" condition.

    Similar to the global check, parents that have properly matching children
    are added to the pass list, and those that lack the proper match string
    are added to the fail list. Not applicable list contains elements where
    "when" was false (interfaces that don't have IPs don't care about whether
    proxy-ARP is enabled).
    '''
    pass_objs = []
    fail_objs = []
    na_objs = []
    parents = parse.find_objects(rule['check']['parent'])

    for parent in parents:
        when = isinstance(rule['check']['when'], bool) and rule['check']['when']
        if when or parent.re_search_children(rule['check']['when']):
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
    '''
    Process command line arguments using argparse. The positional argument
    "config_file" is mandatory and specifies the file to scan. There is one
    optional argument for verbosity that changes the format of the stdout
    output as the program runs. The default verbosity is 0, the most brief.
    '''
    parser = argparse.ArgumentParser()
    parser.add_argument('config_file', help='configuration text file to scan',
                        type=str)
    parser.add_argument("-v", "--verbosity", type=int, choices=[0, 1, 2],
                        help="0 for brief, 1 for details, 2 for CSV rows", default=0)
    return parser.parse_args()

def main():
    '''
    Program entrypoint.
    '''

    # Process CLI arguments
    args = process_args()

    # Parse the config file and store as variable
    parse = CiscoConfParse(args.config_file)

    # Determine what STIGs a specific config should be compared against.
    # Note that multiple STIGs can be specified for a single config, and
    # if a bogus STIG is specified, nothing happens.
    stig_objs = parse.find_objects(r'!@#stig:\S+')
    stigs = [obj.text.split(':')[1] for obj in stig_objs]

    # Find all the rules files and iterate over them
    rule_files = sorted(glob('rules/*.yml'))
    for rule_file in rule_files:
        with open(rule_file, 'r') as stream:
            try:
                rule_data = yaml.safe_load(stream)
            except yaml.YAMLError as exc:
                print(exc)

            # Find out if the rule is needed. Basically find out
            # if the STIGs specified in a rule file overlap with the
            # STIGs specified in a config. Only one match is needed.
            overlap = [v for v in stigs if v in rule_data['part_of_stig']]
            if not overlap:
                continue

            # Rather than specify the uvln ID in each vuln file, which
            # is a waste of time, dynamically update the rule data with
            # the vuln file name.
            vuln_str = path.basename(rule_file).split('.')[0]
            rule_data.update({'vuln_id': vuln_str})

            # Perform the rule checking and print the output with
            # the user-supplied verbosity.
            rule_result = check(parse, rule_data)
            print_rule_result(rule_data, rule_result, verbosity=args.verbosity)

if __name__ == '__main__':
    main()
