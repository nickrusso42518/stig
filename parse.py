from ciscoconfparse import CiscoConfParse
import os
import yaml
import glob

def test_result(rule, result, brief=True):
    if brief:
        #print('{0: <10} {1: <60} {2}'.format('vuln id', 'description', 'pass'))
        print('{0: <10} {1: <60} {2}'.format(rule['vuln_id'], rule['desc'], result['success']))
    else:
        print('----------------------------------------------------------')
        print('Vuln ID:     {}'.format(rule['vuln_id']))
        print('Severity:    {}'.format(rule['severity']))
        print('Description: {}'.format(rule['desc']))
        if result['iter']:
            print('Passing objects:')
            for obj in result['iter']['pass']:
                print('  - {}'.format(obj.text))
            print('Failing objects:')
            for obj in result['iter']['fail']:
                print('  - {}'.format(obj.text))
            print('N/A objects:')
            for obj in result['iter']['na']:
                print('  - {}'.format(obj.text))
        print('Success: {}'.format(result['success']))
    
def check(rule):
    if rule['check']['parent']:
        return _check_hier(rule)
    else:
        return _check_global(rule) 

def _check_global(rule):
    objs = parse.find_objects(rule['check']['text'])
    success = len(objs) == rule['check']['text_cnt']
    if success:
        pass_objs = objs
        fail_objs = []
    else:
        fail_objs = objs
        pass_objs = []
    return {'success': success, 'iter': {'pass': pass_objs, 'fail': fail_objs, 'na': []}}

def _check_hier(rule):
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
    return {'iter': {'pass': pass_objs, 'fail': fail_objs, 'na': na_objs}, 'success': success }

def dump_ioscfgline(ioscfgline):
    print('text:         {}'.format(ioscfgline.text))
    print('linenum:      {}'.format(ioscfgline.linenum))

    if ioscfgline == ioscfgline.parent:
        parent = 'none'
    else:
        parent = ioscfgline.parent
    print('parent:       {}'.format(parent))
    print('child_indent: {}'.format(ioscfgline.child_indent))
    print('indent:       {}'.format(ioscfgline.indent))
    print('is_comment:   {}'.format(ioscfgline.is_comment))
    print('children:')
    for c in ioscfgline.children:
        print('  - {}'.format(c))

parse = CiscoConfParse('test.txt')
#interfaces = parse.find_objects('^ntp')
#for i in interfaces:
#    dump_ioscfgline(i)

#rid = parse.find_objects('router-id')
#for r in rid:
#    dump_ioscfgline(r)

rule_list = []
rules = sorted(glob.glob('rules/*.yml'))
for rule in rules:
    with open(rule, 'r') as stream:
        try:
            data = yaml.safe_load(stream)
            data.update({'vuln_id': os.path.basename(rule).split('.')[0]})
            rule_list.append(data)
            d = check(data)
            test_result(data, d)
        except yaml.YAMLError as exc:
            print(exc)
