[![Build Status](
https://travis-ci.org/nickrusso42518/stig.svg?branch=master)](
https://travis-ci.org/nickrusso42518/stig)

# Lightweight DISA STIG Scanner
A simple and fast Python script to scan configurations for US Government
Security Technical Implementation Guidance (STIG) compliance. The
tool works in an offline mode using an extensible framework of YAML
rulesets for each vulnerability of interest.

> Contact information:\
> Email:    njrusmc@gmail.com\
> Twitter:  @nickrusso42518

  * [Supported platforms](#supported-platforms)
  * [Usage](#usage)
  * [Operation](#operation)
  * [Testing](#testing)
  * [FAQ](#faq)

## Supported platforms
Any platform that has a text-based configuration suited for matching
by regex can be used. The examples in this repository are all based on
Cisco IOS routers and switches.

## Usage
`usage: stig.py [-h] [-v {0,1,2}] [-f] config_file`

A `config_file` is a relative path to the configuration file to scan,
for example `configs/l3pr.cfg`. These files do not have to be in `git`
but could be if they are being used as golden templates. This argument
is __required.__

The `-v` or `--verbosity` argument determines the output style:
  * `0`: One line per rule showing the vuln ID, description, and result
  * `1`: Verbose output showing all rule info, including pass/fail objects
  * `2`: CSV format, one rule per line, including pass/fail objects

This argument is __optional__ and when unspecified, `0` is assumed. See the
`samples/` folder for example outputs of each style.

The `-f` or `--failonly` argument enables the user to only print failed
(out of compliance) rules. This reduces output and is good for on-demand
testing or automated testing where the pass/NA results are not important.
This a boolean option and does not take additional parameters. This
argument is __optional__ and when unspecified, `false` is assumed. All
test results are printed by default (pass, fail, and NA).

## Operation
Each individual rule or sub-rule goes in its own YAML file. Having many
small files enables simpler searching, editing, adding, and deleting for
the management of the rule set. Note that some rules as written in the STIG
specifications may check multiple things. For example `V18633` lists many
banned tunneling protocols, but it is simpler to break these into separate
sub-rule files as shown below. This way, if there are only a few missing
protocols, the entire rule does not fail, and provides a more targeted
notification for remediation.

```
# V18633a.yml
---
severity: 2
desc: Deny outdated tunneling protocol IPP 42
check:
  text: deny\s+42\s+any\s+any\s+log
  text_cnt: 1
  parent: ^ip\s+access-list\s+extended\s+ACL_EXTERNAL
  when: true
part_of_stig:
  - l3ps
  - l3pr

# V18633b.yml
---
severity: 2
desc: Deny outdated tunneling protocol IPP 93
check:
  text: deny\s+93\s+any\s+any\s+log
  text_cnt: 1
  parent: ^ip\s+access-list\s+extended\s+ACL_EXTERNAL
  when: true
part_of_stig:
  - l3ps
  - l3pr
```

The components of a rule file are described below:
  * `severity`: The category number of 1, 2, or 3. Documentation only.
  * `desc`: Summarized explanation of the rule; be succinct.
  * `check`: Nested dictionary containing the critical parts of the rule
    * `text`: The regex to search for. Do not quote the string.
    * `text_cnt`: The number of times to search for `text`. Often times this
      is set to 1, but could be greater if the regex is generic and looking
      for many things (e.g. multiple NTP or AAA servers). To test for a
      configuration item being totally absent, use 0 (e.g. ensure that
      `ip directed-broadcast` appears zero times under each interface).
    * `parent`: The regex of the parent under which the `text` regex should
      be searched. For example, searching for ACL entries under an ACL.
      Do not quote the string.
    * `when`: The sibling to `text` that tests for a regex to be present
      before looking for `text`. For example, only check for `no ip proxy-arp`
      under an interface if it has an IP address. Set this to `true` to
      always look for `text`. If `when` is `false` or the regex fails to
      match, the item is marked "N/A" versus "PASS" or "FAIL".
      Do not quote the string.
    * `part_of_stig`: List of strings that indicate when this rule should be
      evaluated. This string must match the directive at the top of each
      configuration file to be included. For example, if a rule is part of
      `l3ps` and `l3pr`, a configuration with __either one__ of these
      directives will include this rule. The directive string
      is `!@#stig:stig_name`. See `configs/` for examples.


## Testing
A GNU Makefile is used for testing this codebase. There are currently
two steps:
  * `lint`: Runs YAML and Python linters, as well as a Python static
    code analyzer to check fo security flaws.
  * `run`: Runs the STIG tool itself with a variety of input files at
    all available verbosities to test proper operation. The default input
    files should have no failures. If any failures do exist, this step fails.
    Failures can be STIG rule failures or catastrophic unhandled exceptions.

## FAQ
__Q__: Does this tool have the logic to traverse complex dependencies?\
__A__: No. It applies the `text` regex for each rule based on its position
in the configuration, either globally or under a `parent` regex. For example,
embedding blacklist items in an object-group and calling the object-group
from an access-list will be counted by this tool unless the user defines
the rules appropriately.

__Q__: Can I add my own rules or change the existing rules?\
__A__: Yes. There is nothing specific about DISA STIGs for this tool, other
than some naming conventions (e.g., vuln ID) and design intent. I have
included several `extra` rules in the `rules/` directory to illustrate
this point. Users are encouraged to update the rules to fit their
specific environment; this is not a static, click-button dogmatic tool.

__Q__: Can configurations be part of more than one STIG?\
__A__: Yes. Use the `!@#stig:stig_name` directive at the top of the file
as many times as necessary. Ensure the corresponding rules have this
string in their `part_of_stig` YAML list.
