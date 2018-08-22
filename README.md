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
  * [FAQ](#faq)

## Supported platforms
Any platform that has a text-based configuration suited for matching
by regex can be used. The examples in this repository are all based on
Cisco IOS routers and switches.

## Usage
`usage: stig.py [-h] [-v {0,1,2}] config_file`

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

## FAQ
