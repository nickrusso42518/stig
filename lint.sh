#!/bin/bash
# File:    lint.sh
# Version: Bash 3.2.57(1)
# Author:  Nicholas Russo (nickrus@cisco.com)
# Purpose: First-stage CI check to ensure code is free from defect
#          or common styling errors. It prints out when linting starts
#          and ends, plus the name of each file discovered for linting.
#
echo "YAML linting started"
# Return code used to sum the rc from individual lint tests
rc=0
yamllint -s rules/*.yml
rc=$((rc + $?))
echo "YAML linting complete"
#
#
echo "Python linting started"
for f in $(find . -name "*.py"); do
  # Print the filename, then run 'pylint' and 'bandit'
  echo "checking $f"
  pylint $f
  # Sum the rc from pylint with the sum
  rc=$((rc + $?))
  bandit $f
  # Sum the rc from bandit with the sum
  rc=$((rc + $?))
done
echo "Python linting complete"
#
# Exit using the total rc computed. 0 means success, any else is failure
echo "All linting complete, rc=$rc"
exit $rc
