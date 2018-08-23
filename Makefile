# File:    Makefile
# Version: GNU Make 3.81
# Author:  Nicholas Russo (njrusmc@gmail.com))
# Purpose: Phony targets used for linting (YAML/Python) and running
#          the script for some quick testing. Unit tests may be
#          added in the future. See .travis.yml for invocation.
.PHONY: all
all:	lint run

.PHONY: lint
lint:
	yamllint -s rules/*.yml
	pylint *.py
	bandit *py

.PHONY: run
run:
	python3 stig.py -f configs/l2as.cfg
	python3 stig.py -f -v 0 configs/l2as.cfg
	python3 stig.py -f -v 1 configs/l3ir.cfg
	python3 stig.py -f -v 2 configs/l3pr.cfg
