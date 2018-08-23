# File:    Makefile
# Version: GNU Make 3.81
# Author:  Nicholas Russo (njrusmc@gmail.com)
# Purpose: Phony targets used for linting (YAML/Python) and running
#          the script for some quick testing. Unit tests may be
#          added in the future. See .travis.yml for invocation.
.PHONY: all
all:	lint run

.PHONY: lint
lint:
	@echo "Starting  lint"
	find . -name "*.yml" | xargs yamllint -s
	find . -name "*.py" | xargs pylint
	find . -name "*.py" | xargs bandit
	@echo "Completed lint"

.PHONY: run
run:
	@echo "Starting  runs"
	python3 stig.py -f configs/ios_l2as.cfg
	python3 stig.py -f configs/nxos_l3pr.cfg
	python3 stig.py -f -v 0 configs/nxos_l2as.cfg
	python3 stig.py -f -v 1 configs/ios_l3ir.cfg
	python3 stig.py -f -v 2 configs/ios_l3pr.cfg
	@echo "Completed runs"
