# File:    Makefile
# Version: GNU Make 3.81
# Author:  Nicholas Russo (njrusmc@gmail.com)
# Purpose: Phony targets used for linting (YAML/Python) and running
#          the script for some quick testing. Unit tests may be
#          added in the future. See .travis.yml for invocation.

.DEFAULT_GOAL := all

.PHONY: all
all:	lint run

.PHONY: install
install:
	@echo "Starting  pkg installation"
	pip install -r requirements.txt
	@echo "Starting  pkg installation"

.PHONY: lint
lint:
	@echo "Starting  lint"
	find . -name "*.yml" | xargs yamllint -s
	find . -name "*.py" | xargs pylint
	find . -name "*.py" | xargs black -l 80
	find . -name "*.py" | xargs bandit
	@echo "Completed lint"

.PHONY: run
run:
	@echo "Starting  runs"
	python stig.py -f configs/ios_l2as.cfg
	python stig.py -f configs/nxos_l3pr.cfg
	python stig.py -f configs/asa_fw.cfg
	python stig.py -f -v 0 configs/nxos_l2as.cfg
	python stig.py -f -v 1 configs/ios_l3ir.cfg
	python stig.py -f -v 2 configs/ios_l3pr.cfg
	@echo "Completed runs"

.PHONY: dev
dev:
	@echo "Starting  dev tests"
	python stig.py -v 1 configs/asa_fw.cfg
	@echo "Completed dev tests"
