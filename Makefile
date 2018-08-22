.PHONY: lint
lint:
	yamllint -s rules/*.yml
	pylint *.py
	bandit *py

.PHONY: run
run:
	python3 stig.py configs/l2as.cfg
	python3 stig.py -v 0 configs/l2as.cfg
	python3 stig.py -v 1 configs/l3ir.cfg
	python3 stig.py -v 2 configs/l3pr.cfg
