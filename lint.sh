echo "Starting YAML lint"
yamllint -s rules/*.yml
echo "Complete YAML lint"
echo "Starting Python lint"
pylint *.py
echo "Complete Python lint"
