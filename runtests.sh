#! /bin/bash
pip uninstall -y cve-lookup
rm -rf build dist cve_lookup.egg-info
python setup.py install
python tests/cvss2_test.py
python tests/cvss3_test.py
