# CVE Lookup
![Version](https://img.shields.io/pypi/v/cve-lookup) ![Downloads](https://img.shields.io/pypi/dm/cve-lookup) ![MIT License](https://img.shields.io/pypi/l/cve-lookup) ![Language percent](https://img.shields.io/github/languages/top/Machinething/cve_lookup)

Look up Common Vulnerabilities and Exposures (CVE for short) and get details about them.

# How to use
## As a program
```sh
$ cve_lookup CVE-2017-5754
CVE-2017-5754
CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N
(AV:L/AC:M/Au:N/C:C/I:N/A:N)
4.7 "Medium"
```

## As a library
```python
import cve_lookup

my_cve = cve_lookup.cve("CVE-2017-5754")
print(my_cve.id)
print(my_cve.cvss3v)
print(my_cve.cvss2v)
print(round(my_cve.cvss2.score_overall, 1), '\"{}\"'.format(my_cve.cvss2.score_name))
```

# Install
#### From PyPi
```sh
$ pip3 install cve_lookup
```

#### From GitHub

```sh
$ git clone https://github.com/machinething/cve-lookup
$ cd cve-lookup
$ pip3 install -r requirements.txt
$ python3 setup.py install
```

## Requirements/Dependencies

- Python3 and Pip3
- An internet connection (You probably have one)
