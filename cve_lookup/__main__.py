from . import cve

heartbleed = cve.cve("CVE-2014-0160")
print(heartbleed.id)
print(heartbleed.cvss3)
print(heartbleed.cvss2)
