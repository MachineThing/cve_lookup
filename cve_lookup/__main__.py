from . import cve

heartbleed = cve.cve("CVE-2014-0160")
print(heartbleed.id)
print(heartbleed.cvss3v)
print(heartbleed.cvss2v)
#print(round(heartbleed.cvss3.score_overall, 1))
print(round(heartbleed.cvss2.score_overall, 1))
