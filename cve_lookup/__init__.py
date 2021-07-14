from bs4 import BeautifulSoup
import requests

cve = requests.get("https://nvd.nist.gov/vuln/detail/CVE-2014-0160")

soup = BeautifulSoup(cve.text, 'html.parser')
print(soup.prettify())
