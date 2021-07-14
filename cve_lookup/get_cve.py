from bs4 import BeautifulSoup
import requests

nvd = requests.get("https://nvd.nist.gov/vuln/detail/CVE-2014-0160")

nvd_html = BeautifulSoup(nvd.text, 'html.parser')
print(nvd_html.find(attrs={"data-testid":"page-header-vuln-id"}).string)
