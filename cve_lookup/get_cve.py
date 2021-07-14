from bs4 import BeautifulSoup
import requests

nvd = requests.get("https://nvd.nist.gov/vuln/detail/CVE-2014-0160")

nvd_html = BeautifulSoup(nvd.text, 'html.parser')

def get_id(id, testid=True):
    if testid:
        return nvd_html.find(attrs={"data-testid":id}).string
    else:
        return nvd_html.find(attrs={"id":id}).string
print(get_id("page-header-vuln-id"))
print(get_id("Cvss3NistCalculatorAnchor", testid=False))
print(get_id("Cvss2CalculatorAnchor", testid=False))
