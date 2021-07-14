from bs4 import BeautifulSoup
import requests

class cve():
    id = None
    cvss3 = None
    cvss2 = None

    def __init__(self, id):
        try:
            assert(type(id) == str)
            assert(id[:4].upper() == 'CVE-')
        except AssertionError:
            raise ValueError('{} is not a valid CVE id!'.format(id))
        nvd = requests.get("https://nvd.nist.gov/vuln/detail/{}".format(id.upper()))
        nvd_html = BeautifulSoup(nvd.text, 'html.parser')

        def _get_id(id, testid=True):
            if testid:
                return nvd_html.find(attrs={"data-testid":id}).string
            else:
                return nvd_html.find(attrs={"id":id}).string

        self.id = _get_id("page-header-vuln-id")
        self.cvss3 = _get_id("Cvss3NistCalculatorAnchor", testid=False)
        self.cvss2 = _get_id("Cvss2CalculatorAnchor", testid=False)
