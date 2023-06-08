from bs4 import BeautifulSoup
import requests
from cve_lookup import vector

class cve():
    id = None
    cvss3v = None
    cvss2v = None
    cvss3 = None
    cvss2 = None
    desc = None

    def _get_id(self, html, id, testid=True):
        try:
            if testid:
                return html.find(attrs={"data-testid":id}).string
            else:
                return html.find(attrs={"id":id}).string
        except AttributeError:
            return None

    def __init__(self, id):
        try:
            assert(type(id) == str)
            assert(id[:4].upper() == 'CVE-')
        except AssertionError:
            raise ValueError('{} is not a valid CVE id!'.format(id))
        nvd = requests.get("https://nvd.nist.gov/vuln/detail/{}".format(id.upper()))
        nvd_html = BeautifulSoup(nvd.text, 'html.parser')

        self.id = self._get_id(nvd_html, "page-header-vuln-id")
        self.cvss3v = self._get_id(nvd_html, "vuln-cvss3-nist-vector")
        self.cvss2v = self._get_id(nvd_html, "vuln-cvss2-panel-vector")
        self.desc = self._get_id(nvd_html, "vuln-analysis-description")
        if self.cvss2v:
            self.cvss2 = vector.cvss2_vector(self.cvss2v)
