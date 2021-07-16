from bs4 import BeautifulSoup
import requests
from . import vector

class cve():
    id = None
    cvss3v = None
    cvss2v = None
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
        self.cvss3v = _get_id("vuln-cvss3-nist-vector")
        self.cvss2v = _get_id("vuln-cvss2-panel-vector")
        self.cvss2 = vector.cvss2_vector(self.cvss2v)
