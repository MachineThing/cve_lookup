class cvss2_vector:
    _version = 2

    vector = {}
    vector_txt = None

    # -- Scores --
    # Base Scores
    score_base = 0.0
    score_impact = 0.0
    score_exploitability = 0.0

    # Temporal Score
    score_temporal = 0.0

    # Environmental Scores
    score_environmental = 0.0
    score_modified_impact = 0.0

    # Overall Score
    score_overall = 0.0
    def __init__(self, vector):
        self.vector_txt = vector
        vector_list = self.vector_txt.split('/')
        for vectors in vector_list:
            vectorsp = vectors.split(':')
            self.vector[vectorsp[0]] = vectorsp[1]


def gen_cvss(vector, cvss_version=None):
    if cvss_version == None:
        if vector[0] == '(':
            cvss_version = 2.0
        elif vector[7] == '0':
            cvss_version = 3.0
        elif vector[7] == '1':
            cvss_version = 3.1
        else:
            raise ValueError('This CVSS version isn\'t valid or supported')
    else:
        if type(cvss_version) != float or type(cvss_version) != int:
            raise TypeError('CVSS version must be a float!')
        else:
            cvss_version = float(cvss_version)
