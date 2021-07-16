class InvalidVectorValue(ValueError):
    def __init__(self, vector, vector_list, message=None):
        bad_value = vector_list[vector]
        if message == None:
            if type(bad_value) != str:
                bad_value = type(bad_value).__name__
            self.message = 'The \'{}\' vector cannot be \'{}\''.format(vector, bad_value)
        else:
            self.message = message
        super().__init__(self.message)

class cvss2_vector:
    _version = 2

    vector = {'AV':None, 'AC':None, 'Au':None, 'C':None, 'I':None, 'A':None, 'E':'ND', 'RL':'ND', 'RC':'ND', 'CDP':'ND', 'TD':'ND', 'CR':'ND', 'IR':'ND', 'AR':'ND'}
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
    score_name = ""

    def score_case(self, vector, vector_list, values):
        # Basically a switch case statement, Python 3.10 implements something simular but this exists for compatibility purposes with older Python versions
        for case in values:
            if vector_list[vector] == case:
                return values[case]
        raise InvalidVectorValue(vector, vector_list)

    def calculate_base(self):
        # Base score calculation
        access_vector = self.score_case('AV', self.vector, {'L':0.395, 'A':0.646, 'N':1})
        access_complexity = self.score_case('AC', self.vector, {'H':0.35, 'M':0.61, 'L':0.71})
        authentication = self.score_case('Au', self.vector, {'M':0.45, 'S':0.56, 'N':0.704})
        confidentality_impact = self.score_case('C', self.vector, {'N':0, 'P':0.275, 'C':0.660})
        integrity_impact = self.score_case('I', self.vector, {'N':0, 'P':0.275, 'C':0.660})
        availability_impact = self.score_case('A', self.vector, {'N':0, 'P':0.275, 'C':0.660})

        self.score_impact = 10.41 * (1 - (1 - confidentality_impact) * (1 - integrity_impact) * (1 - availability_impact))
        self.score_exploitability = 20 * access_complexity * authentication * access_vector
        fimpact = 0
        if self.score_impact != 0:
            fimpact = 1.176
        self.score_base = (.6*self.score_impact+.4*self.score_exploitability-1.5)*fimpact

    def calculate_overall(self):
        self.calculate_base()
        self.score_overall = self.score_base

    def __init__(self, vector):
        # Initialization
        self.vector_txt = vector
        vector_list = self.vector_txt.split('/')
        for vectors in vector_list:
            vectorsp = vectors.split(':')
            self.vector[vectorsp[0]] = vectorsp[1]
        self.calculate_overall()



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
