# Equations from:
# https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator/v30/equations
# Metric levels from:
# https://www.first.org/cvss/v3.0/specification-document#8-4-Metrics-Levels
# (As if 7/26/2021)

from math import ceil
from . import exceptions
from . import cvss2

class cvss3_vector(cvss2.cvss2_vector):
    _version = 3.0

    round_up = lambda num : ceil(num*10)/10

    def calculate_base(self):
        # Base score calculation
        access_vector = self.score_case('AV', {'L':0.395, 'A':0.646, 'N':1})
        access_complexity = self.score_case('AC', {'H':0.35, 'M':0.61, 'L':0.71})
        authentication = self.score_case('Au', {'M':0.45, 'S':0.56, 'N':0.704})
        confidentality_impact = self.score_case('C', {'N':0, 'P':0.275, 'C':0.660})
        integrity_impact = self.score_case('I', {'N':0, 'P':0.275, 'C':0.660})
        availability_impact = self.score_case('A', {'N':0, 'P':0.275, 'C':0.660})

        self.score_impact = 10.41 * (1 - (1 - confidentality_impact) * (1 - integrity_impact) * (1 - availability_impact))
        self.score_exploitability = 20 * access_complexity * authentication * access_vector
        fimpact = 0
        if self.score_impact != 0:
            fimpact = 1.176
        return (.6*self.score_impact+.4*self.score_exploitability-1.5)*fimpact

    def calculate_temporal(self, score_base):
        exploitability = self.score_case('E', {'ND':1, 'U':0.85, 'POC':0.9, 'F':0.95, 'H':1})
        remediation_level = self.score_case('RL', {'ND':1, 'OF':0.87, 'TF':0.9, 'W':0.95, 'U':1})
        report_confidence = self.score_case('RC', {'ND':1, 'UC':0.9, 'UR':0.95, 'C':1})
        return score_base * exploitability * remediation_level * report_confidence

    def calculate_environment(self):
        collateral_damage_potential = self.score_case('CDP', {'ND':0, 'N':0, 'L':0.1, 'LM':0.3, 'MH':0.4, 'H':0.5})
        target_distribution = self.score_case('TD', {'ND':1, 'N':0, 'L':0.25, 'M':0.75, 'H':1})

        confidentality_requirement = self.score_case('CR', {'ND':1, 'L':0.5, 'M':1, 'H':1.51})
        integrity_requirement = self.score_case('IR', {'ND':1, 'L':0.5, 'M':1, 'H':1.51})
        availability_requirement = self.score_case('AR', {'ND':1, 'L':0.5, 'M':1, 'H':1.51})

        # The three variables below this comment is from the Base Score Metrics but are needed for this equation
        confidentality_impact = self.score_case('C', {'N':0, 'P':0.275, 'C':0.660})
        integrity_impact = self.score_case('I', {'N':0, 'P':0.275, 'C':0.660})
        availability_impact = self.score_case('A', {'N':0, 'P':0.275, 'C':0.660})

        self.modified_impact = min(10, 10.41 * (1 -
                                                 (1 - confidentality_impact * confidentality_requirement)
                                               * (1 - integrity_impact * integrity_requirement)
                                               * (1- availability_impact * availability_requirement)))

        # "modified_temporal" is the Temporal Score recomputed with the impact sub-equation replaced with the "modified_impact" variable
        fimpact = 0
        if self.score_impact != 0:
            fimpact = 1.176
        modified_temporal = self.calculate_temporal((.6*self.modified_impact+.4*self.score_exploitability-1.5)*fimpact)
        return (modified_temporal + (10 - modified_temporal) * collateral_damage_potential) * target_distribution

    def __init__(self, vector):
        # Initialization

        # Initialize vector here
        self.vector = {'AV':None, 'AC':None, 'PR':None, 'UI':None, 'S':None, 'C':None, 'I':None, 'A':None, 'E':'X', 'RL':'X', 'RC':'X', 'MAV':'X', 'MAC':'X', 'MPR':'X', 'MUI':'X', 'MS':'X', 'MC':'X', 'MI':'X', 'MA':'X', 'CR':'X', 'IR':'X', 'AR':'X'}

        # We don't need to remove the CVSS part as it can be treated as a vector
        self.vector_txt = vector
        vector_list = self.vector_txt.split('/')
        for vectors in vector_list:
            vectorsp = vectors.split(':')
            self.vector[vectorsp[0]] = vectorsp[1]

        # Use the inherited calculate_overall method to calculate the overall score
        self.score_overall = max(0, min(10, self.calculate_overall(['CDP', 'TD', 'CR', 'IR', 'AR'], ['E', 'RL', 'RC'])))
        if self.score_overall >= 9.0:
            self.score_name = "Critical"
        elif self.score_name >= 7.0:
            self.score_name = "High"
        elif self.score_name >= 4.0:
            self.score_name = "Medium"
        elif self.score_name >= 0.1:
            self.score_name = "Low"
        else:
            self.score_name = "None"
