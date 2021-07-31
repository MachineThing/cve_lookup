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

    round_up = lambda self, num : ceil(num*10)/10

    def calculate_base(self):
        # Base score calculation
        scope = self.score_case('S', {'U': False, 'C': True}) # True if scope changed
        attack_vector = self.score_case('AV', {'N':0.85, 'A':0.62, 'L':0.55, 'P':0.2})
        attack_complex = self.score_case('AC', {'L':0.77, 'H':0.44})
        if scope:
            privileges_req = self.score_case('PR', {'N':0.85, 'L':0.68, 'H':0.50})
        else:
            privileges_req = self.score_case('PR', {'N':0.85, 'L':0.62, 'H':0.27})
        user_interaction = self.score_case('UI', {'N':0.85, 'R':0.62})

        confidentality_impact = self.score_case('C', {'N':0, 'L':0.22, 'H':0.56})
        integrity_impact = self.score_case('I', {'N':0, 'L':0.22, 'H':0.56})
        availability_impact = self.score_case('A', {'N':0, 'L':0.22, 'H':0.56})

        self.score_impact_base = 1 - ((1 - confidentality_impact) * (1 - integrity_impact) * (1 - availability_impact))
        if scope:
            self.score_impact = 7.52 * (self.score_impact_base - 0.029) - 3.25 * (self.score_impact_base - 0.02)**15
        else:
            self.score_impact = 6.42 * self.score_impact_base
        self.score_exploitability = 8.22 * attack_vector * attack_complex * privileges_req * user_interaction

        if self.score_impact <= 0:
            return 0
        elif scope:
            return self.round_up(min(1.08 * (self.score_impact + self.score_exploitability), 10))
        else:
            return self.round_up(min(self.score_impact + self.score_exploitability, 10))

    def calculate_temporal(self, score_base):
        exploitability = self.score_case('E', {'X':1, 'U':0.85, 'POC':0.9, 'F':0.95, 'H':1})
        remediation_level = self.score_case('RL', {'X':1, 'OF':0.87, 'TF':0.9, 'W':0.95, 'U':1})
        report_confidence = self.score_case('RC', {'X':1, 'UC':0.9, 'UR':0.95, 'C':1})
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
        self.score_overall = max(0, min(10, self.calculate_overall(['MAV', 'MAC', 'MPR', 'MUI', 'MS', 'MC', 'MI', 'MA', 'CR', 'IR', 'AR'], ['E', 'RL', 'RC'])))
        if self.score_overall >= 9.0:
            self.score_name = "Critical"
        elif self.score_overall >= 7.0:
            self.score_name = "High"
        elif self.score_overall >= 4.0:
            self.score_name = "Medium"
        elif self.score_overall >= 0.1:
            self.score_name = "Low"
        else:
            self.score_name = "None"
