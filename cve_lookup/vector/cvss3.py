from cvss import CVSS3
from . import cvss2

class cvss3_vector(cvss2.cvss2_vector):
    _version = 3.0

    def __init__(self, vector):
        # Initialization

        # Prep vector
        self._vector = CVSS3(self.vector)
        self.vector_clean = self._vector.clean_vector()

        # Scores
        self.base_score = self._vector.scores()[0]
        self.temporal_score = self._vector.scores()[1]
        self.environmental_score = self._vector.scores()[2]

        # Overall score
        if self.environmental_score != None:
            self.score_overall = self.environmental_score
        elif self.temporal_score != None:
            self.score_overall = self.temporal_score
        else:
            self.score_overall = self.base_score

        # Score name
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
