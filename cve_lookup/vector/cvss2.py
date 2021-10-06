from cvss import CVSS2

class cvss2_vector:
    _version = 2.0

    def __init__(self, vector):
        # Initialization

        # Format vector
        if vector[0] == '(':
            self.vector = vector[1:-1]
        else:
            self.vector = vector

        # Prep vector
        self._vector = CVSS2(self.vector)
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
        if self.score_overall >= 7:
            self.score_name = "High"
        elif self.score_overall >= 4:
            self.score_name = "Medium"
        else:
            self.score_name = "Low"
