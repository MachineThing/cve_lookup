from cve_lookup.vector import cvss3_vector
import unittest
import os.path

class TestScore(unittest.TestCase):
    file = os.path.join(os.path.dirname(__file__), 'cvss3.vectors')
    def test_score(self):
        tests = open(self.file, 'r')
        line = 0
        vector = None
        score = None
        calc = True
        for i in tests:
            if line == 0:
                vector = i[:-1]
            elif line == 1:
                calc = True
                score = i[:-1]
                if score == 'None':
                    calc = False
                else:
                    score = float(score)
            elif line == 3:
                line = -1
                if calc:
                    calc_score = cvss3_vector(str(vector)).score_base
                    score = round(score, 1)
                    if round(calc_score-0.1, 1) != score and round(calc_score, 1) != score and round(calc_score+0.1, 1) != score:
                        raise AssertionError('{} != {}'.format(calc_score, score))
            line += 1
        tests.close()

    def test_temporal(self):
        tests = open(self.file, 'r')
        line = 0
        vector = None
        score = None
        calc = True
        for i in tests:
            if line == 0:
                vector = i[:-1]
            elif line == 2:
                calc = True
                score = i[:-1]
                if score == 'None':
                    calc = False
                else:
                    score = float(score)
            elif line == 3:
                line = -1
                if calc:
                    calc_score = cvss3_vector(str(vector)).score_temporal
                    score = round(score, 1)
                    if round(calc_score-0.1, 1) != score and round(calc_score, 1) != score and round(calc_score+0.1, 1) != score:
                        raise AssertionError('{} != {}'.format(calc_score, score))
            line += 1
        tests.close()

    def test_environmental(self):
        tests = open(self.file, 'r')
        line = 0
        vector = None
        score = None
        calc = True
        for i in tests:
            if line == 0:
                vector = i[:-1]
            elif line == 3:
                calc = True
                score = i[:-1]
                if score == 'None':
                    calc = False
                else:
                    score = float(score)
                line = -1
                if calc:
                    calc_score = cvss3_vector(str(vector)).score_environmental
                    score = round(score, 1)
                    if round(calc_score-0.1, 1) != score and round(calc_score, 1) != score and round(calc_score+0.1, 1) != score:
                        raise AssertionError('{} != {}'.format(calc_score, score))
            line += 1
        tests.close()

if __name__ == '__main__':
    unittest.main()
