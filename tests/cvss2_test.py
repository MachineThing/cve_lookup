from cve_lookup.vector import cvss2_vector
import os.path

class TestScore(unittest.TestCase):
    file = os.path.join(os.path.dirname(__file__), 'cvss2.vectors')
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
                    self.assertEqual(round(cvss2_vector(str(vector)).score_base, 1), score)
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
                    self.assertEqual(round(cvss2_vector(str(vector)).score_temporal, 1), score)
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
                    self.assertEqual(round(cvss2_vector(str(vector)).score_environmental, 1), score)
            line += 1
        tests.close()

if __name__ == '__main__':
    unittest.main()
