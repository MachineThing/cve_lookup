from cve_lookup.vector import cvss2_vector
import unittest
import os.path

class TestScore(unittest.TestCase):
    file = os.path.join(os.path.dirname(__file__), 'cvss2.vectors')
    def test_score(self):
        tests = open(self.file, 'r')
        line = 0
        vector = None
        base_score = None
        temp_score = None
        envi_score = None
        calc = True
        for i in tests:
            if line == 0:
                vector = i[:-1]
            elif line == 1:
                base_score = i[:-1]
                if base_score == 'None':
                    calc = False
                else:
                    base_score = float(base_score)
            elif line == 2:
                temp_score = i[:-1]
                if temp_score == 'None':
                    calc = False
                else:
                    temp_score = float(temp_score)
            elif line == 3:
                envi_score = i[:-1]
                if envi_score == 'None':
                    calc = False
                else:
                    envi_score = float(envi_score)
                line = -1
                if calc:
                    self.assertEqual(round(cvss2_vector(str(vector)).score_base, 1), base_score)
                    self.assertEqual(round(cvss2_vector(str(vector)).score_temporal, 1), temp_score)
                    self.assertEqual(round(cvss2_vector(str(vector)).score_environmental, 1), envi_score)
            line += 1
        tests.close()



if __name__ == '__main__':
    unittest.main()
