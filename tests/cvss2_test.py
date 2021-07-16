from cve_lookup.vector import cvss2_vector
import unittest

class TestScore(unittest.TestCase):
    def test_score_2014_0160(self): # Heartbleed
        self.assertEqual(round(cvss2_vector('AV:N/AC:L/Au:N/C:P/I:N/A:N').score_overall, 1), 5.0)

    def test_score_2017_0144(self): # EternalBlue
        self.assertEqual(round(cvss2_vector('AV:N/AC:M/Au:N/C:C/I:C/A:C').score_overall, 1), 9.3)

    def test_score_2021_34527(self): # PrintNightmare (Remote Code Variant)
        self.assertEqual(round(cvss2_vector('AV:N/AC:L/Au:S/C:C/I:C/A:C').score_overall, 1), 9.0)

    def test_score_2019_0708(self): # Bluekeep
        self.assertEqual(round(cvss2_vector('AV:N/AC:L/Au:N/C:C/I:C/A:C').score_overall, 1), 10.0)

    def test_score_2017_5754(self): # Meltdown
        self.assertEqual(round(cvss2_vector('AV:L/AC:M/Au:N/C:C/I:N/A:N').score_overall, 1), 4.7)

    def test_score_2021_20024(self):
        self.assertEqual(round(cvss2_vector('AV:A/AC:L/Au:N/C:P/I:N/A:C').score_overall, 1), 6.8)
