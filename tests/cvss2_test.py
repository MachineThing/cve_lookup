from cve_lookup.vector import cvss2_vector
import unittest

class TestBaseScore(unittest.TestCase): # Base metrics only
    def test_score_1(self): # Real CVE (CVE-2014-0160 "Heartbleed")
        self.assertEqual(round(cvss2_vector('(AV:N/AC:L/Au:N/C:P/I:N/A:N)').score_overall, 1), 5.0)

    def test_score_2(self): # Real CVE (CVE-2017-0144 "EternalBlue")
        self.assertEqual(round(cvss2_vector('(AV:N/AC:M/Au:N/C:C/I:C/A:C)').score_overall, 1), 9.3)

    def test_score_3(self): # Real CVE (CVE-2021-34527 "PrintNightmare")
        self.assertEqual(round(cvss2_vector('(AV:N/AC:L/Au:S/C:C/I:C/A:C)').score_overall, 1), 9.0)

    def test_score_4(self): # Real CVE (CVE-2019-0708 "Bluekeep")
        self.assertEqual(round(cvss2_vector('(AV:N/AC:L/Au:N/C:C/I:C/A:C)').score_overall, 1), 10.0)

    def test_score_5(self): # Real CVE (CVE-2017-5754 "Meltdown")
        self.assertEqual(round(cvss2_vector('(AV:L/AC:M/Au:N/C:C/I:N/A:N)').score_overall, 1), 4.7)

    def test_score_6(self): # Real CVE (CVE-2021-20024)
        self.assertEqual(round(cvss2_vector('(AV:A/AC:L/Au:N/C:P/I:N/A:C)').score_overall, 1), 6.8)

    def test_score_7(self): # Removed Parenthesis, should still work
        self.assertEqual(round(cvss2_vector('AV:N/AC:L/Au:N/C:N/I:N/A:N').score_overall, 1), 0.0)

    def test_score_8(self): # Real CVE (CVE-2021-20024) but without parenthesis
        self.assertEqual(round(cvss2_vector('AV:A/AC:L/Au:N/C:P/I:N/A:C').score_overall, 1), 6.8)

class TestTemporalScore(unittest.TestCase): # Base and Temporal metrics only
    def test_score_1(self):
        self.assertEqual(round(cvss2_vector('AV:N/AC:H/Au:S/C:P/I:N/A:C/E:U/RL:U/RC:UR').score_overall, 1), 4.5)

    def test_score_2(self):
        self.assertEqual(round(cvss2_vector('(AV:N/AC:L/Au:N/C:C/I:C/A:C/E:U/RL:W/RC:UR)').score_overall, 1), 7.7)

    def test_score_3(self):
        self.assertEqual(round(cvss2_vector('(AV:N/AC:L/Au:N/C:C/I:C/A:C/E:H/RL:U/RC:C)').score_overall, 1), 10.0)

    def test_score_4(self):
        self.assertEqual(round(cvss2_vector('(AV:L/AC:H/Au:M/C:P/I:N/A:N/E:U/RL:ND/RC:UC)').score_overall, 1), 0.6)

    def test_score_5(self): # Above but without "Not Defined" modifier
        self.assertEqual(round(cvss2_vector('(AV:L/AC:H/Au:M/C:P/I:N/A:N/E:U/RC:UC)').score_overall, 1), 0.6)

class TestEnvironmentalScore(unittest.TestCase): # Base and Environmental metrics only
    def test_score_1(self):
        self.assertEqual(round(cvss2_vector('(AV:N/AC:L/Au:N/C:C/I:C/A:C/CDP:L/TD:L/CR:H/IR:H/AR:H)').score_overall, 1), 2.5)

    def test_score_2(self):
        self.assertEqual(round(cvss2_vector('(AV:A/AC:M/Au:M/C:P/I:P/A:P/CDP:H/TD:H/CR:H/IR:H/AR:H)').score_overall, 1), 7.9)

    def test_score_3(self):
        self.assertEqual(round(cvss2_vector('(AV:N/AC:M/Au:S/C:N/I:P/A:N/CDP:H/TD:M/CR:ND/IR:H/AR:ND)').score_overall, 1), 5.4)

    def test_score_4(self): # Above but without "Not Defined" modifiers
        self.assertEqual(round(cvss2_vector('(AV:N/AC:M/Au:S/C:N/I:P/A:N/CDP:H/TD:M/IR:H)').score_overall, 1), 7.9)

class TestComboScore(unittest.TestCase): # All metrics
    def test_score_1(self):
        self.assertEqual(round(cvss2_vector('(AV:N/AC:L/Au:N/C:C/I:C/A:C/E:U/RL:OF/RC:UC/CDP:N/TD:L/CR:H/IR:H/AR:H)').score_overall, 1), 1.7)

    def test_score_2(self):
        self.assertEqual(round(cvss2_vector('(AV:L/AC:H/Au:M/C:N/I:N/A:N/E:H/RL:U/RC:C/CDP:H/TD:H/CR:H/IR:H/AR:H)').score_overall, 1), 5.0)

    def test_score_3(self):
        self.assertEqual(round(cvss2_vector('(AV:A/AC:M/Au:N/C:N/I:C/A:C/E:H/RL:ND/RC:C/CDP:ND/TD:H/CR:ND/IR:H/AR:H)').score_overall, 1), 7.9)

    def test_score_4(self): # Above but without "Not Defined" modifiers
        self.assertEqual(round(cvss2_vector('(AV:A/AC:M/Au:N/C:N/I:C/A:C/E:H/RC:C/TD:H/IR:H/AR:H)').score_overall, 1), 7.9)
