from cve_lookup.vector import cvss3_vector
import unittest

class TestBaseScore(unittest.TestCase): # Base metrics only
    def test_score_1(self): # Real CVE (CVE-2014-0160 "Heartbleed")
        self.assertEqual(round(cvss3_vector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N').score_overall, 1), 7.5)

    def test_score_2(self): # Real CVE (CVE-2017-0144 "EternalBlue")
        self.assertEqual(round(cvss3_vector('CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H').score_overall, 1), 8.1)

    def test_score_3(self): # Real CVE (CVE-2021-34527 "PrintNightmare")
        self.assertEqual(round(cvss3_vector('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H').score_overall, 1), 8.8)

    def test_score_4(self): # Real CVE (CVE-2019-0708 "Bluekeep")
        self.assertEqual(round(cvss3_vector('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').score_overall, 1), 9.8)

    def test_score_5(self): # Real CVE (CVE-2017-5754 "Meltdown")
        self.assertEqual(round(cvss3_vector('CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N').score_overall, 1), 5.6)

    def test_score_6(self): # Real CVE (CVE-2021-20024)
        self.assertEqual(round(cvss3_vector('CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H').score_overall, 1), 8.1)

    def test_score_7(self): # Removed Parenthesis, should still work
        self.assertEqual(round(cvss3_vector('AV:P/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:N').score_overall, 1), 0.0)

    def test_score_8(self): # Real CVE (CVE-2021-20024) but without CVSS header
        self.assertEqual(round(cvss3_vector('AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H').score_overall, 1), 8.1)

class TestTemporalScore(unittest.TestCase): # Base and Temporal metrics only
    def test_score_1(self):
        self.assertEqual(round(cvss3_vector('AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:N/A:H').score_overall, 1), 5.7)

    def test_score_2(self):
        self.assertEqual(round(cvss3_vector('AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H/RL:U/RC:C').score_overall, 1), 10.0)

    def test_score_3(self):
        self.assertEqual(round(cvss3_vector('AV:P/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H/E:X/RL:O/RC:U').score_overall, 1), 5.5)

    def test_score_4(self): # Above but without "Not Defined" modifier
        self.assertEqual(round(cvss3_vector('AV:P/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H/RL:O/RC:U').score_overall, 1), 5.5)

class TestEnvironmentalScore(unittest.TestCase): # Base and Environmental metrics only
    def test_score_1(self):
        self.assertEqual(round(cvss3_vector('AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/CR:L/IR:L/AR:L/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:N/MI:N/MA:N').score_overall, 1), 0.0)

    def test_score_2(self):
        self.assertEqual(round(cvss3_vector('AV:A/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:L/CR:H/IR:H/AR:H/MAV:A/MAC:H/MPR:L/MUI:R/MS:C/MC:L/MI:L/MA:L').score_overall, 1), 6.5)

    def test_score_3(self):
        self.assertEqual(round(cvss3_vector('AV:A/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H/CR:H/IR:H/AR:H/MAV:A/MAC:H/MPR:L/MUI:R/MS:C/MC:X/MI:X/MA:X').score_overall, 1), 7.7)

    def test_score_4(self): # Above but without "Not Defined" modifiers
        self.assertEqual(round(cvss3_vector('AV:A/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H/CR:H/IR:H/AR:H/MAV:A/MAC:H/MPR:L/MUI:R/MS:C').score_overall, 1), 7.7)

class TestComboScore(unittest.TestCase): # All metrics
    def test_score_1(self):
        self.assertEqual(round(cvss3_vector('AV:P/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H/E:F/RL:T/RC:U/CR:H/IR:H/AR:H/MAV:A/MAC:H/MPR:H/MUI:N/MS:U/MC:H/MI:H/MA:H').score_overall, 1), 5.5)

    def test_score_2(self):
        self.assertEqual(round(cvss3_vector('AV:P/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:U/RC:C/CR:H/IR:H/AR:H/MAV:A/MAC:H/MPR:N/MUI:N/MS:C/MC:H/MI:H/MA:H').score_overall, 1), 8.2)

    def test_score_3(self):
        self.assertEqual(round(cvss3_vector('AV:A/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H/E:H/RL:X/RC:C/CR:H/IR:H/AR:H/MAV:A/MAC:H/MPR:L/MUI:R/MS:C/MC:X/MI:X/MA:X').score_overall, 1), 7.7)

    def test_score_4(self): # Above but without "Not Defined" modifiers
        self.assertEqual(round(cvss3_vector('AV:A/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H/E:H/RC:C/CR:H/IR:H/AR:H/MAV:A/MAC:H/MPR:L/MUI:R/MS:C').score_overall, 1), 7.7)

if __name__ == '__main__':
    unittest.main()
