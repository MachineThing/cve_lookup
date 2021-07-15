class cvss_vector:
    def __init__(self):
        pass

def gen_cvss(vector, cvss_version=None):
    if cvss_version == None:
        if vector[0] == '(':
            cvss_version = 2.0
        elif vector[7] == '0':
            cvss_version = 3.0
        elif vector[7] == '1':
            cvss_version = 3.1
        else:
            raise ValueError('This CVSS version isn\'t valid or supported')
    else:
        if type(cvss_version) != float or type(cvss_version) != int:
            raise TypeError('CVSS version must be a float!')
        else:
            cvss_version = float(cvss_version)
