from cve_lookup.cve import cve

def main():
    import argparse

    parser = argparse.ArgumentParser(description='Look up a CVE.')
    parser.add_argument('CVE', type=str, nargs=1, help='CVE id')

    args = parser.parse_args()

    my_cve = cve(args.CVE[0])
    print(my_cve.id)
    print(my_cve.cvss3v)
    #print(round(my_cve.cvss3.score_overall, 1))
    if my_cve.cvsss2v:
        print(my_cve.cvss2v)
        print(round(my_cve.cvss2.score_overall, 1), '\"{}\"'.format(my_cve.cvss2.score_name))
