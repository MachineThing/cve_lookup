# Generate a bunch cvss vectors for testing.

from tqdm import tqdm
import cvsslib
from sys import argv
import random
import os.path

try:
    vectors = int(argv[1])
except IndexError:
    vectors = 100000

vectors_gen_2 = []
vectors_gen_30 = []
vectors_gen_31 = []

values_av_2 = ('L', 'A', 'N')
values_ac_2 = ('H', 'M', 'L')
values_au_2 = ('M', 'S', 'N')
values_c_2 = ('N', 'P', 'C')
values_i_2 = ('N', 'P', 'C')
values_a_2 = ('N', 'P', 'C')

values_e_2 = ('ND', 'U', 'POC', 'F', 'H')
values_rl_2 = ('ND', 'OF', 'TF', 'W', 'U')
values_rc_2 = ('ND', 'UC', 'UR', 'C')

values_cdp_2 = ('ND', 'N', 'L', 'LM', 'MH', 'H')
values_td_2 = ('ND', 'N', 'L', 'M', 'H')
values_cr_2 = ('ND', 'L', 'M', 'H')
values_ir_2 = ('ND', 'L', 'M', 'H')
values_ar_2 = ('ND', 'L', 'M', 'H')

values_av_3 = ('N', 'A', 'L', 'P')
values_ac_3 = ('L', 'H')
values_pr_3 = ('N', 'L', 'H')
values_ui_3 = ('N', 'R')
values_s_3 = ('U', 'C')
values_c_3 = ('N', 'L', 'H')
values_i_3 = ('N', 'L', 'H')
values_a_3 = ('N', 'L', 'H')

values_e_3 = ('X', 'U', 'P', 'F', 'H')
values_rl_3 = ('X', 'O', 'T', 'W', 'U')
values_rc_3 = ('X', 'U', 'R', 'C')

values_mav_3 = ('X', 'N', 'A', 'L', 'P')
values_mac_3 = ('X', 'L', 'H')
values_mpr_3 = ('X', 'N', 'L', 'H')
values_mui_3 = ('X', 'N', 'R')
values_ms_3 = ('X', 'U', 'C')
values_mc_3 = ('X', 'N', 'L', 'H')
values_mi_3 = ('X', 'N', 'L', 'H')
values_ma_3 = ('X', 'N', 'L', 'H')
values_cr_3 = ('X', 'L', 'M', 'H')
values_ir_3 = ('X', 'L', 'M', 'H')
values_ar_3 = ('X', 'L', 'M', 'H')

def gen_vector(name, values, nond=False, end='/'):
    choice = random.choice(values)
    if nond or (choice != 'ND' and choice != 'X'):
        return name+':'+random.choice(values)+end
    else:
        return ''

def gen_comp_vector(version, temporal=False, environmental=False, nond=False):
    n_vect = None
    if version == cvsslib.cvss2:
        n_vect = ''
        n_vect += gen_vector('AV', values_av_2)
        n_vect += gen_vector('AC', values_ac_2)
        n_vect += gen_vector('Au', values_au_2)
        n_vect += gen_vector('C', values_c_2)
        n_vect += gen_vector('I', values_i_2)
        n_vect += gen_vector('A', values_a_2)
        if temporal:
            n_vect += gen_vector('E', values_e_2, nond=nond)
            n_vect += gen_vector('RL', values_rl_2, nond=nond)
            n_vect += gen_vector('RC', values_rc_2, nond=nond)
        if environmental:
            n_vect += gen_vector('CDP', values_cdp_2, nond=nond)
            n_vect += gen_vector('TD', values_td_2, nond=nond)
            n_vect += gen_vector('CR', values_cr_2, nond=nond)
            n_vect += gen_vector('IR', values_ir_2, nond=nond)
            n_vect += gen_vector('AR', values_ar_2, nond=nond)
        n_vect = n_vect[:len(n_vect)-1]
    elif version == cvsslib.cvss3:
        n_vect = ''
        n_vect += gen_vector('AV', values_av_3)
        n_vect += gen_vector('AC', values_ac_3)
        n_vect += gen_vector('PR', values_pr_3)
        n_vect += gen_vector('UI', values_ui_3)
        n_vect += gen_vector('S', values_s_3)
        n_vect += gen_vector('C', values_c_3)
        n_vect += gen_vector('I', values_i_3)
        n_vect += gen_vector('A', values_a_3)
        if temporal:
            n_vect += gen_vector('E', values_e_3, nond=nond)
            n_vect += gen_vector('RL', values_rl_3, nond=nond)
            n_vect += gen_vector('RC', values_rc_3, nond=nond)
        if environmental:
            n_vect += gen_vector('MAV', values_mav_3, nond=nond)
            n_vect += gen_vector('MAC', values_mac_3, nond=nond)
            n_vect += gen_vector('MPR', values_mpr_3, nond=nond)
            n_vect += gen_vector('MUI', values_mui_3, nond=nond)
            n_vect += gen_vector('MS', values_ms_3, nond=nond)
            n_vect += gen_vector('MC', values_mc_3, nond=nond)
            n_vect += gen_vector('MI', values_mi_3, nond=nond)
            n_vect += gen_vector('MA', values_mac_3, nond=nond)
            n_vect += gen_vector('CR', values_cr_3, nond=nond)
            n_vect += gen_vector('IR', values_ir_3, nond=nond)
            n_vect += gen_vector('AR', values_ar_3, nond=nond)
        n_vect = n_vect[:len(n_vect)-1]

    calc = cvsslib.calculate_vector(n_vect, version)
    txt = n_vect+'\n{}\n{}\n{}\n'.format(calc[0], calc[1], calc[2])
    return txt

print("Generating random vectors, this will take a while depending on how many vectors you are generating.")
for version in (cvsslib.cvss2, cvsslib.cvss3):
    file = None
    dir = None
    version_f = 0
    if version == cvsslib.cvss2:
        file = os.path.join(os.path.dirname(__file__), 'cvss2.vectors')
        dir = vectors_gen_2
        version_f = 2.0
    elif version == cvsslib.cvss3:
        file = os.path.join(os.path.dirname(__file__), 'cvss3.vectors')
        dir = vectors_gen_30
        version_f = 3.0
    for vect in tqdm(range(1, vectors+1), desc="Generating CVSS {} vectors".format(version_f)):
        vector = gen_comp_vector(version, temporal=bool(random.getrandbits(1)), environmental=bool(random.getrandbits(1)))
        dir.append(vector)
    vec_store = open(file, 'w')
    for vect in dir:
        vec_store.write(vect)
    vec_store.close()
