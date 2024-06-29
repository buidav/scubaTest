import pandas as pd

if __name__ == '__main__':
    excel = pd.read_excel('./NistMapping.xlsx', sheet_name=None)
    df = excel['mapping']
    for i, j in df.iterrows():
        if 'MS.AAD' not in j['SCuBA Policy ID']:
            continue
        # print(j[''], end=" ")
        # print(j[1], end=" ")
        print(str(j['NIST SP 800-53 Revision 5 ']).splitlines())
        # print(type(j))
        # print()