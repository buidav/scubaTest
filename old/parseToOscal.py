import pandas as pd

class ScubaOscal:
    '''
    Class for turning scuba into oscal
    '''

    def __init__(self, excel):
        self.excel = excel
    
    def parseExcel(self):
        df = self.excel['mapping']
        for i, j in df.iterrows():
            if 'MS.AAD' not in j['SCuBA Policy ID']:
                continue
            print(str(j['NIST SP 800-53 Revision 5 ']).splitlines())
    def toOscal(self):
        

if __name__ == '__main__':
    excel = pd.read_excel('./NistMapping.xlsx', sheet_name=None)
    oscal = ScubaOscal(excel)
    oscal.parseExcel()

