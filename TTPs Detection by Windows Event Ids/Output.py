
from Util.MitreMatrix import createMatrix
from game2dboard import Board
from tkinter import *
import xlsxwriter

tactics = ['Reconnaissance','Resource Development', 'Initial Access', 'Execution', 'Persistence',
           'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Discovery',
            'Lateral Movement', 'Collection', 'Command and Control',  'Exfiltration', 'Impact']

matrix = createMatrix()

workbook = xlsxwriter.Workbook('Mapping_Res_to_MitreAttack.xlsx')
worksheet1 = workbook.add_worksheet()

formatOfFound = workbook.add_format({'bg_color': '#FFC7CE',
                                     'font_color': '#9C0006'})
i=0
for tactic in tactics:
    worksheet1.write(0,i,tactic)
    i+=1

workbook.close()