
from Util.MitreMatrix import get_tactic_techniques
from game2dboard import Board
from tkinter import *
import xlsxwriter
import math

tactics = ['reconnaissance','resource-development', 'initial-access', 'execution', 'persistence',
           'privilege-escalation', 'defense-evasion', 'credential-access', 'discovery',
            'lateral-movement', 'collection', 'command-and-control',  'exfiltration', 'impact']

successRatesPerTactic = {}

def calculateSuccessOfTactic (tactic, techniquesNum,sucssesNum ):
    result = math.floor(sucssesNum/techniquesNum) * 100
    successRatesPerTactic[tactic] = result


def createOutputAsMatrix(TTPs):
    workbook = xlsxwriter.Workbook('Mapping_Res_to_MitreAttack.xlsx')
    worksheet1 = workbook.add_worksheet()

    headlineFormat = workbook.add_format()
    headlineFormat.set_bold()

    foundFormat = workbook.add_format({'bg_color': '#FFC7CE',
                                         'font_color': '#9C0006'})

    column = 0

    for tactic in tactics:
        row = 1
        sucssesNum = 0
        worksheet1.write(0, column, tactic)
        techniques =  get_tactic_techniques(tactic)
        techniquesNum = len(techniques)
        print('numOfTechinqes:', techniquesNum)
        for technique in techniques:
            if techniques[technique] in TTPs:
                worksheet1.write(row, column, technique,foundFormat)
                sucssesNum += 1
            else:
                worksheet1.write(row, column, technique)
            row+=1

        calculateSuccessOfTactic (tactic, techniquesNum,sucssesNum)
        column += 1
    workbook.close()
