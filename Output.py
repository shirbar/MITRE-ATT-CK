from Util.MitreMatrix import get_tactic_techniques
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import xlsxwriter
import math
import pandas as pd
import xlrd
from tkinter.ttk import Notebook,Entry
from tkinter import Scale, Tk, Frame, Label, Button, WORD
import textwrap


tactics = ['reconnaissance','resource-development', 'initial-access', 'execution', 'persistence',
           'privilege-escalation', 'defense-evasion', 'credential-access', 'discovery',
            'lateral-movement', 'collection', 'command-and-control',  'exfiltration', 'impact']

successRatesPerTactic = {}

def calculateSuccessOfTactic (tactic, techniquesNum,sucssesNum ):
    result = (sucssesNum/techniquesNum) * 100
    successRatesPerTactic[tactic] = round(result,2)

def getValue(value):
    print(value)

def getValue2(value, scale2):
    print(value)


def createOutputAsMatrix(TTPs):
    workbook = xlsxwriter.Workbook('Mapping_Res_to_MitreAttack.xlsx')
    worksheet1 = workbook.add_worksheet()

    headlineFormat = workbook.add_format()
    headlineFormat.set_bold()

    foundFormat = workbook.add_format({'bg_color': '#FFC7CE',
                                         'font_color': '#9C0006'})

    window = Tk()
    window.title("Scale,Tabs,Table Example")
    window.geometry("600x400")


    frame2 = Frame(window)
    frame2.pack(fill="both")

    tablayout = Notebook(frame2)
    tab1 = Frame(tablayout)
    tab1.pack(fill="both")

    column = 0

    for tactic in tactics:
        row = 1
        sucssesNum = 0
        worksheet1.write(0, column, tactic)
        techniques =  get_tactic_techniques(tactic)
        techniquesNum = len(techniques)

        label = Label(tab1, text=str(tactic))
        label.config(font=('Arial', 10))
        label.grid(row=row-1, column=column, sticky="nsew", padx=1, pady=1)
        tab1.grid_columnconfigure(column, weight=1)

        for technique in techniques:

            if techniques[technique] in TTPs:
                worksheet1.write(row, column, technique,foundFormat)
                sucssesNum += 1

                label = Label(tab1, text=str(technique), bg="red", fg="white" ,wraplength=500, underline=1)

            else:
                label = Label(tab1, text=str(technique),wraplength=500, underline=1)
                worksheet1.write(row, column, technique)

            label.config(font=('Arial', 9), underline=True)
            label.grid(row=row, column=column, sticky="nsew")
            tab1.grid_columnconfigure(column, weight=1)

            row+=1

        calculateSuccessOfTactic (tactic, techniquesNum,sucssesNum)
        column += 1
    workbook.close()
    tablayout.add(tab1, text="MITRE ATT&CK Mapping")

    # tab2
    tab2 = Frame(tablayout)
    tab2.pack(fill="both")
    tablayout.add(tab2, text="Results Analysis")

    # The file/file path text
    placex = 6
    placey=2
    for key in successRatesPerTactic:
        strToPrint = str(key)+' : ' + str(successRatesPerTactic[str(key)]) +' % ' + ' success rates '
        label_file1 = Label(tab2, text=strToPrint)
        label_file1.config(font=('Arial', 12))
        label_file1.pack(padx=placex, pady=placey)
        placex = placex +2

    tablayout.pack(fill="both")

    print('success results:', successRatesPerTactic)
    print('output is done')


    window.mainloop()

def check():
    wb = xlrd.open_workbook( 'Mapping_Res_to_MitreAttack.xlsx', formatting_info = True)
    ws = wb.sheet_by_index(0)
    c = ws.cell(1, 1)
    cif = ws.cell_xf_index(1, 1)
    iif = wb.xf_list[cif]
    cbg = iif.background.pattern_colour_index
    print(cbg)

