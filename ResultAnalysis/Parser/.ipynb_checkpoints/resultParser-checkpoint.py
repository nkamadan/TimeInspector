import os
import re
from unicodedata import name
import numpy as np
import pandas as pd

Filename = 'test_results.txt'

def stats():
    resultFile = open(Filename, "r")
    data = resultFile.read()
    numberOfAllFiles = re.findall('Start#######################################',data)
    print("Number of all files:", len(numberOfAllFiles))
    print("FileName number: ",len(re.findall('FileName:',data)))

    numberOfNoPaths = re.findall('no path',data)
    print("No path is found in all files:", len(numberOfNoPaths))
    numberOfShortestPathFiles = re.findall('File: \S*, len',data)
    print("Shortest path files: {}\n".format(len(numberOfShortestPathFiles)))

def print_path_found_results():
    resultFile2 = open(Filename, "r")
    line_data = resultFile2.readlines()
    #print(line_data)
    print("Files that has path:\n")
    for line in line_data:
        if(len(line)>5 and line[0:5]=='File:' and ('len(BASIC_BLOCKS):' in line)):
            print(line)

def print_no_path_found_results():
    resultFile2 = open(Filename, "r")
    line_data = resultFile2.readlines()
    #print(line_data)
    print("Files that has no path:\n")
    for line in line_data:
        if(len(line)>5 and line[0:5]=='File:' and ('no path' in line)):
            print(line)

#Path instructions parser
def testResultsOnlyParsed():
    resultFile = open(Filename, "r")
    line_data = resultFile.readlines()
    allData = []
    instruction_array_with_data = []
    instruction_array = []
    start_of_new_path = False
    first_empty_line = False
    for line in line_data:
        temp = line[0:9]
        if(len(line)>5 and line[0:1]=='[' and line[0:2]!='[{'):
            start_of_new_path = True
            instruction_array_with_data.append('')# reserved for the name of the file
            #get instruction count from this line
            count_line = line.split('instruction count: ')
            #print(count_line[1][:-1]) 
            count_line = count_line[1][:-1]
            instruction_array_with_data.append(count_line)
        elif(start_of_new_path == True and first_empty_line == False and line == '\n'):#first empty line
            first_empty_line = True
        elif(start_of_new_path == True and first_empty_line == True and line[0:9] == '     addr'):#instruction lines
            inst = line.split('disasm: ')
            inst = inst[1].split("      ")
            inst = inst[0]
            #print(inst[1][:-1])
            instruction_array.append(inst)
        elif(start_of_new_path == True and first_empty_line == True and line == '\n'):#file names
            start_of_new_path = False
            first_empty_line = False

            instruction_array_with_data.append(instruction_array)
            #print()
            #print(instruction_array_with_data)
            #print()
            allData.append(instruction_array_with_data)
            instruction_array_with_data = []
            instruction_array = []
        elif(len(line)>5 and line[0:6]=='File: '):#Set file names
            #print(line[6:].split(','))
            fileName = line[6:].split(',')
            fileName = fileName[0]
            for ndata in allData:
                if(ndata[0] == ''):
                    ndata[0] = fileName

    return allData
    #print(allInstructions)

def printAllData(allData):
    for npdata in allData:
        print()
        print(npdata)
        print()


def saveDataAsCsv(allData):
    df = pd.DataFrame(allData)
    df.to_csv('pathInstructions.csv')

def openPathInstructions():
    return pd.read_csv('pathInstructions.csv')

def print_path_found_file_names(allData):
    names = set()
    print("\nFile names that has path:")
    for npdata in allData:
        names.add(npdata[0])
    for i in names:
        print(i)
    print("\n")

def print_no_path_found_file_names():
    resultFile = open(Filename, "r")
    line_data = resultFile.readlines()
    #counter = 0
    print("File names that has no path:")
    for line in line_data:
        if(len(line)>8 and line[0:6]=='File: ' and 'no path' in line):
            tempLine = line[6:] 
            tempArray = tempLine.split(', no path')
            print(tempArray[0])
            #counter +=1
    #print(counter)
    print('\n')



stats()

print_path_found_results()

print_no_path_found_results()

allData = testResultsOnlyParsed()

print_path_found_file_names(allData)
print_no_path_found_file_names()

saveDataAsCsv(allData)

df = openPathInstructions()
print(df)