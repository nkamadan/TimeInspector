
import os
import subprocess

custom_files = []

#compile Makefile under ./bin examples .In this way, all testcase binaries will be obtained 
def makeFileRunner():
    cmd_make = 'make -C ./bin/examples/ all'
    os.system(cmd_make)

#find all executables under ./bin/examples and sort them alphabetically 
def executableFinder():
    cmd_executables = 'find ./bin/examples -type f -executable' 
    temp = subprocess.run(['find','./bin/examples','-type','f','-executable'],stdout=subprocess.PIPE)
    results = temp.stdout.decode('utf-8')
    allBinaries = sorted(results.split('\n'))
    return allBinaries

#execute all example binaries with main.py and redirect the test results into test_results.txt
def testCasesRunner():
    #clear the file
    open('test_results.txt', 'w').close()

    if custom_files == []:
        executeables = executableFinder()
    else:
        executeables = custom_files 
    #for each binary path, exacute the main.py and write the test results into test_results.txt
    for binary in executeables:
        if(binary != ''):
            binaryName = str(binary)
            print(f"analyzing {binaryName}")
            cmd = "echo " + binaryName + " | python3 main.py >> test_results.txt"
            ps = subprocess.run(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT).stdout.decode('utf-8')

    
def main():
    makeFileRunner()
    testCasesRunner()

if __name__ == "__main__":
    main()
