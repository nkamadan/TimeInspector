import os
import subprocess

custom_files = []


import errno
import os
import signal
import functools

class TimeoutError(Exception):
    pass

def timeout(seconds=10, error_message=os.strerror(errno.ETIME)):
    def decorator(func):
        def _handle_timeout(signum, frame):
            raise TimeoutError(error_message)

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            signal.signal(signal.SIGALRM, _handle_timeout)
            signal.alarm(seconds)
            try:
                result = func(*args, **kwargs)
            finally:
                signal.alarm(0)
            return result

        return wrapper

    return decorator


#compile Makefile under ./bin examples .In this way, all testcase binaries will be obtained 
def makeFileRunner():
    cmd_make = 'make -C ./bin/examples/ all'
    os.system(cmd_make)

#find all executables under ./bin/examples and sort them alphabetically 
def executableFinder():
    cmd_executables = 'find ./bin/examples -type f -executable' 
    temp = subprocess.run(['find','/home/stanalyze/Binaries/','-type','f'],stdout=subprocess.PIPE)
    results = temp.stdout.decode('utf-8')
    allBinaries = sorted(results.split('\n'))
    #print(allBinaries)
    return allBinaries

def split(a, n):
    k, m = divmod(len(a), n)
    return (a[i*k+min(i, m):(i+1)*k+min(i+1, m)] for i in range(n))

#execute all example binaries with main.py and redirect the test results into test_results.txt
def testCasesRunner(x):
    #clear the file
    open(f"test_results_{x}.txt", 'w').close()

    if custom_files == []:
        executeables = executableFinder()
    else:
        executeables = custom_files 
    #for each binary path, execute the main.py and write the test results into test_results.txt
    partialExecutables = list(split(executeables,8))
    #print("total 8 parts starting from 0")
    for binary in partialExecutables[x]:
        if(binary != ''):
            binaryName = str(binary)
            print(f"analyzing {binaryName}")
            cmd = "echo " + binaryName + f" | python3 main.py >> test_results_{x}.txt"
            try:
                ps = runthecommand(cmd)
            except:
                print("timed out, skipping")

@timeout(60*60*1,os.strerror(errno.ETIMEDOUT))
def runthecommand(cmd):
    return subprocess.run(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT).stdout.decode('utf-8') 
def main():
    #makeFileRunner()
    x =int(input("total 8 parts starting from 0, which part: "))
    testCasesRunner(x)

if __name__ == "__main__":
    main()
