import os

DIRECTORY = '/home/musa/Documents/Research/Static Analysis of Timing Attacks/lightweight'

execs = os.popen(f'find "{DIRECTORY}" -name "*"').readlines()

counter = 0
occur = 0

for ex in execs:
    ex = ex.replace('\n','')
    res = os.popen(f'objdump -dS "{ex}" | grep clock_gettime@plt').readlines()
    if (res != []):
        counter += 1
        occur += len(res)
        print(ex)

print(counter)
print(occur)