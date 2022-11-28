from shared import *
from main import Abl_Basic_Block

HIGH, LOW = range(2)
# Configuration
CHECK_LEVEL = LOW

time_reading_zones = {}

radare_instance = ''


def callJsonFromRadare(command,radare2Pipe):
    allJsonRadareResults = []
    for i in range(10):
        resultFromRadare = radare2Pipe.cmd(command)
        allJsonRadareResults.append(resultFromRadare)
        if(len(allJsonRadareResults)>2 and (allJsonRadareResults[-1]==allJsonRadareResults[-2])):
            return resultFromRadare
    else:
        print("ERRORJSON: Some problems occured in callJsonFromRadare.Command is {}".format(command))
        return ''


#SYMBOLS_TIMING
# Burada zaman okuması yapan yerlerin adreslerini alalım.
# Resolve edemediğimiz yerler eğer bu adreslereden birisine denk gelirse zaman 
# okuması olarak işleyelelim.
def get_time_xrefs(radare_interface):
    for function in SYMBOLS_TIMING.keys():
        temp = "sym.imp." + function
        #Since r2 pipe do not return correct json output all the time, we will call afbj 50 times until it return expected output. 
        for i in range(50):
            try:
                res = callJsonFromRadare(f'axt @@ {temp}',radare_interface)
                if(res != ""):
                    for line in res.split('\n')[:-1]:
                        time_reading_zones[line.split(' ')[1]] = {"name": function, "cost": SYMBOLS_TIMING[function]}
                break
            except:
                unUsedVar = 1
                print("INFO: In get_time_xrefs radare2 returned unexpected output in iteration ",i)
        else:
            print("ERRORJSON: In get_time_xrefs radare2 returned unexpected output 50 timesin JSON1. Program will exit.")
            print(res)
            exit(1)




def can_this_addr_read_time(addr):
    if(time_reading_zones.get(addr)):
        return time_reading_zones.get(addr)['cost']

def get_timing_function_name(addr):
    if(time_reading_zones.get(addr)):
        return time_reading_zones.get(addr)['name']


# Inspector function
def deepInspect(start_block :Abl_Basic_Block, end_block :Abl_Basic_Block, cost :int, radar):
    
    global radare_instance
    radare_instance = radar

    if(get_timing_function_name(start_block.start_address) == 'clock_gettime'):
        if(get_timing_function_name(end_block.start_address) == 'clock_gettime'):
            first_time_upper = get_instruction_from_address(start_block.start_address, -5)
            second_time_upper = get_instruction_from_address(end_block.start_address, -5)

            first_index = get_esi_index(first_time_upper)
            second_index = get_esi_index(second_time_upper)

            if (first_index != second_index):
                print(f"INSPECTOR: Ignored path {start_block.start_address} => {end_block.start_address} with cost {cost}")
                return -1

        return 1
    return 1

# Esi register used for clock get time
def get_esi_index(instr :str):
    return instr.split(",") [-1]

# 
def get_instruction_from_address(addr :int, bytes :int):
    radare_instance.cmd(f"s {addr}")
    res = callJsonFromRadare(f"pD {bytes}",radare_instance)
    #res = radare_instance.cmd(f"pD {bytes}")
    return res.split("     ")[-1].rstrip().lstrip()

