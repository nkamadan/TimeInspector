import os
from numpy import True_
from pexpect import split_command_line
import r2pipe
import json
from dataclasses import dataclass
import re
from tqdm import tqdm
import sys
#from ana.main import Abl_Basic_Block, parse_abl_result

# aa --> only afx 

# ls -l file_path --> user? root?

# env LD_DEBUG=bindings ./main

# os.system("gdb -batch -ex 'file /home/kamadan/Desktop/dynamic_link_example/libfoo.so' -ex 'disassemble foo' ") 


def callJsonFromRadare(command,r2pipe):
    allJsonRadareResults = []
    for i in range(10):
        resultFromRadare = r2pipe.cmd(command)
        allJsonRadareResults.append(resultFromRadare)
        if(len(allJsonRadareResults)>2 and (allJsonRadareResults[-1]==allJsonRadareResults[-2])):
            return resultFromRadare
    else:
        print("ERRORJSON: Some problems occured in callJsonFromRadare.")
        return ''


analyzed_libs_dict = {}
total_path = 0
shrtest_path = 100000

class Afb_Basic_Block():
    def __init__(self,start_address,instr_count):
        self.start_address = start_address
        self.jump_true_address = None
        self.jump_false_address = None
        self.instr_count = instr_count
        self.calls = []

    def __str__(self): 
        return "Block-> Addr: %s, JTrue: %s, JFalse: %s, Instr_Count: %s" % (self.start_address,self.jump_true_address,self.jump_false_address,self.instr_count)

def parse_afb_result(file: str):
    result = []
    blocksJson = json.loads(file)
    for out in blocksJson:
        block = Afb_Basic_Block(hex(out["addr"]),out["ninstr"])
        if 'jump' in out:
            block.jump_true_address = hex(out["jump"])
        if 'fail' in out:
            block.jump_false_address = hex(out["fail"])
        result.append(block)
    return result


class Abl_Basic_Block():
    def __init__(self, start_address):
        self.start_address = start_address

        self.index = 0
        # Will be add later
        self.end_address = None
        # this is the address that block jumps if the
        # condition true
        self.jump_true_address = None
        # this is the address that block jumps otherwise
        self.jump_false_address = None
        # size of the basic block
        self.size = None
        # Cross refs of the block as an array
        self.xrefs = set()
        # Func of the block as an array
        self.fcns = []
        #
        self.calls = []

        # if the block has jump this flag will be true.
        self.jump_true_flag = False
        # if the block has only true jump, this flag will be false.
        self.jump_false_flag = False
        # if the block has cross refs this flag will be true.
        self.xrefs_flag = False
        # if the block calls functions this flag will be true.
        self.fcns_flag = False
        #IF THIS BLOCK IS A CALL BLOCK
        self.calls_flag = False  
        #If this block is a call the jump address will be seen in this field
        self.call_jump_address = None

        # if the block has rdtsc this flag is raised;
        self.rdtsc_flag = False
        # addresses of the rdtsc's contained here.
        self.searched_instructions = {}

        #if there is a function call whose cost already calculated, the cost of the call will be stored in here.
        self.function_call_cost = -1

        self.fake_xrefs = set()
        self.fake_rdtsc_flag = False
        self.fake_rdtsc_depth = -1

def parse_abl_result(file: str):
    BASIC_BLOCKS = []
    # get Json object
    blocksJson = json.loads(file)

    # traverse the blocks for all json object
    for idx in tqdm(blocksJson["blocks"], desc="Parsing Ablj Results..."):
        # for idx in blocksJson["blocks"]:
        startAdress = idx["addr"]
        bsc = Abl_Basic_Block(startAdress)
        sizeBlock = idx["size"]
        bsc.size = sizeBlock
        intEndAddress = hex(int(startAdress, 16) + sizeBlock)
        bsc.end_address = intEndAddress
        if 'jump' in idx:
            bsc.jump_true_flag = True
            bsc.jump_true_address = hex(idx["jump"])
        if 'fail' in idx:
            bsc.jump_false_flag = True
            bsc.jump_false_address = hex(idx["fail"])
        if 'xrefs' in idx:
            bsc.xrefs_flag = True
            bsc.xrefs = set(idx["xrefs"])
            # #print(bsc.xrefs,"%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%")
        if 'fcns' in idx:
            bsc.fcns_flag = True
            bsc.fcns = idx["fcns"]
        if 'calls' in idx:
            bsc.calls_flag = True
            bsc.calls = idx["calls"]
        BASIC_BLOCKS.append(bsc)
    return BASIC_BLOCKS

@dataclass
class symbols_meta:
    addr: str
    name: str # symbols imported from this lib
    instr_count: int # # of instructions this symbol has
    timing: bool
    def __init__(self, addr: str = "init", name: str = "init",instr_count: int = -1, timing: bool = -1):
        self.name = name
        self.addr = addr
        self.instr_count = instr_count
        self.timing = timing

    def __str__(self): 
        return "Symbol object-> Name: %s, Adress: %s, Instr: %s, Timing: %s" % (self.name,self.addr,self.instr_count,self.timing)

@dataclass
class lib_symbols:
    lib: str
    symbols: list # symbols imported from this lib --> list of symbols_meta [symbols_meta]
    priv: str # user or root privilege
    def __init__(self, lib: str = "init", symbols: list = [], priv: str = "init"):
        self.lib = lib
        self.symbols = symbols
        self.priv = priv

    def __str__(self): 
        return "Lib object-> Name: %s, Symbols: %s, Privilege: %s" % (self.lib,self.symbols,self.priv)

timing_functions = ['localtime','asctime','clock_get_time','timespec_get','clock_gettime','system_clock::now']


def get_r2(file_path):
    
    if (file_path in analyzed_libs_dict):
        return analyzed_libs_dict[file_path]
    else:
        if (file_path == ''):
            file_path = input("enter the file name to be analyzed: ")
        radare2 = r2pipe.open(file_path)
        #print("Analyzing the file ###############################")
        radare2.cmd('aaa')
        analyzed_libs_dict[file_path] = radare2
        return radare2

def imported_symbols(radare2):
    # Analyze all
    all_symbols = []
    
    #Since r2 pipe do not return correct json output all the time, we will call afbj 50 times until it return expected output. 
    for i in range(50):
        try:
            isj_result = callJsonFromRadare("isj",radare2)
            #isj_result = radare2.cmd("isj")
            blocksJson = json.loads(isj_result)
            for block in blocksJson:
                if (block["name"].find("imp.") > -1) and (block["flagname"].find("sym.imp") > -1 and block["vaddr"] != 0):
                    temp_symbol = symbols_meta(block["vaddr"],block["realname"])
                    all_symbols.append(temp_symbol)
                else:
                    continue
            return all_symbols
            break
        except:
            unUsedVar = 1
            print("INFO: In imported_symbols radare2 returned unexpected output in iteration ",i)
    else:
        print("ERRORJSON: In imported_symbols radare2 returned unexpected output 50 timesin JSON1. Program will exit.")
        print(isj_result)
        exit(1)

def check_imp_in(radare2,func):
    #Since r2 pipe do not return correct json output all the time, we will call afbj 50 times until it return expected output. 
    for i in range(50):
        try:
            isj_result = callJsonFromRadare("isj",radare2)
            #isj_result = radare2.cmd("isj")
            blocksJson = json.loads(isj_result)
            for block in blocksJson:
                if(block["flagname"].find("sym.") > -1 and block["is_imported"] == True and block["realname"] == func):
                    return "imp"
                elif(block["flagname"].find("sym.") > -1 and block["is_imported"] == False and block["realname"] == func):
                    return "in"
            break
        except:
            unUsedVar = 1
            print("INFO: In check_imp_in radare2 returned unexpected output in iteration ",i)
    else:
        print("ERRORJSON: In check_imp_in radare2 returned unexpected output 50 timesin JSON1. Program will exit.")
        print(isj_result)
        exit(1)
        
def populate_libs_wsymbols(shared_libs,all_symbols):       
    for symbol in all_symbols:
        for bin in shared_libs:
            r2 = get_r2(bin.lib)
            dump = os.popen("gdb -batch -ex 'file {}' -ex 'disassemble {}'".format(bin.lib,symbol.name)).read()
            temp = []
            incr = 0
            for out in dump:
                if out == "\n":
                    incr = incr + 1
            if(len(dump) > 0 and check_imp_in(r2,symbol.name) == "in"):
                timing = detect_timing(dump)
                if timing == True:
                    symbol.timing = True
                else:
                    symbol.timing = False
                symbol.instr_count = incr
                if(len(bin.symbols) == 0):
                    temp.append(symbol)
                    bin.symbols = temp
                    break
                else:
                    bin.symbols.append(symbol)
                    break
    return shared_libs

def populate_libs_wsymbols_reverse(shared_libs,all_symbols):
    for bin in shared_libs:
        for symbol in all_symbols:
            output = os.popen("gdb -batch -ex 'file {}' -ex 'disassemble {}'".format(bin.lib,symbol.name)).read()
            temp = []
            incr = 0
            for out in output:
                if out == "\n":
                    incr = incr + 1
            #print("COUNT: {} and symbol {}".format(incr, symbol.name))
            if(len(output) > 0):
                symbol.instr_count = incr - 2 # incr contains 2 more information lines.
                if(len(bin.symbols) == 0):
                    temp.append(symbol)
                    bin.symbols = temp
                else:
                    bin.symbols.append(symbol)
    return shared_libs
 

def privilege(shared_libs):
    for bin in shared_libs:
        result = os.popen("ls -l {}".format(bin.lib)).read()
        splitted = result.split(" ")
        bin.priv = splitted[2]
    return shared_libs   

def find_shared_libs(binary):
    sh_libs = []
    result = os.popen("ldd {}".format(binary)).read()
    dependencies = result.split("\n")
    clean = []
    for dep in dependencies:
        clean.append(dep.split(" "))
    final_paths = []
    for elem in clean:
        if(elem[0]==""):
            clean.remove(elem)
        elif (elem[0].find("linux-vdso") > -1 or elem[0].find("ld-linux") > -1):
            #print("vdso --> ignored")
            continue
        else:
            lib = lib_symbols()
            if(len(elem) == 2):  # /lib64/ld-linux-x86-64.so.2 (0x00007fb438338000)
                lib.lib = elem[0].strip()
                sh_libs.append(lib)
            else:   
                lib.lib = elem[2].strip()            # libfoo.so => /lib/libfoo.so (0x00007fb438310000)
                sh_libs.append(lib)

    return sh_libs 

def detect_timing(dump):
    splitted_by_ws = dump.split()
    for elem in splitted_by_ws:
        for func in timing_functions:
            if elem.find(func) > -1:
                return 1
        if elem.find("rdtsc") > -1 or elem.find("rdtscp") > -1:
            return 1
    return 0

def parse_afx(dump):
    split_by_newline = dump.split("\n")
    imp = []
    normal = []
    for line in split_by_newline:
        if(line != ''):
            split_by_ws = line.split()
            if(split_by_ws[0] == "C"):
                if "qword" not in split_by_ws:
                    temp_sym = symbols_meta()
                    if(split_by_ws[-1].find("sym.imp.") > -1):
                        temp_sym.name = split_by_ws[-1].replace('sym.imp.','')
                        temp_sym.addr = split_by_ws[1]
                        imp.append(temp_sym)
                    elif(split_by_ws[-1].find("sym.") > -1):
                        temp_sym.name = split_by_ws[-1].replace('sym.','')
                        temp_sym.addr = split_by_ws[1]
                        normal.append(temp_sym)
                    elif(split_by_ws[-1].find("fnc.")):
                        temp_sym.name = split_by_ws[-1]
                        temp_sym.addr = split_by_ws[1]
                        normal.append(temp_sym) #fcn.211251261
    return imp,normal        

def shortest_path(bb,graph):
    global total_path
    global shrtest_path
    
    if (bb == None):
        return
    
    total_path += bb.instr_count
    
    left_block = next((x for x in graph if x.start_address == bb.jump_false_address), None)
    loop_detect = False
    
    if(left_block != None):
        if(left_block.start_address != None):
            to_compare = int(bb.start_address[2:],16)
            if(to_compare >= int(left_block.start_address[2:],16)):
                loop_detect = True
        if loop_detect == False:
            shortest_path(left_block,graph)
    
    if (bb.jump_true_address == None and bb.jump_false_address == None):
        if total_path < shrtest_path:
            shrtest_path = total_path
   
    right_block = next((x for x in graph if x.start_address == bb.jump_true_address), None)
    loop_detect2 = False
    if(right_block != None):
        if(right_block.start_address != None):
            to_compare = int(bb.start_address[2:],16)
            if(to_compare >= int(right_block.start_address[2:],16)):
                loop_detect2 = True
        if loop_detect2 == False:
            shortest_path(right_block,graph)
        
    if (bb.jump_true_address == None and bb.jump_false_address == None):
        if total_path < shrtest_path:
            shrtest_path = total_path
    
    
    total_path -= bb.instr_count
    return shrtest_path


def do_something(lib,symbol,d): #Bu fonksiyondan foo'da timing var mi ve shortest path olacak
    global shrtest_path
    depth = d
    r2 = get_r2(lib.lib)
    imp_symbols = []
    in_symbols = []
    if symbol.name.find("fcn.") == -1:
        append_sym = "sym." + symbol.name
        r2.cmd("s %s" % append_sym)
    else:
        r2.cmd("s %s" % symbol.name)

    #Since r2 pipe do not return correct json output all the time, we will call afbj 50 times until it return expected output. 
    for i in range(50):
        try:
            afbj_res = callJsonFromRadare("afbj",r2)
            #afbj_res = r2.cmd("afbj")
            afbj_up = parse_afb_result(afbj_res)
            break
        except:
            unUsedVar = 1
            print("INFO: In do_something radare2 returned unexpected output in iteration ",i)
    else:
        print("ERRORJSON: In do_something radare2 returned unexpected output 50 timesin JSON1. Program will exit.")
        print(afbj_res)
        exit(1)

    if(depth == 0):
        shrtest_path = 10000
        return shortest_path(afbj_up[0],afbj_up) 
    else:
        #Since r2 pipe do not return correct json output all the time, we will call afbj 50 times until it return expected output. 
        for i in range(50):
            try:
                afx_result = callJsonFromRadare("afx",r2)
                #afx_result = r2.cmd("afx")
                imp_symbols,in_symbols = parse_afx(afx_result)
                break
            except:
                unUsedVar = 1
                print("INFO: In do_something radare2 returned unexpected output in iteration ",i)
        else:
            print("ERRORJSON: In do_something radare2 returned unexpected output 50 timesin JSON2. Program will exit.")
            print(afbj_res)
            exit(1)


        #print("imp_symbols for: {}".format(lib.lib))
        #print(imp_symbols)
        #print("in_symbols for: {}".format(lib.lib))
        #print(in_symbols)
        if(len(imp_symbols) > 0):
            dep_libs = find_shared_libs(lib.lib)
            imp_symbols_with_libs = populate_libs_wsymbols(dep_libs,imp_symbols)
            for d_lib in imp_symbols_with_libs:
                for i_symbol in d_lib.symbols:
                    shortest_path_of_this_symbol = do_something(d_lib,i_symbol,d-1)
                    #Since r2 pipe do not return correct json output all the time, we will call afbj 50 times until it return expected output. 
                    for i in range(50):
                        try:
                            abj_res_raw = callJsonFromRadare("abj {}".format(i_symbol.addr),r2)
                            #abj_res_raw = r2.cmd("abj {}".format(i_symbol.addr))
                            abj_res = json.loads(abj_res_raw)
                            if('addr' in abj_res):
                                bb_address_of_this_symbol = hex(abj_res["addr"])
                                for bb in afbj_up:
                                    if(bb.start_address == bb_address_of_this_symbol):
                                        bb.instr_count += shortest_path_of_this_symbol
                                        break                            
                            break
                        except:
                            unUsedVar = 1
                            print("INFO: In do_something radare2 returned unexpected output in iteration ",i)
                    else:
                        print("ERRORJSON: In do_something radare2 returned unexpected output 50 timesin JSON3. Program will exit.")
                        print(abj_res_raw)
                        exit(1)

        if(len(in_symbols) > 0):
            for in_sym in in_symbols:
                if(in_sym.name == "fcn.00076f20"):
                    continue
                else:
                    shortest_path_of_this_symbol = do_something(lib,in_sym,d-1)
                    #Since r2 pipe do not return correct json output all the time, we will call afbj 50 times until it return expected output. 
                    for i in range(50):
                        try:
                            abj_res_raw = callJsonFromRadare("abj {}".format(in_sym.addr),r2)
                            #abj_res_raw = r2.cmd("abj {}".format(in_sym.addr))
                            abj_res = json.loads(abj_res_raw)
                            if('addr' in abj_res):
                                bb_address_of_this_symbol = hex(abj_res["addr"])
                                for bb in afbj_up:
                                    if(bb.start_address == bb_address_of_this_symbol):
                                        bb.instr_count += shortest_path_of_this_symbol
                                        break                          
                            break
                        except:
                            unUsedVar = 1
                            print("INFO: In do_something radare2 returned unexpected output in iteration ",i)
                    else:
                        print("ERRORJSON: In do_something radare2 returned unexpected output 50 timesin JSON4. Program will exit.")
                        print(abj_res_raw)
                        exit(1)
        
        if((afbj_up[0].jump_true_address or afbj_up[0].jump_false_address)):
            if(afbj_up[0].jump_true_address):
                afbj_res = callJsonFromRadare(f"afbj {afbj_up[0].jump_true_address}",r2)
                #afbj_res = r2.cmd(f"afbj {afbj_up[0].jump_true_address}")
                afbj_up = parse_afb_result(afbj_res)
            if(afbj_up[0].jump_false_address):
                afbj_res = callJsonFromRadare(f"afbj {afbj_up[0].jump_false_address}",r2)
                #afbj_res = r2.cmd(f"afbj {afbj_up[0].jump_false_address}")
                afbj_up += parse_afb_result(afbj_res)
            
        
        shrtest_path = 10000

        return shortest_path(afbj_up[0],afbj_up)

#def shortest_path()
def go_deeper(depth,shared_libs):
    global total_path
    global BASIC_BLOCKS

    for lib in shared_libs:
        r2 = get_r2(lib.lib)
        ablj_result = callJsonFromRadare("ablj",r2)
        #ablj_result = r2.cmd("ablj")
        BASIC_BLOCKS = parse_abl_result(ablj_result)
        for symbol in lib.symbols:
            total_path = 0
            symbol.instr_count = do_something(lib,symbol,depth)
            #print("SYMBOL IS: {} AND INSTRUCTION COUNT IS: {}".format(symbol.name,symbol.instr_count))
    return shared_libs

def call_this_from_main(file_path, depth):
    r = get_r2(file_path)
    imp_list = imported_symbols(r)
    # print(imp_list)
    shareds = find_shared_libs(file_path)
    # print(shareds)
    result = populate_libs_wsymbols(shareds,imp_list)
    # print(result)
    # print("global variables")
    # print(all_symbols)
    # print(shared_libs)
    last = privilege(result)
    # print(last)
    # print("#############")
    abc = go_deeper(depth,last)
    #print(abc)
    return abc


# call_this_from_main('/bin/diff', 2)