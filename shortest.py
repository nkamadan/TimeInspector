#!/usr/bin/python3

from operator import truediv
import os
from posixpath import split
import r2pipe
import json
from tqdm import tqdm  # !! pip install tqdm -> nice library for progress bar
from utils import *
import statistics


# Configurations
FILE = '/home/musa/Documents/Research/Static Analysis of Timing Attacks/Code/tt/Basic-Block/a.out'
# FILE = '/lib/x86_64-linux-gnu/libc.so.6'
XREF_DEPTH = 2

BASIC_BLOCKS = []
BLOCKS_CONTAINS_RDTSC = []
BLOCKS_CONTAINS_RDTSC_TMP = []
SYMBOLS = {} # address: instruction_count

TEMPY = []
r = ''

def open_file():
    global FILE

    if (FILE == ''):
        FILE = input("enter the file name to be analyzed: ")

    return (r2pipe.open(FILE))

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

def split_call(block: Abl_Basic_Block, from_next):
    if(block == -1):
        return
    
    r.cmd("e search.from = %s;" % block.start_address)
    r.cmd("e search.to = %s;" % block.end_address)

    # find instruction in given address range. then get result as string.
    result = r.cmd("/am call")
    block.calls = []
    block.calls_flag = False

    if (from_next):
        BASIC_BLOCKS.append(block)

    if (result != ""):
        
        result = result.split('\n')[:-1][0].split(
            ' ')  # result[0] = the address of the CALL instruction. result[3] = the address that the CALL goes.
        tmp = []
        for elem in result:  # Clear empty chars
            if elem != '':
                tmp.append(elem)
        result = tmp

        if (is_hex(result[3]) == True):  # Address can be resolved
            # cur_inst_len = int(len(result[1])/2)
            cur_inst_len = int(result[1])
            jump_addr = result[3]

            # Construct the block which contains only the CALL
            call_block = Abl_Basic_Block(result[0])
            call_block.end_address = hex(int(result[0], 16) + cur_inst_len)
            call_block.start_address = result[0]
            call_block.size = cur_inst_len
            call_block.calls_flag = True
            call_block.calls.append(jump_addr)

            # CALL instruction is the only instruction in this block.
            if int(result[0], 16) == int(block.start_address, 16) and int(result[0], 16) + cur_inst_len == int(block.end_address, 16):
                
                block.calls_flag = True
                block.fake_xrefs = block.fake_xrefs.union(block.xrefs)
                block.calls.append(jump_addr)
                return  # We do not need to do anything, it is already separated.

            # CALL is the last instruction. Modify the current block.
            elif int(block.end_address, 16) - cur_inst_len == int(result[0], 16):
                call_block.jump_false_address = block.jump_false_address
                call_block.jump_true_address = block.jump_true_address
                call_block.jump_true_flag = block.jump_true_flag
                call_block.jump_false_flag = block.jump_false_flag

                call_block.fake_xrefs = call_block.fake_xrefs.union(block.fake_xrefs)
                call_block.fake_xrefs = call_block.fake_xrefs.union(block.xrefs)

                block.end_address = call_block.start_address
                block.jump_true_flag = True
                block.jump_true_address = call_block.start_address  # block will jump to call block.
                block.size = block.size - cur_inst_len
                block.jump_false_address = None

                BASIC_BLOCKS.append(call_block)


            # CALL instruction is the first instruction
            elif int(result[0], 16) == int(block.start_address,
                                           16):  # CALL is the 1st instruction. No need to create a call_block.
                # Just create a next block and modify the block and bind next block and block accordingly.
                next_block = Abl_Basic_Block(hex(int(result[0], 16) + cur_inst_len))
                next_block.end_address = block.end_address
                next_block.size = block.size - cur_inst_len
                next_block.jump_false_address = block.jump_false_address
                next_block.jump_true_address = block.jump_true_address
                next_block.jump_false_flag = block.jump_false_flag
                next_block.jump_true_flag = block.jump_true_flag
                next_block.rdtsc_flag = block.rdtsc_flag

                next_block.fake_xrefs = next_block.fake_xrefs.union(block.fake_xrefs)
                next_block.fake_xrefs = next_block.fake_xrefs.union(block.xrefs)

                block.end_address = hex(int(result[0], 16) + cur_inst_len)
                block.size = cur_inst_len
                block.calls_flag = True
                block.jump_true_address = next_block.start_address
                block.jump_true_flag = True
                block.jump_false_address = None
                block.calls.append(result[3])

                split_call(next_block, 1)  # Keep searching for further calls in the next block

            # GENERAL CASE. CALL is at the middle of somewhere.
            else:
                next_block = Abl_Basic_Block(hex(int(result[0],16) + cur_inst_len))  # Next block will be after the call_block which is only 1 instruction
                next_block.end_address = block.end_address
                next_block.jump_true_address = block.jump_true_address
                next_block.jump_false_address = block.jump_false_address
                next_block.jump_true_flag = block.jump_true_flag
                next_block.jump_false_flag = block.jump_false_flag

                next_block.fake_xrefs = next_block.fake_xrefs.union(block.fake_xrefs)
                next_block.fake_xrefs = next_block.fake_xrefs.union(block.xrefs)

                next_block.size = int(next_block.end_address, 16) - int(next_block.start_address, 16)

                block.calls_flag = False
                block.end_address = call_block.start_address
                block.jump_true_address = call_block.start_address
                block.jump_true_flag = True
                block.size = int(call_block.start_address, 16) - int(block.start_address, 16)
                block.jump_false_flag = False
                block.jump_false_address = None

                call_block.jump_true_address = next_block.start_address
                call_block.jump_true_flag = True

                call_block.fake_xrefs = call_block.fake_xrefs.union(block.fake_xrefs)
                call_block.fake_xrefs = call_block.fake_xrefs.union(block.xrefs)

                BASIC_BLOCKS.append(call_block)
                
                split_call(next_block, 1)  # Keep searching for further calls in the next block.

        else:
            a = 2

infi = 1000000000

def dijkstraDist(g, s, path):
    # used for finding the shortest path
    # maps basic block addresses to index of basic block in G array.
    
    BASIC_BLOCKS_ADDRS_TO_INDEX = {}

    # create the mapping stated above
    for i in range(len(g)):
        BASIC_BLOCKS_ADDRS_TO_INDEX[g[i].start_address] = i

    # distance of each start address from root rdtsc
    # in an array, mapped accordingly indexes.
    dist = [infi for i in range(len(g))]

    # whether the start_address (inside the g (basic_blocks)) is visited or not
    visited = [False for i in range(len(g))]

    # initialize the graph for dijkstra iteration
    for i in range(len(g)):
        path[i] = -1
    dist[s] = 0
    path[s] = -1
    current = s

    # sett is used to keep next-step vertices
    sett = set()
    first_Iteration = True

    insideCallAddresses = []

    while (True):
        # mark current as visited
        # however in case of a loop, we will not mark starting point as visited
        if (first_Iteration == False):
            visited[current] = True
        first_Iteration = False

        #If the block is call
        if (g[current].calls_flag == True):
            
            v = BASIC_BLOCKS_ADDRS_TO_INDEX.get(g[current].call_jump_address)
            
            if g[current].call_jump_address in SYMBOLS:

                vInsideCall = BASIC_BLOCKS_ADDRS_TO_INDEX.get(g[current].call_jump_address)
                #if the call cost is already set, do not set again
                if(g[vInsideCall].function_call_cost == -1):
                    #set function call cost from dependency symbols dictionary  
                    g[vInsideCall].function_call_cost = SYMBOLS[g[vInsideCall].start_address] 
                    #print("Function call cost of address {} is {}.".format(g[vInsideCall].start_address,g[vInsideCall].function_call_cost))
            

            try:
                if (not visited[v]):
                    insideCallAddresses.append(g[current].start_address)
                    # insert into visited vertex
                    sett.add(v)
                    alt = dist[current] + g[current].size

                    # condition to check the distance is correct and update
                    # if it is minimum from the previous than compute the distance
                    if alt < dist[v] or (v == s and dist[v] == 0):
                        dist[v] = alt
                        path[v] = current
                else:
                    #The cost should be set and there should not be recursion.
                    vInsideCall = BASIC_BLOCKS_ADDRS_TO_INDEX.get(g[current].call_jump_address)
                    if(g[vInsideCall].function_call_cost != -1 and g[current].start_address not in insideCallAddresses):
                        try:
                            #next address of the function call
                            v = BASIC_BLOCKS_ADDRS_TO_INDEX.get(g[current].jump_true_address)
                            if (visited[v] == False):
                                sett.add(v)
                                
                                alt = dist[current] + g[vInsideCall].function_call_cost

                                if alt < dist[v] or (v == s and dist[v] == 0):
                                    dist[v] = alt
                                    path[v] = current
                        except:
                            print("ERROR: The function call do not have jump true address.".format(g[current].start_address))
                            
                    else:
                        print("ERROR:The function call {} has {} cost.".format(g[vInsideCall].start_address,g[vInsideCall].function_call_cost))
            except:
                swszxc =3
        else:

            if (g[current].jump_true_flag == True and g[current].jump_true_address is not None):
                v = BASIC_BLOCKS_ADDRS_TO_INDEX.get(g[current].jump_true_address)
                try:
                    if (visited[v] == False):
                        sett.add(v)
                        alt = dist[current] + g[current].size

                        if alt < dist[v] or (v == s and dist[v] == 0):
                            dist[v] = alt
                            path[v] = current
                except:
                    swszxc =3

            if g[current].jump_false_flag == True and g[current].jump_false_address is not None:

                v = BASIC_BLOCKS_ADDRS_TO_INDEX.get(g[current].jump_false_address)
                try:
                    if not visited[v]:

                        # insert into visited vertex
                        sett.add(v)
                        alt = dist[current] + g[current].size

                        if alt < dist[v] or (v == s and dist[v] == 0):
                            dist[v] = alt
                            path[v] = current
                except:
                    swszxc =3

            if (g[current].jump_true_flag == False and g[current].jump_false_flag == False 
                and g[current].calls_flag == False and len(g[current].fake_xrefs) != 0):
        
                # TODO : make sure this case is always a return case of a function
                
                #if this return came from after function call is called, then set this flag as true
                fromCall = False
                tempXrefs = g[current].fake_xrefs
                for xref in tempXrefs:
                    xrefHex = hex(xref)
                    if(xrefHex in insideCallAddresses):
                        fromCall = True
                        tempXrefs = [int(xrefHex,0)]
                        insideCallAddresses.remove(xrefHex)
                        break
                
                #traverse all xref adrresses for marking the blocks after the calls
                for currentXrefAddressInt in tempXrefs:
                    currentXrefAddressHex = hex(currentXrefAddressInt)
                    #currentXrefAddressHex is the function call adress
                    v = BASIC_BLOCKS_ADDRS_TO_INDEX.get(currentXrefAddressHex)
                    #g[v].jump_true_address is the next block address after the call
                    try:
                        v = BASIC_BLOCKS_ADDRS_TO_INDEX.get(g[v].jump_true_address)
                    except:
                        print("error")

                    if( v == None):
                        print("Function call is the last element of basic block. Will throw exception.")
                    try:
                        if not visited[v]:

                            sett.add(v)
                            alt = dist[current] + g[current].size

                            # condition to check the distance is correct and update
                            # if it is minimum from the previous than compute the distance
                            if alt < dist[v] or (v == s and dist[v] == 0):
                                #set function call cost if this return reached from a call (not starting from the function)
                                #the cost will be set on call jump addresses of the calls since they are shared
                                if(fromCall):
                                    vFunctionCall = BASIC_BLOCKS_ADDRS_TO_INDEX.get(currentXrefAddressHex)
                                    vFunctionCallStart = BASIC_BLOCKS_ADDRS_TO_INDEX.get(g[vFunctionCall].call_jump_address)
                                    totalCost = alt - dist[vFunctionCallStart]
                                    #print("TotalCost for block {} is: {}".format(g[vFunctionCall].call_jump_address,totalCost)) 
                                    g[vFunctionCallStart].function_call_cost = totalCost
                                dist[v] = alt
                                path[v] = current
                    except:
                        bxzq = 2
                        ##print("Error in dijkstra return case, block start address is:{}".format(g[current].start_address))
        if current in sett:
            sett.remove(current)

        if len(sett) == 0:
            break
        minDist = infi
        index = 0

        # Loop to update the distance
        # of the vertices of the graph
        for a in sett:
            if dist[a] < minDist:
                minDist = dist[a]
                index = a
        current = index
    return dist

def is_inst_in_block(block, instruction: str):
    # set radare's search engine configuration to our current scope
    r.cmd("e search.from = %s;" % block.start_address)
    r.cmd("e search.to = %s;" % block.end_address)

    # find instruction in given address range. then get result as string.
    result = r.cmd("/am %s" % instruction)

    # if searched instruction is found
    if (result != ""):
        block.rdtsc_flag = True

        # split line by line then add the instruction to searched instruction dictionary in Basic_Block
        splitted = result.split('\n')[:-1]
        for line in splitted:
            a = line.split(' ')
            # #print("printing a__",a)
            block.searched_instructions[a[0]] = instruction

        #print("for block: ", block.start_address, " found: ", block.searched_instructions, "\n")
        if (block not in BLOCKS_CONTAINS_RDTSC):
            BLOCKS_CONTAINS_RDTSC.append(block)

def fill_calls_jump_address_fields(basic_blocks):
    for block in basic_blocks:
        if block.calls_flag == True:
            axf_result = r.cmd("axf {}".format(block.start_address))
            temp = axf_result.split(" ")
            if(len(temp)>=3):
                block.call_jump_address = hexLeadingZeroEreaser(temp[1])
            else:
                continue

def find_instruction_count_from_start_address(start_address,end_address):
    r.cmd("s {}".format(start_address))
    #get basic block of the seek address as json format
    basicBlockOfAddressRaw = r.cmd("pdbj")
    pdbj_Results = json.loads(basicBlockOfAddressRaw)
    InstructionCount = 0
    startFound = False 
    #count the number of instruction between start address and end address of the basic block (both included)
    #if the end address is not in the json object, we might thought last object is the end address since the basic block ends there
    for row in pdbj_Results:
        addressOfRowHex = hex(row["offset"])
        if(addressOfRowHex == start_address):
            startFound = True
        if startFound == True:
            InstructionCount += 1
        if(addressOfRowHex == end_address):
            break
    return InstructionCount
    
def fill_size_fields(basic_blocks):
    r.cmd("f- hit*")
    for block in basic_blocks:
        if block.calls_flag == True:
            block.size = 1 # will be decided later
        elif block.rdtsc_flag == True:
            if block.size == None: # or fake_rdtsc_flag == True # can be used in future
                block.size = 1
        else:
            block.size = find_instruction_count_from_start_address(block.start_address, block.end_address)

# ========================== NEW CODES FOR ADRESS TO ADDRESS =========================== ##

def give_functions_depth(block : Abl_Basic_Block, depth):
    if (block == -1):
        return
    
    if (depth == XREF_DEPTH + 2):
        for x in block.fcns:
            if (get_basic_block(hex(x)) != -1):
                get_basic_block(hex(x)).function_call_cost = 1
    
        for x in block.calls:
            if (get_basic_block(x) != -1):
                get_basic_block(x).function_call_cost = 1

        return 
    
    give_functions_depth(get_basic_block(block.jump_true_address),depth)
    give_functions_depth(get_basic_block(block.jump_false_address),depth)

    for x in block.fcns:
        give_functions_depth(get_basic_block(hex(x)),depth+1)
    
    for x in block.calls:
        give_functions_depth(get_basic_block(x),depth+1)
    

def depth_xref_filler(list):

    for block in list:
        block = get_basic_block(block)
        block_start_address = block.start_address
        afb_result = r.cmd("afbj {}".format(block_start_address))
        afb_json = json.loads(afb_result)
        function_address_int = afb_json[0]["addr"]
        function_address_hex = hex(function_address_int)
        axt_result = r.cmd("axtj {}".format(function_address_hex))
        axt_json = json.loads(axt_result)
        # #print("\n BLOCK ADDR: {} -----------------<".format(block_start_address))
        for xref in axt_json:
            if xref['type'] == 'CALL':
                xref_address_int = int(xref['from'])
                block.fake_xrefs.add(xref_address_int)

        axt_result = r.cmd("axtj {}".format(block_start_address))
        axt_json = json.loads(axt_result)
        block.xrefs = set()
        for xref in axt_json:
            if xref['type'] == 'CALL':
                xref_address_int = int(xref['from'])
                block.xrefs.add(xref_address_int)

def create_possible_paths(block,addr_list,depth):
    if (block == -1 or depth == XREF_DEPTH ):
        return addr_list

    addr_list.append(block.jump_true_address)
    create_possible_paths(get_basic_block(block.jump_true_address),addr_list,depth+1)

    addr_list.append(block.jump_false_address)
    create_possible_paths(get_basic_block(block.jump_false_address),addr_list,depth+1)

    for call_block in block.fcns:
        addr_list.append(hex(call_block))
        create_possible_paths(get_basic_block(hex(call_block)),addr_list,depth+1)
    
    for call_block in block.calls:
        addr_list.append(hex(call_block))
        create_possible_paths(get_basic_block(hex(call_block)),addr_list,depth+1)
    
    return addr_list

def get_basic_block(addr):
    for block in BASIC_BLOCKS:
        if (block.start_address == addr):
            return block
    return -1

# Imitate end address as rdtsc
def find_shortest(possible_exit_list):
    # Create fake rdtsc block
    for exit in possible_exit_list:
        block : Abl_Basic_Block
        block = get_basic_block(hexLeadingZeroEreaser(exit['start']))
        if block == -1:
            return "Err"

        block.end_address = hex(int(block.end_address, 16) - 2)
        block.jump_true_address = hex(int(block.end_address, 16))
        block.jump_true_flag = True

        last_addr = hex(int(block.end_address, 16))

        rdtsc_block = Abl_Basic_Block(last_addr)
        rdtsc_block.end_address = hex(int(last_addr, 16) + 2)
        rdtsc_block.start_address = last_addr
        rdtsc_block.size = 2
        rdtsc_block.calls = []
        rdtsc_block.calls_flag = False
        rdtsc_block.rdtsc_flag = True
        rdtsc_block.jump_false_flag = False 
        rdtsc_block.jump_true_flag = True

        BLOCKS_CONTAINS_RDTSC.append(rdtsc_block)
        BASIC_BLOCKS.append(rdtsc_block)
# Hard-coded possible exit function
def find_possible_exits(addr):
    r.cmd("s {addr}")
    res = r.cmd("afb {}".format(addr))
    res = res.split('\n')
    possible_exits = []
    
    for line in res[:-1]:
        line = line.split(" ")
        if len(line) < 5:
            possible_exits.append({"start": line[0], "end": line[1]})
    
    return possible_exits

def call_helper(block : Abl_Basic_Block, depth):
    if (depth == 10 or block == -1):
        return

    split_call(block,0)

    split_call(get_basic_block(block.jump_true_address),0)
    call_helper(get_basic_block(block.jump_true_address),depth+1)
    split_call(get_basic_block(block.jump_false_address),0)
    call_helper(get_basic_block(block.jump_false_address),depth+1)

    for t in block.calls:
        try:
            split_call(get_basic_block(t),0)
        except(Exception):
            print("..")
        call_helper(get_basic_block(t), depth + 1)

def generate_call_splitter(addr):
    main_block : Abl_Basic_Block
    main_block = get_basic_block(addr)
    call_helper(main_block,0)
    
def fill_xref_fields():
    # iterate each block (tqdm for progress bar)
    for block in tqdm(BASIC_BLOCKS, desc="Filling xrefs..."):
        # for block in BASIC_BLOCKS:
        block_start_address = block.start_address
        afb_result = r.cmd("afbj {}".format(block_start_address))
        afb_json = json.loads(afb_result)
        function_address_int = afb_json[0]["addr"]
        function_address_hex = hex(function_address_int)
        axt_result = r.cmd("axtj {}".format(function_address_hex))
        axt_json = json.loads(axt_result)
        # #print("\n BLOCK ADDR: {} -----------------<".format(block_start_address))
        for xref in axt_json:
            if xref['type'] == 'CALL':
                xref_address_int = int(xref['from'])
                block.fake_xrefs.add(xref_address_int)

        axt_result = r.cmd("axtj {}".format(block_start_address))
        axt_json = json.loads(axt_result)
        block.xrefs = set()
        for xref in axt_json:
            if xref['type'] == 'CALL':
                xref_address_int = int(xref['from'])
                block.xrefs.add(xref_address_int)


def main():
    global BLOCKS_CONTAINS_RDTSC
    global r
    
    r = open_file()
    r.cmd('aaa;')
    abl_result = r.cmd('ablj')

    while abl_result == '':
        abl_result = r.cmd('ablj')

    parse_abl_result(abl_result)

    #FOO_ADDR = '0x61cc0'
    FOO_ADDR = '0x11b4'

    slist = create_possible_paths(get_basic_block(FOO_ADDR),[],0)
    slist = list(dict.fromkeys(slist))
    slist = list(filter(None, slist))
    depth_xref_filler(slist)

    possible_exit_list = find_possible_exits(FOO_ADDR)
    
    # for block in BASIC_BLOCKS:
    # # #print("Splitting started for basic block number {} for CALLS".format(basic_index))
    #     split_call(block, 0)
    find_shortest(possible_exit_list)

    generate_call_splitter(FOO_ADDR)
    
    #depth_xref_filler(get_basic_block(FOO_ADDR),0)
    # TODO BURAYA ADRES BAŞI EKLENECEK
    start_addresses_of_rdtsc_blocks = [FOO_ADDR]

    #convert addresses for a standard format such as 0x00001160 to 0x1160
    convertAllHexBasicBlockFieldsToStandardFormat(BASIC_BLOCKS)
    #fill calls jump address fields of basic blocks
    fill_calls_jump_address_fields(BASIC_BLOCKS)

    fill_size_fields(BASIC_BLOCKS)

    give_functions_depth(get_basic_block(FOO_ADDR),0)

    path_lengths = []    

    for blk in start_addresses_of_rdtsc_blocks:
        start = 0
        for i in range(len(BASIC_BLOCKS)):
            if (BASIC_BLOCKS[i].start_address == blk):
                start = i
                break

        path = [0 for k in range(len(BASIC_BLOCKS))]
        dist = dijkstraDist(BASIC_BLOCKS, start, path)

        for i in range(len(dist)):
            if (dist[i] != infi):
                if (BASIC_BLOCKS[i].rdtsc_flag == True or BASIC_BLOCKS[i].fake_rdtsc_flag == True) and dist[i] != 0:
                    
                    print("[{}] ==> [{}] instruction count: {}".format(
                        BASIC_BLOCKS[start].start_address, BASIC_BLOCKS[i].start_address, dist[i]))

                    path_lengths.append(dist[i])

    name = FILE.split('/')[-1]
    try:
        print(f'{name},{len(BASIC_BLOCKS)},{len(BLOCKS_CONTAINS_RDTSC)},{len(path_lengths)},{min(path_lengths)},{statistics.mean(path_lengths)},{statistics.median(path_lengths)}')
    except:
        print("no path")



if __name__ == "__main__":
    #print("#####################################################################################################")
    print(f"-------- Analyzing {FILE} --------\n")
    main()
    
