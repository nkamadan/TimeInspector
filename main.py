#!/usr/bin/python3

from cmath import exp
import os
import r2pipe
import json
from tqdm import tqdm  # !! pip install tqdm -> nice library for progress bar
from utils import *
from shared import *
import shared as share
from time_checker import *
import statistics
from Deependency.ldd import call_this_from_main
import re
def open_file():
    global FILE

    if (FILE == ''):
        FILE = input()
    
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

def callJsonFromRadare(command):
    allJsonRadareResults = []
    for i in range(10):
        resultFromRadare = r.cmd(command)
        allJsonRadareResults.append(resultFromRadare)
        if(len(allJsonRadareResults)>2 and (allJsonRadareResults[-1]==allJsonRadareResults[-2])):
            return resultFromRadare
    else:
        print("ERRORJSON: Some problems occured in callJsonFromRadare.Command is {}".format(command))
        return ''



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

def split_rdtsc(block: Abl_Basic_Block, from_next):
    r.cmd("e search.from = %s;" % block.start_address)
    r.cmd("e search.to = %s;" % block.end_address)

    # find instruction in given address range. then get result as string.    
    result = callJsonFromRadare("/am rdtsc")
    block.rdtsc_flag = False

    # #print("start address ",block.start_address)
    # #print("end address ", block.end_address)
    # #print("result",result)

    if (from_next):
        BASIC_BLOCKS.append(block)

    if (result != ""):
        result = result.split('\n')[:-1][0].split(' ')
        cur_inst_len = 2

        # Construct the block which contains only the RDTSC
        rdtsc_block = Abl_Basic_Block(result[0])
        rdtsc_block.end_address = hex(int(result[0], 16) + cur_inst_len)
        # rdtsc_block.end_address = result[0]
        rdtsc_block.start_address = result[0]
        rdtsc_block.size = cur_inst_len
        rdtsc_block.calls = []
        rdtsc_block.calls_flag = False
        rdtsc_block.rdtsc_flag = True
        rdtsc_block.jump_false_flag = False ##### changed
        rdtsc_block.jump_true_flag = True
        rdtsc_block.xrefs = block.xrefs

        # RDTSC instruction is the only instruction in this block.
        if int(result[0], 16) == int(block.start_address, 16) and int(result[0], 16) + cur_inst_len == int(
                block.end_address, 16):
            block.fake_xrefs = block.fake_xrefs.union(block.xrefs)  ##### changed
            block.rdtsc_flag = True
            BLOCKS_CONTAINS_RDTSC_TMP.append(block)
            return  # We do not need to do anything, it is already separated.

        # RDTSC is the last instruction. Modify the current block.
        elif int(block.end_address, 16) - cur_inst_len == int(result[0], 16):
            # ? neden block. jumpfalse address
            
            # son blok ise elimizdeki blok gibi davranması gerekecek
            rdtsc_block.jump_false_address = block.jump_false_address
            rdtsc_block.jump_false_flag = block.jump_false_flag

            # son blok ise elimizdeki blok gibi davranması gerekecek
            rdtsc_block.jump_true_address = block.jump_true_address
            rdtsc_block.jump_true_flag = block.jump_true_flag

            # propagating xrefs could destroy the hierarchy, instead propagate it into fake xrefs
            # by doing this, we can work with xrefs in hierarchy

            rdtsc_block.fake_xrefs = rdtsc_block.fake_xrefs.union(block.fake_xrefs)##### changed
            rdtsc_block.fake_xrefs = rdtsc_block.fake_xrefs.union(block.xrefs)##### changed

            block.end_address = rdtsc_block.start_address
            block.jump_true_address = rdtsc_block.start_address
            block.jump_true_flag = True

            block.jump_false_address = None
            block.jump_false_flag = False

            block.size = block.size - cur_inst_len

            BASIC_BLOCKS.append(rdtsc_block)
            BLOCKS_CONTAINS_RDTSC_TMP.append(rdtsc_block)

        # RDTSC instruction is the first instruction
        elif int(result[0], 16) == int(block.start_address,
                                       16):  # RDTSC is the 1st instruction. No need to keep create a rdtsc_block

            rdtsc_block.jump_true_flag = True
            rdtsc_block.jump_true_address = hex(int(block.start_address,16) + cur_inst_len)
            rdtsc_block.fake_xrefs = rdtsc_block.fake_xrefs.union(block.fake_xrefs)  ##### changed
            rdtsc_block.fake_xrefs = rdtsc_block.fake_xrefs.union(block.xrefs)  ##### changed

            block.start_address = hex(int(block.start_address,16) + cur_inst_len)
            block.size = block.size - cur_inst_len
            #reason to reset xref of blocks: it is a block after rdtsc block. Real xrefs belong to
            # rdtsc block now. This block below needs to have fake xrefs instead.
            block.xrefs = set()
            block.fake_xrefs = rdtsc_block.fake_xrefs

            BASIC_BLOCKS.append(rdtsc_block)
            BLOCKS_CONTAINS_RDTSC_TMP.append(rdtsc_block)
            split_rdtsc(block, 1)

        # GENERAL CASE. CALL is at the middle of somewhere.
        else:
            next_block = Abl_Basic_Block(hex(int(result[0],
                                                 16) + cur_inst_len))  # Next block will be after the call_block which is only 1 instruction
            next_block.end_address = block.end_address
            next_block.calls = block.calls
            next_block.jump_true_address = block.jump_true_address
            next_block.jump_false_address = block.jump_false_address
            next_block.size = int(next_block.end_address, 16) - int(next_block.start_address, 16)

            next_block.jump_true_flag = block.jump_true_flag
            next_block.jump_false_flag = block.jump_false_flag


            next_block.fake_xrefs = next_block.fake_xrefs.union(block.fake_xrefs)
            next_block.fake_xrefs = next_block.fake_xrefs.union(block.xrefs)

            if (block.jump_true_address != None):
                block.jump_true_flag = True
            
            block.jump_false_flag = False
            block.jump_false_address = None


            block.end_address = rdtsc_block.start_address
            block.jump_true_address = rdtsc_block.start_address
            block.size = int(rdtsc_block.start_address, 16) - int(block.start_address, 16)
            block.jump_true_flag = True

            # Set next adress of rdtsc block
            rdtsc_block.jump_true_address = next_block.start_address
            #############rdtsc_block.jump_false_address = next_block.start_address

            rdtsc_block.fake_xrefs = rdtsc_block.fake_xrefs.union(block.fake_xrefs)
            rdtsc_block.fake_xrefs = rdtsc_block.fake_xrefs.union(block.xrefs)
            
            
            BASIC_BLOCKS.append(rdtsc_block)
            BLOCKS_CONTAINS_RDTSC_TMP.append(rdtsc_block)

            split_rdtsc(next_block, 1)

        # RUBRIC:
    return

#   This function takes a block and splits it into several blocks if CALL instruction(s) exist.
#   At the termination of this function, it is provided that all CALLs are separate blocks.
#   calls_flag = true if the block is a CALL block. 
#   If calls_flag = true, you can go to the address of that function by calls[0] which returns the address of the function
#   If calls_flag = false, you dont need to do anything, that basic block is a simple basic block in which no CALL instruction exist.
#   BB = [mov , mov , call, add, sub, j] --> RESULT = [mov,mov] --> [call] --> [add,sub,j] 
#   calls maybe empty (we are doing static analysis, we cant resolve address)
def split_call(block: Abl_Basic_Block, from_next):
    r.cmd("e search.from = %s;" % block.start_address)
    r.cmd("e search.to = %s;" % block.end_address)

    # find instruction in given address range. then get result as string.
    result = callJsonFromRadare("/am call")
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
            ##print("There is a CALL but address cannot be resolved")


###############
# function to find distance from given source
infi = 1000000000

# g is graph of dijkstra
# s start node in dijkstra
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

    # for pinting the path
    parent = [-1 for i in range(len(g))]
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
        

        #this variable for just for debugging purpose
        testaddress = g[current].start_address 

        #If the block is call
        if (g[current].calls_flag == True):
            # TODO : only resolved calls should be used. Will be checked later
            
            #if the flag is true, then the function call is an unroselved function (e.g. printf)
            #if it is unresolved function, the cost of the function will be set by using results SYMBOLS dictionary
            dependency_call_flag = False
            v = BASIC_BLOCKS_ADDRS_TO_INDEX.get(g[current].call_jump_address)
            
            
            #if the current blocks start address is in SYMBOLS
            if g[current].call_jump_address in SYMBOLS:
                #print("Welcome")
                #print(SYMBOLS)
                dependency_call_flag = True
                #get the function start address
                vInsideCall = BASIC_BLOCKS_ADDRS_TO_INDEX.get(g[current].call_jump_address)
                #if the call cost is already set, do not set again
                if(g[vInsideCall].function_call_cost == -1):
                    #set function call cost from dependency symbols dictionary  
                    g[vInsideCall].function_call_cost = SYMBOLS[g[vInsideCall].start_address] 
                    #print("Function call cost of address {} is {}.".format(g[vInsideCall].start_address,g[vInsideCall].function_call_cost))
            

            try:
                if (not visited[v]) and (dependency_call_flag == False):
                    insideCallAddresses.append(g[current].start_address)
                    # insert into visited vertex
                    sett.add(v)
                    if (first_Iteration == False):
                        alt = dist[current] + g[current].size
                    else:
                        alt = dist[current] + 1


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
                                #go to the inside of the call and get the cost of the function
                                if (first_Iteration == False):
                                    alt = dist[current] + g[vInsideCall].function_call_cost
                                else:
                                    alt = dist[current] + 1                                

                                if alt < dist[v] or (v == s and dist[v] == 0):
                                    dist[v] = alt
                                    path[v] = current
                        except:
                            print("ERROR: The function call do not have jump true address.".format(g[current].start_address))
                            
                    else:
                        print("ERROR:The function call {} has {} cost.".format(g[vInsideCall].start_address,g[vInsideCall].function_call_cost))
            except:
                swszxc =3
                #print("Error in dijkstra call case, block start address is:{}".format(g[current].start_address))
        else:

            #if call address is in the list do not continue with true and false case
            if (g[current].jump_true_flag == True and g[current].jump_true_address is not None):
                # we get the jump true address of current block.
                # we use index of that block to find the shortest path (indexes are easier to work with)
                v = BASIC_BLOCKS_ADDRS_TO_INDEX.get(g[current].jump_true_address)
                try:
                    if (visited[v] == False):
                        # insert into visited vertex
                        sett.add(v)
                        # total size of the path

                        # distance is the instruction count
                        # dist[current] gives current distance of the vertex.
                        # g[current] gives current basic block object
                        # using .size total distance is calculated.
                        if (first_Iteration == False):
                            alt = dist[current] + g[current].size
                        else:
                            alt = dist[current] + 1                        


                        # if calculated distance is smaller than the record,
                        # record it to the dist array. (basically we are keeping shorted distances in dist)
                        #                   THE OR PART: if the v is the start vertex (a cycle detected), then record it
                        #                   if the distance is 0 (this means this is the first cycle detected)
                        #                   if there is another cycle after first record, It will be recorded
                        #                   because it will satisfy the alt < dist[v] condition.
                        if alt < dist[v] or (v == s and dist[v] == 0):
                            dist[v] = alt
                            path[v] = current
                except:
                    swszxc =3
                    #print("Error in dijkstra jump true case, block start address is:{}".format(g[current].start_address))

            # same actions above. but for jump false flag.
            if g[current].jump_false_flag == True and g[current].jump_false_address is not None:

                v = BASIC_BLOCKS_ADDRS_TO_INDEX.get(g[current].jump_false_address)
                try:
                    if not visited[v]:

                        # insert into visited vertex
                        sett.add(v)
                        if (first_Iteration == False):
                            alt = dist[current] + g[current].size
                        else:
                            alt = dist[current] + 1

                        # condition to check the distance is correct and update
                        # if it is minimum from the previous than compute the distance
                        if alt < dist[v] or (v == s and dist[v] == 0):
                            dist[v] = alt
                            path[v] = current
                except:
                    swszxc =3
                    #print("Error in dijkstra jump false case, block start address is:{}".format(g[current].start_address))

            #if there is no possible jump and if the block is not a call, the function ends in here
            #if fake_xrefs is not none then there is some return adress to search for.
            #Therefore in this "if" the function will mark all possible return addresses.
            #These addresses will be the function calls, therefore we will skip these addresses and directly calculate the next blocks after calls.
            #In this way, there will be no cycles. 
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
                            if (first_Iteration == False):
                                alt = dist[current] + g[current].size
                            else:
                                alt = dist[current] + 1

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

        # if the current vertex is visited
        # remove it from the next-step sett
        if current in sett:
            sett.remove(current)
        # if there is no next step left, break
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

        first_Iteration = False


    # A utility function to print
    # the constructed distance
    # array
    return dist



def is_inst_in_block(block, instruction: str):
    # set radare's search engine configuration to our current scope
    r.cmd("e search.from = %s;" % block.start_address)
    r.cmd("e search.to = %s;" % block.end_address)
    
    # find instruction in given address range. then get result as string.
    result = callJsonFromRadare("/am %s" % instruction)

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

    # set search scope back to default. We couldn't implement it. if r2 is going to be used again in general scope,
    # we can define another r2 object in this scope and use it.

def fill_xref_fields():
    # iterate each block (tqdm for progress bar)
    for block in tqdm(BASIC_BLOCKS, desc="Filling xrefs..."):
        # for block in BASIC_BLOCKS:
        block_start_address = block.start_address
        #Since r2 pipe do not return correct json output all the time, we will call afbj 50 times until it return expected output. 
        for i in range(50):
            try:
                #testRadareCmd = r.cmd("s main")
                afb_result = callJsonFromRadare("afbj {}".format(block_start_address))
                #afb_result = r.cmd("afbj {}".format(block_start_address))
                afb_json = json.loads(afb_result)
                function_address_int = afb_json[0]["addr"]
                function_address_hex = hex(function_address_int)
                break
            except:
                unUsedVar = 1
                print("INFO: In fill_xref_fields radare2 returned unexpected output in iteration ",i)
        else:
            print("ERRORJSON: In fill_xref_fields radare2 returned unexpected output 50 timesin JSON1. Program will exit.")
            print(afb_result)
            exit(1)
            
        #Since r2 pipe do not return correct json output all the time, we will call afbj 50 times until it return expected output. 
        for i in range(50):
            try:
                #testRadareCmd = r.cmd("s main")
                axt_result = callJsonFromRadare("axtj {}".format(function_address_hex))
                #axt_result = r.cmd("axtj {}".format(function_address_hex))
                axt_json = json.loads(axt_result)
                # #print("\n BLOCK ADDR: {} -----------------<".format(block_start_address))
                for xref in axt_json:
                    if xref['type'] == 'CALL':
                        xref_address_int = int(xref['from'])
                        block.fake_xrefs.add(xref_address_int)
                break
            except:
                unUsedVar = 1
                print("INFO: In fill_xref_fields radare2 returned unexpected output in iteration ",i)
        else:
            print("ERRORJSON: In fill_xref_fields radare2 returned unexpected output 50 times in JSON2. Program will exit.")
            print(axt_result)
            exit(1)
        
        for i in range(50):
            try:
                #testRadareCmd = r.cmd("s main")
                axt_result = callJsonFromRadare("axtj {}".format(block_start_address))
                #axt_result = r.cmd("axtj {}".format(block_start_address))
                axt_json = json.loads(axt_result)
                block.xrefs = set()
                for xref in axt_json:
                    if xref['type'] == 'CALL':
                        xref_address_int = int(xref['from'])
                        block.xrefs.add(xref_address_int)
                break
            except:
                unUsedVar = 1
                print("INFO: In fill_xref_fields radare2 returned unexpected output in iteration ",i)
        else:
            print("ERRORJSON: In fill_xref_fields radare2 returned unexpected output 50 times in JSON3. Program will exit.")
            print(axt_result)
            exit(1)
        

# For all rdtsc block, find their cross references and mark them their fake rdtsc flag true.
# Do the same thing for given depth
def mark_xref_to_rdtsc(depth: int = 2):
    total = set()
    for d in range(0, depth):
        # temp will store the functions that calls rdtsc.
        # The depth of the rdtsc instruction is also storing for future use.
        temp = set()
        for block in BLOCKS_CONTAINS_RDTSC:
            for xref in block.xrefs.union(block.fake_xrefs):
                xref_hex = hex(xref)
                if(xref_hex=="0x11ae"):
                    swszxc =3
                    #print(block.start_address,block.xrefs,block.fake_xrefs)
                for i in range(0, len(BASIC_BLOCKS)):
                    block_to_mark = BASIC_BLOCKS[i]
                    start_int = (
                        int(block_to_mark.start_address, 16))  # this because some addresses has 0s in the beginning
                    start_hex = hex(start_int)
                    # if the basic block is in the cross ref list of the rdtsc block
                    if (xref_hex == start_hex):
                        BASIC_BLOCKS[i].fake_rdtsc_flag = True
                        if (BASIC_BLOCKS[i].fake_rdtsc_depth == -1):
                            BASIC_BLOCKS[i].fake_rdtsc_depth = d
                        temp.add(BASIC_BLOCKS[i])

                        #print("START HEX MARKED: ", start_hex)
                        # #print("###########################################################55555555555555")
        # After finishing every depth, we are adding the functions contains rdtsc (with its depth) to BLOCKS_CONTAINS_RDTSC.
        for block in temp:
            if block not in total:
                start_int = (int(block.start_address, 16))  # this because some addresses has 0s in the beginning
                start_hex = hex(start_int)
                #print("APPENDED HEX: ", start_hex)

                BLOCKS_CONTAINS_RDTSC.append(block)
                total.add(block)

#fill calls jump address fields of basic blocks
#if a basic block is a function call, then call_jump_address field of the basic block will be set accordingly
def fill_calls_jump_address_fields(basic_blocks):
    for block in basic_blocks:
        if block.calls_flag == True:
            axf_result = callJsonFromRadare("axf {}".format(block.start_address))
            temp = axf_result.split(" ")
            if(len(temp)>=3):
                block.call_jump_address = hexLeadingZeroEreaser(temp[1])
            else:
                swszxc =3
                #print("ERROR, fill_calls_jump_address_field did not set for address {}.".format(block.start_address)) 

def change_calls_with_rdtsc():
    for block in BASIC_BLOCKS:
        call_can_read_time = can_this_addr_read_time(hexLeadingZeroEreaser(block.start_address)) #is this address have time==true from nureddin.
        if(call_can_read_time is not None):
            #block.size = symbols[block.]
            block.size = call_can_read_time 
            #print("\n",)
            #TODO : block. size ekle. #add cost from
            block.calls_flag = False
            block.calls = []
            block.calls_flag = False
            block.rdtsc_flag = True
            block.jump_false_flag = False ##### changed
            block.jump_true_flag = True
            block.xrefs = []
            BLOCKS_CONTAINS_RDTSC.append(block)

def find_instruction_count_from_start_address(start_address,end_address):
    r.cmd("s {}".format(start_address))

    for i in range(50):
        try:
            #get basic block of the seek address as json format
            #testRadareCmd = r.cmd("s main")
            basicBlockOfAddressRaw = callJsonFromRadare("pdbj")
            #basicBlockOfAddressRaw = r.cmd("pdbj")
            pdbj_Results = json.loads(basicBlockOfAddressRaw)
            InstructionCount = 0
            startFound = False 
            #count the number of instruction between start address and end address of the basic block (both included)
            #if the end address is not in the json object, we might thought last object is the end address since the basic block ends there
            for row in pdbj_Results:
                addressOfRowHex = hex(row["offset"])
                start_addressPlusOne = hex(int(start_address,16)+int('0x1',16))
                if(addressOfRowHex == start_address or addressOfRowHex == start_addressPlusOne):
                    startFound = True
                if startFound == True:
                    InstructionCount += 1
                if(addressOfRowHex == end_address):
                    break
            return InstructionCount
            break
        except:
            unUsedVar = 1
            print("INFO: In find_instruction_count_from_start_address radare2 returned unexpected output in iteration ",i)
    else:
        print("ERRORJSON: In find_instruction_count_from_start_address radare2 returned unexpected output 50 times in JSON3. Program will exit.")
        print(basicBlockOfAddressRaw)
        exit(1)


    
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

#parser for the deependency outputs
def DependencyParser(results):
    for lib_symbols in results:
        if(lib_symbols.symbols != []):
            for symbols_meta in lib_symbols.symbols:
                #get address of symbols_meta and convert to hex
                hex_symbol_addr_dep = hex(symbols_meta.addr)
                #get instruction count of deependency's symbol
                instr_count_dep = symbols_meta.instr_count
                if(hex_symbol_addr_dep not in SYMBOLS):
                    #add new item to the SYMBOLS e. The key will be the address of function and the value will be instruction count
                    SYMBOLS[hex_symbol_addr_dep] = instr_count_dep
                    #print(instr_count_dep)
                    if symbols_meta.timing ==True:
                        SYMBOLS_TIMING[symbols_meta.name] = symbols_meta.instr_count
                        SYMBOLS_REFERENCE[hex_symbol_addr_dep] = symbols_meta
                else: #in case we have same function twice with different instruction counts

                    print("DEBUG: same symbol has been found twice.")
                    print("hexCounts for {}: existing-->{} and new-->{} ".format(hex_symbol_addr_dep,SYMBOLS[hex_symbol_addr_dep],instr_count_dep))
                    min_count= min(SYMBOLS[hex_symbol_addr_dep],instr_count_dep)
                    SYMBOLS[hex_symbol_addr_dep] = min_count
                    SYMBOLS_REFERENCE[hex_symbol_addr_dep] = symbols_meta
                    print("Min inst count is: ",min_count) 

def printPath(path,start,end,init):
    #print("in path: ", end)
    # Base Case : If j is source

    if (path[end] == -1 or end == start) and init ==1:
        printBasicBlockContent(BASIC_BLOCKS[end])
        return
    init =1
    printPath(path,start,path[end],init)
    printBasicBlockContent(BASIC_BLOCKS[end])

def printBasicBlockContent(block):
    #The function prints all instructions of the basic block.
    print("start",block.start_address,"end",block.end_address,end=" \n")
    
        #Since r2 pipe do not return correct json output all the time, we will call afbj 50 times until it return expected output. 
    for i in range(50):
        try:
            r.cmd("s {}".format(block.start_address))
            #get basic block of the seek address as json format
            #testRadareCmd = r.cmd("s main")
            basicBlockOfAddressRaw = callJsonFromRadare("pdbj")
            #basicBlockOfAddressRaw = r.cmd("pdbj")
            pdbj_Results = json.loads(basicBlockOfAddressRaw)
            startFound = False 

            for row in pdbj_Results:
                addressOfRowHex = hex(row["offset"])
                start_addressPlusOne = hex(int(block.start_address,16)+int('0x1',16))
                end_addressPlusOne = hex(int(block.end_address,16)+int('0x1',16))
                if(addressOfRowHex == block.start_address or addressOfRowHex == start_addressPlusOne):
                    startFound = True
                #Print the address later from the start address. If it is end address do not print it, unless it is a return address
                if startFound == True and (block.rdtsc_flag == True or block.calls_flag == True  ):
                    print("     addr:",addressOfRowHex,"     esil:",row["esil"],"     refptr:",row["refptr"],"     fcn_addr:",row["fcn_addr"],"     fcn_last:",row["fcn_last"],"     size:",row["size"],"     opcode:",row["opcode"],"     disasm:",row["disasm"],"     bytes:",row["bytes"],"     family:",row["family"],"     type:",row["type"],"     reloc:",row["reloc"],"     type_num:",row["type_num"],"     type2_num:",row["type2_num"])
                    break
                if startFound == True and addressOfRowHex != block.end_address:
                    print("     addr:",addressOfRowHex,"     esil:",row["esil"],"     refptr:",row["refptr"],"     fcn_addr:",row["fcn_addr"],"     fcn_last:",row["fcn_last"],"     size:",row["size"],"     opcode:",row["opcode"],"     disasm:",row["disasm"],"     bytes:",row["bytes"],"     family:",row["family"],"     type:",row["type"],"     reloc:",row["reloc"],"     type_num:",row["type_num"],"     type2_num:",row["type2_num"])
                if(addressOfRowHex == block.end_address and row["type"] == "ret" ):
                    print("     addr:",addressOfRowHex,"     esil:",row["esil"],"     refptr:",row["refptr"],"     fcn_addr:",row["fcn_addr"],"     fcn_last:",row["fcn_last"],"     size:",row["size"],"     opcode:",row["opcode"],"     disasm:",row["disasm"],"     bytes:",row["bytes"],"     family:",row["family"],"     type:",row["type"],"     reloc:",row["reloc"],"     type_num:",row["type_num"],"     type2_num:",row["type2_num"])
                if(addressOfRowHex == block.end_address or addressOfRowHex == end_addressPlusOne):
                    break
            break
        except:
            unUsedVar = 1
            #print("INFO: In printBasicBlockContent radare2 returned unexpected output in iteration ",i)
    else:
        print("ERRORJSON: In printBasicBlockContent radare2 returned unexpected output 50 timesin JSON1. Program will exit.")
        print(pdbj_Results)
        exit(1)
    


def main():
    global BLOCKS_CONTAINS_RDTSC
    global BLOCKS_CONTAINS_RDTSC_TMP
    global r
    
    r = open_file()
    name = FILE.split('/')[-1]
    print("FileName: {} ".format(name))

    if(DEPENDENCY_OPEN):
        dependencyResults = call_this_from_main(FILE,2) 
        #print(dependencyResults)
        DependencyParser(dependencyResults)
    

    # Analyze all
    #print("########### ANALYZING THE FILE #################")
    r.cmd('aaa;')
    abl_result = callJsonFromRadare('ablj')

    while abl_result == '':
        abl_result = callJsonFromRadare.cmd('ablj')

    parse_abl_result(abl_result)

    ##print("########### FILLING XREF FIELDS ###################")
    fill_xref_fields()

    get_time_xrefs(r)

    #print("########### {} BASIC BLOCKS CREATED ###########".format(len(BASIC_BLOCKS)))

    TEMPY2 = BLOCKS_CONTAINS_RDTSC

    #print("########### SPLITTING CALLS ###################")
    for block in BASIC_BLOCKS:
        # #print("Splitting started for basic block number {} for CALLS".format(basic_index))
        split_call(block, 0)

    #print("########### FINDING RDTSC #####################")
    for block in BASIC_BLOCKS:
        is_inst_in_block(block, "rdtsc")

    basic_index = 0
    #print("########### SPLITTING RDTSC ###################")
    for block in BLOCKS_CONTAINS_RDTSC:
        # #print("Splitting started for basic block number {} RDTSC".format(basic_index))
        split_rdtsc(block, 0)

    BLOCKS_CONTAINS_RDTSC = BLOCKS_CONTAINS_RDTSC_TMP
    # #print("Splitting is finished:###############################")

    # For all rdtsc block, find their cross references and mark them their fake rdtsc flag true. Do the same thing for given depth
    ##print("########### MARKING XREFS OF RDTSC ###################")
    #mark_xref_to_rdtsc(XREF_DEPTH)

    if TREAT_ALL_TIME_FUNCTIONS_AS_RDTSC:
        change_calls_with_rdtsc()

    start_addresses_of_rdtsc_blocks = []
    for blocks in BLOCKS_CONTAINS_RDTSC:
        start_addresses_of_rdtsc_blocks.append(hexLeadingZeroEreaser(blocks.start_address))

    for block in BASIC_BLOCKS:
        if block.fake_rdtsc_flag:
            BLOCKS_CONTAINS_RDTSC.append(block)
    
    #convert addresses for a standard format such as 0x00001160 to 0x1160
    convertAllHexBasicBlockFieldsToStandardFormat(BASIC_BLOCKS)
    #fill calls jump address fields of basic blocks
    fill_calls_jump_address_fields(BASIC_BLOCKS)

    fill_size_fields(BASIC_BLOCKS)

    #print("\nInstruction counts:")

    path_lengths = []    

    for blk in start_addresses_of_rdtsc_blocks:
        start = 0
        for i in range(len(BASIC_BLOCKS)):
            # BASIC_BLOCKS_ADDRS_TO_INDEX[BASIC_BLOCKS[i].start_address] = i
            if (BASIC_BLOCKS[i].start_address == blk):
                # #print(i)
                start = i
                break

        path = [-1 for i in range(len(BASIC_BLOCKS))]
        dist = dijkstraDist(BASIC_BLOCKS, start, path)
        #print("PRINTING PATH\n\n\n\n")
        #print(path)
        for i in range(len(dist)):
            if (dist[i] != infi):
                if (BASIC_BLOCKS[i].rdtsc_flag == True or BASIC_BLOCKS[i].fake_rdtsc_flag == True) and dist[i] != 0:
                    # Go to deep inspector function
                    if (dist[i] < INSPECT_THRESHOLD):
                        if (deepInspect(BASIC_BLOCKS[start], BASIC_BLOCKS[i],dist[i],r) == -1):
                            break

                    print("\n[{}] ==> [{}] instruction count: {}".format(
                        BASIC_BLOCKS[start].start_address, BASIC_BLOCKS[i].start_address, dist[i]))
                    if(PRINT_PATH):
                        print("\nShortest path content is printing: ")
                        printPath(path, start, i,0)
                        print("\n")
                    path_lengths.append(dist[i])
    #printBasicBlocks(BASIC_BLOCKS)
    
    try:        
        print(f'File: {name}, len(BASIC_BLOCKS): {len(BASIC_BLOCKS)}, len(BLOCKS_CONTAINS_RDTSC): {len(BLOCKS_CONTAINS_RDTSC)}, len(path_lengths): {len(path_lengths)}, min(path_lengths): {min(path_lengths)}, statistics.mean(path_lengths): {statistics.mean(path_lengths)}, statistics.median(path_lengths): {statistics.median(path_lengths)}')
    except:
        print(f"File: {name}, no path")

if __name__ == "__main__":
    print("Start#######################################Start")
    main()
    print("End########################################End")
