# Configurations
FILE = ''
XREF_DEPTH = 3
INSPECT_THRESHOLD = 40 

# BLOCKS_CONTAINS_RDTSC will also store the addresses of the function calls that have rdtsc in it somehow.
# I mean may be that function has a rdtsc in 3th depth
BASIC_BLOCKS = []
BLOCKS_CONTAINS_RDTSC = []
BLOCKS_CONTAINS_RDTSC_TMP = []
SYMBOLS = {} # address: instruction_count
SYMBOLS_TIMING = {} # symbol: instruction count
SYMBOLS_REFERENCE = {}
#STANDART_FUNCTIONS = ['localtime','asctime','clock_get_time','timespec_get','clock_gettime','system_clock::now']
# This dictionary will map all basic blocks with their start addresses
DEPENDENCY_OPEN = True #Open depencency by setting true, close it by setting false
PRINT_PATH = True #Print all the instructions on the shortest path
TEMPY = []
TEMPY2 = []

r = ''


TREAT_ALL_TIME_FUNCTIONS_AS_RDTSC = True