# This is a proof script for opcua.pv on ProVerif.
# usage :
#  $ python3.11 prove.py -q "1.2.2" -c "RSA|ECC, None|Sign|Encrypt, reopen, SNone|SSec, anon|pwd|cert, switch, leaks" -t 300 -s previous.txt --skip -p 5 | tee results.txt
#  $ cat results.txt

from configurations import *

from argparse import ArgumentParser
from hashlib import sha256
from multiprocessing import Pool
from os import urandom
from re import search, split
from subprocess import run, PIPE, STDOUT
from sys import stdout
from threading import Thread
from time import strptime


HEADER    = "commit-info.txt"
OUTPUT    = "log"
CONF      = "tmp_conf"
TARG      = "tmp_opcua"
QUERY     = ""
ERROR     = ""
PROCESSES = 5


#  --- Parse arguments:

parser = ArgumentParser(
   prog = 'prove.py',
   description = 'launch proverif to prove a query on different configurations'
)
parser.add_argument('-c', '--config',     help='maximal configuration')
parser.add_argument('-f', '--final',      help='final run: we do not avoid configurations above one that has TIMED OUT', action='store_true')
parser.add_argument('-g', '--git',        help='get git commit', action = 'store_true')
parser.add_argument('-l', '--logs'       ,help='record complete proverif output', action = 'store_true')
parser.add_argument('-p', '--processes',  help='parallelize calls to proverif', type=int, const=PROCESSES, nargs='?')
parser.add_argument('-q', '--query')
parser.add_argument(      '--skip',       help='skip recomputing maximal TRUE or maximal FALSE configurations', action='store_true')
parser.add_argument('-s', '--start',      help='last results file to start from')
parser.add_argument('-t', '--timeout',    help='timeout in seconds',  type=int)
args = parser.parse_args()

# Get commit:
if args.git:
   p = run(['git', 'rev-parse', 'HEAD'], capture_output = True)
   REVISION = p.stdout.decode('utf-8')[:-1]
else:
   REVISION = '?'

# query and maximal configuration
QUERY  = args.query
print("Proving quer", end='')
if  QUERY == "3.1.all":
   QUERIES = ["3.1", "3.1.A", "3.1.B", "3.1.C", "3.1.D", "3.1.E",  "3.1.conf", "3.1.axioms", "3.1.axioms.1"]
   print("ies: " + ', '.join(QUERIES), end='')
elif QUERY == "3.2.all":
   QUERIES = ["3.2", "3.2.A", "3.2.axioms", "3.1.A", "3.1.C"]
   print("ies: " + ', '.join(QUERIES), end='')
else:
   QUERIES = [QUERY]
   print("y: " + QUERY, end='')
print(" in version " + REVISION)

CONFIG = configuration.from_str(args.config)
T = Trie.from_conf(CONFIG)
if DEBUG:
   Print_Trie(T)
print("With maximal configuration: " + str(CONFIG))

# timeout
if args.timeout == None:
   TIMEOUT = 5 * 60 # seconds
   user_timeout = input(f"Enter timeout in seconds (by default {str(TIMEOUT)}): ")
   if user_timeout.strip():
      TIMEOUT = int(user_timeout)
else:
   TIMEOUT = args.timeout

# LIMITS
# at most:   4 processes during 2h or more
#           20 processes during 7m or less
#

# processes and memory
# at most:   4 x 100 GiB during 2h or more
# at least: 20 x  20 GiB during 7m or less
GiB = 1 # Gi Bytes
if args.processes != None:
   PROCESSES = min(args.processes, max(20 - 8*TIMEOUT // 3600, 4))
   DATA_LIMIT = 4 * 100 * GiB // PROCESSES
else:
   PROCESSES = 1
   DATA_LIMIT = 15 * GiB


print("Computations with a timeout of " + str(TIMEOUT) + " seconds and a limit of " + str(DATA_LIMIT) + " GiB", end='')
if PROCESSES > 1:
   print(' using ' + str(PROCESSES) + " parallel processes", end='')
print(".")

DATE_OF_START = datetime.now()

def get_time(s):
   if s.find('s') == -1:
      return strptime(s, "%Hh%Mm")
   else:
      return strptime(s, "%Mm%Ss")


# configurations lists read from the start file
MAX_CFG_LIST       = []
MIN_CFG_LIST       = []
MIN_FALSE_CFG_LIST = []
MIN_OOM_CFG_LIST   = []

if args.start != None and args.start != '':
   with open(args.start, "r") as f:

      # We want to start our new computations from the minimal UNPROVED configurations,
      # but we may want to skip OOM configurations.
      line = f.readline();
      while not ("Minimal configurations" in line):
         line = f.readline()
      line = f.readline()
      while line != "\n":
         comma = line.find(':')
         if (args.skip and line.find('MEM_OUT') != -1):
            t = get_time (line[comma+9:-1].replace(' ', ''))
            MIN_OOM_CFG_LIST += [( configuration.from_str(line[:comma]), timedelta(hours=t.tm_hour, minutes=t.tm_min, seconds=t.tm_sec) )]
         else:
            MIN_CFG_LIST += [configuration.from_str(line[:comma])]
         line = f.readline()

      # Then either we skip or we retest the minimal FALSE (or CANNOT BE PROVED) configurations
      while not ("Minimal FALSE configurations" in line):
         line = f.readline()
      line = f.readline()
      while line != "\n":
         comma = line.find(':')
         # we assume that "FALSE" and "CANNOT" (CANNOT BE PROVED) have almost the same length..
         if line[comma: comma+8].find("FALSE") != -1:
            result = Result.FALSE
         else:
            result = Result.CANNOT
         t = get_time (line[comma+8:-1].replace(' ', ''))
         MIN_FALSE_CFG_LIST += [( configuration.from_str(line[:comma]), result, timedelta(hours=t.tm_hour, minutes=t.tm_min, seconds=t.tm_sec) )]
         line = f.readline()

      # Then either we skip or we retest the maximal TRUE configurations
      while not ("Maximal configurations" in line):
         line = f.readline()
      line = f.readline()
      while (line != "\n" and line != ""):
         comma = line.find(': TRUE')
         end_of_line = line[comma+6:-1].replace(' ', '')
         t = get_time(end_of_line)
         MAX_CFG_LIST += [( configuration.from_str(line[:comma]), timedelta(hours=t.tm_hour, minutes=t.tm_min, seconds=t.tm_sec) )]
         line = f.readline()



# call "opcua.py" to generate the files and call proverif, then parse the results.

def SHA256(m):
    ctx = sha256()
    ctx.update(urandom(32))
    ctx.update(m.encode('UTF-8'))
    s = ""
    for b in ctx.digest():
       s += hex(int(b))[2:]
    return s

def run_proverif(query, config, timeout):
   global REVISION
   global ERROR
   config = str(config)
   t = datetime.now()
   random_ext = f"_{query}_" + SHA256(config) # t.strftime("_%Y-%m-%d-%Hh%Mm%Ss%f")
   outfile = open(OUTPUT + random_ext + ".txt", "w")
   outfile.write("TEST CASE:\nQuery: " + query + "\nConfiguration: " + config + "\n")
   outfile.flush()
   result = Result.MEM_OUT # Out of Memory is the worst case, because we may not be able to get an output file, nor clean the temporary files.
   separator = query + ": " + config + ': '
   try:
      prover  = ['python3', 'opcua.py', '-q', query, '-c', config, '-l', str(DATA_LIMIT)]
      prover += ['-t', str(timeout)] if timeout != 0 else []
      prover += ['-r', random_ext, '--no_reconstruction']
      t = datetime.now()
      p = run(prover, check=True, stdout=PIPE, stderr=STDOUT, encoding='utf-8')
      d = datetime.now() - t

   except Exception as e:
      d = datetime.now() - t
      error = "ERROR " + str(e) + ", " + str(type(e))
      print(separator + error)
      outfile.write(error +"\n")
      outfile.flush()
      outfile.close()
      _ = run(['rm', '-f', CONF+random_ext+".pvl", TARG+random_ext+".pv"])
      return Result.ERROR, d

   if "Out of time!" in p.stdout:
      d = datetime.now() - t
      error = "OOT ERROR >" + format_time(d)
      print(separator + error)
      outfile.write(error +"\n")
      outfile.flush()
      outfile.close()
      _ = run(['rm', '-f', CONF+random_ext+".pvl", TARG+random_ext+".pv"])
      return Result.TIMEOUT, d

   n = p.stdout.find("Verification summary:\n")
   if n > 0:
      m = p.stdout.find("\n\n--------------------------------------------------------------", n)
      results = split(" - Query",  p.stdout[n+35:m])
      result = Result.UNKNOWN
      for res in results[1:]:
         r = search("is true.|is false.|cannot be proved.", res)
         if r == None:
            print(separator + "Internal error")
            result = Result.ERROR
            ERROR = "Error while parsing ProVerif’s output"
            break
         elif r.group(0) == "is true.":
            print(separator + "true", end='')
            separator = ', '
            # for the result to be true all queries must be true.
            if result == Result.UNKNOWN: # unchanged if result == Result.TRUE
               result = Result.TRUE
         elif r.group(0) == "is false.":
            print(separator + "FALSE", end='')
            separator = ', '
            result = Result.FALSE
         elif r.group(0) == "cannot be proved.":
            print(separator + "?????", end = '')
            separator = ','
            if result != Result.FALSE:
               result = Result.CANNOT

   if result == Result.MEM_OUT:
      r = search("Error:.*.", p.stdout)
      if r != None:
         print(separator + "ERROR", end='')
         result = Result.ERROR
      else:
         print(separator + "OOM ERROR", end = '')
         result = Result.MEM_OUT

   if result == Result.ERROR or result == Result.UNKNOWN:
      print("\nERROR: opcua.py says: <<\n" + p.stdout[-1000:] + ">> Unable to parse. Aborting.\n")
      raise

   # running time
   print(format_time(d))
   # logs
   if args.logs:
      outfile.write(p.stdout)
   else:
      outfile.write(p.stdout[n:]) # restricted logs
   outfile.close()
   _ = run(['rm', '-f', "tmp_conf"+random_ext+".pvl", "tmp_opcua"+random_ext+".pv"])
   return result, d


def test(config, timeout):
   global QUERIES
   result = Result.TRUE
   duration = timedelta(seconds=0)
   for query in QUERIES:
      result, d = run_proverif(query, config, timeout)
      duration += d
      if result != Result.TRUE:
         break
   return result, duration


def mark_trie(cfg_lst, result, duration):
   if result == Result.TRUE:
      T.mark(cfg_lst, result, duration)
      T.delete_inf(cfg_lst, result)
      T.unmark_inf(cfg_lst)
   elif result == Result.FALSE or result == Result.CANNOT or result == Result.MEM_OUT or\
       (result == Result.TIMEOUT and not args.final):
      T.mark(cfg_lst, result, duration)
      T.delete_sup(cfg_lst, result)
      T.unmark_sup(cfg_lst)
   elif result == Result.TIMEOUT and args.final:
      T.mark(cfg_lst, result, duration)
      T.unmark_sup(cfg_lst)


# Skip the previous results:
if args.skip and args.start != None:

   # Get rid of false (or cannot be proved) configurations
   if MIN_FALSE_CFG_LIST != []:
      print("\n --- Skipping the minimal FALSE configurations from " + args.start + "\n")
   while MIN_FALSE_CFG_LIST != []:
      min_cfg, result, duration = MIN_FALSE_CFG_LIST.pop(0)
      debug(str(min_cfg) + " " + str(result) + " " + str(duration))
      cfg_lst = elem_list_from(min_cfg)
      if T.find(cfg_lst):
         mark_trie(cfg_lst, result, duration)

   # Get rid of maximal TRUE configurations
   if MAX_CFG_LIST != []:
      print("\n --- Skipping the maximal TRUE configurations from " + args.start + "\n")
   while MAX_CFG_LIST != []:
    max_cfg, duration = MAX_CFG_LIST.pop(0)
    debug(str(max_cfg) + " " + str(duration))
    cfg_lst = elem_list_from(max_cfg)
    if T.find(cfg_lst):
       mark_trie(cfg_lst, Result.TRUE, duration)

   # Get rid of Out of Memory configurations
   if MIN_OOM_CFG_LIST != []:
      print("\n --- Skipping the minimal Out of Memory configurations from " + args.start + "\n")
   while MIN_OOM_CFG_LIST != []:
      oom_cfg, duration = MIN_OOM_CFG_LIST.pop(0)
      debug(str(oom_cfg) + " " + str(duration))
      cfg_lst = elem_list_from(oom_cfg)
      if T.find(cfg_lst):
         mark_trie(cfg_lst, Result.MEM_OUT, duration)

# Start from a known high configuration, without timeout:
if not args.skip and not args.final:
   entry = input("Enter a configuration to start from, without timeout, or simply press ENTER: ")
   if entry != "":
      input_cfg = configuration.from_str(entry)
      cfg_lst = elem_list_from(input_cfg)
      if T.find(cfg_lst):
         # Starting from a supposed maximal true configuration we hope to prune down the Trie.
         debug(str(input_cfg) + " no timeout!")
         if T.reserve(cfg_lst):
            result, duration = test(configuration.from_list(cfg_lst), 0)
            mark_trie(cfg_lst, result, duration)
            if result == Result.FALSE   or result == Result.CANNOT or\
               result == Result.TIMEOUT or result == Result.MEM_OUT:
               print("Warning: this input configuration is not true! ")
      else:
         print("Sorry, the input configuration is not included in the maximal configuration!\n")

# --- Prover's loop: ---

def test_loop_A():
   result = Result.UNKNOWN
   finished = False
   cfg_lst = []
   while not finished:
      # start with false (or cannot be proved) configurations
      if cfg_lst == [] and MIN_FALSE_CFG_LIST != []:
        min_cfg, result, duration = MIN_FALSE_CFG_LIST.pop(0)
        debug(str(min_cfg) + " " + str(result) + " " + str(duration))
        cfg_lst = elem_list_from(min_cfg)
        if T.reserve(cfg_lst):
           result, duration = test(min_cfg, max(2*duration.seconds, TIMEOUT))
           mark_trie(cfg_lst, result, duration)
           if result == Result.TRUE:
              print("Warning: this supposed minimal false configuration above is now TRUE! ")

      # Then starting from known proved maximal configurations we prune down the Trie.
      elif cfg_lst == [] and MAX_CFG_LIST != []:
        max_cfg, duration = MAX_CFG_LIST.pop(0)
        debug(str(max_cfg) + " " + str(duration))
        cfg_lst = elem_list_from(max_cfg)
        if T.reserve(cfg_lst):
           result, duration = test(configuration.from_list(cfg_lst), max(2*duration.seconds, TIMEOUT))
           mark_trie(cfg_lst, result, duration)
           if result == Result.FALSE   or result == Result.CANNOT or\
              result == Result.TIMEOUT or result == Result.MEM_OUT:
              print("Warning: this supposed maximal true configuration above is not true anymore! ")
      # Nothing left to be done.
      else:
         finished = True
      cfg_lst = []


def test_loop_B():
   result = Result.UNKNOWN
   finished = False
   cfg_lst = []
   while not finished:
      # Starting from known minimal unproved configurations, we prune up the Trie
      # and hope to prune it down if we manage to prove the property in a new configuration.
      if cfg_lst == [] and MIN_CFG_LIST != []:
        min_cfg = MIN_CFG_LIST.pop(0)
        debug(str(min_cfg));
        cfg_lst = elem_list_from(min_cfg)
        if T.reserve(cfg_lst):
           result, duration = test(min_cfg, TIMEOUT)
           mark_trie(cfg_lst, result, duration)
           while result == Result.TRUE:
              cfg_lst = T.mutate_up(cfg_lst)
              if (cfg_lst == None or cfg_lst == []):
                 break
              if T.reserve(cfg_lst):
                 result, duration = test(configuration.from_list(cfg_lst), TIMEOUT)
                 mark_trie(cfg_lst, result, duration)
              else:
                 break

      # In the end, we directly pick a configuration from the trie.
      elif cfg_lst == [] and not T.is_void():
         cfg_lst = T.first()
         debug("First configuration of the Trie: " + str(cfg_lst))
         if cfg_lst == []:
            finished = True
            break
         if T.reserve(cfg_lst):
            result, duration = test(configuration.from_list(cfg_lst), TIMEOUT)
            mark_trie(cfg_lst, result, duration)

      # Nothing left to be done.
      else:
         finished = True

      # Should we try to mutate up or down?
      cfg_lst = []


# --- Threading ----

#Print_Trie(T)
tasks = []
if args.processes != None:
   print("-- loop A: false and known proved configurations.")
   for i in range(PROCESSES):
      t = Thread(target = test_loop_A)
      t.start()
      tasks += [t]
   while tasks != []:
      t = tasks.pop()
      t.join()
   print("-- loop B: unproved configurations.")
   for i in range(PROCESSES):
      t = Thread(target = test_loop_B)
      t.start()
      tasks += [t]
   while tasks != []:
      t = tasks.pop()
      t.join()
else:
   test_loop_A()
   test_loop_B()

# --- results: ---

now = datetime.now()
day = now.strftime("%Y/%m/%d")

# Smallest configurations with OOM or OOT
run_info = " for " + QUERY
if args.git:
   run_info += " in version " + REVISION[:7]
run_info += ", as of " + day
print("\nMinimal configurations:")
Print_Min_Trie(T)
print("\nMinimal FALSE configurations" + run_info + ":")
Print_False_Trie(T)
# Greatest configuration with TRUE
print("\nMaximal configurations (<", end='')
print(format_time(timedelta(hours=(TIMEOUT//3600), seconds=TIMEOUT%3600)) +")" + run_info + ":")
Print_Max_Trie(T)

print("\nTotal time: " + format_time(now - DATE_OF_START) + run_info, end='')
if args.processes != None:
   print(' using ' + str(PROCESSES) + " parallel processes", end='')
print(".\n")

exit(0)
