# This script calls opuca.py to make proofs on security properties over the model of the OPC UA protocol with ProVerif.
# usage :
#  $ python3 reproduce_proofs.py -q <property> -c <configuration>


from argparse import ArgumentParser
from datetime import datetime, timedelta
from os import remove
from re import search, split
from subprocess import run, PIPE, STDOUT
import sys

DEBUG = False
LIMIT  = 100 # GiB, default of opcua.py
OUTPUT = "log"
QUERY  = ""
SHORT  = False # Do not repeat configuration for each query
TIMEOUT = 0 # No timeout by default

# Parse arguments:
parser = ArgumentParser(
   prog = 'reproduce_proofs.py',
   description = "This script calls opuca.py to make proofs on security properties over the model of the OPC UA protocol with ProVerif."
)
parser.add_argument('-c', '--config')
parser.add_argument('-l', '--limit')
parser.add_argument('-q', '--query')
parser.add_argument('-r', '--reverse', action='store_true')
parser.add_argument('-t', '--timeout')
args = parser.parse_args()

# Limit
if args.limit:
   LIMIT = int(args.limit)
# Timeout
if args.timeout:
   TIMEOUT = int(args.timeout)
   
# Queries
if args.query == "Agr-[S->C]":
   query_list = ["3.1", "3.1.A", "3.1.B", "3.1.C", "3.1.D", "3.1.E", "3.1.axioms", "3.1.axioms.1", "3.1.conf"]
   SHORT = True
elif args.query == "Agr-[C->S]":
   query_list = ["3.2", "3.2.A", "3.2.axioms", "3.1.A", "3.1.C"]
   if "ECC" in args.config:
      query_list += ["3.1.axioms"]
   SHORT = True
elif args.query in ["Conf[C]", "Conf[S]", "Conf[Pwd]"]:
   query_list = [args.query]
else:
   print("Unknown property.")
   exit(1)
if args.reverse:
   query_list.reverse()
# Configuration
if SHORT:
   print("Config: " + args.config)

def select(query):
   global QUERY
   QUERY = query
   if SHORT:
      print(query, end=': ')
   else:
      print("\nQuery: " + query)

def test(config):
   global QUERY
   global REVISION
   if not (args.config and SHORT):
      print(config, end=': ')
   t = datetime.now()
   random_ext = t.strftime("_%Y-%m-%d-%Hh%Mm%Ss%f")
   outfile = open(OUTPUT + random_ext + ".txt", "w")
   outfile.write("TEST CASE:\nQuery: " + QUERY + "\nConfiguration: " + config + "\n\n")
   outfile.flush()
   try:
      t = datetime.now()
      exe = ["python3", "opcua.py", '-q', QUERY, '-c', config, '-l', str(LIMIT), '-r', random_ext]
      exe += ["--no_reconstruction"]
      if TIMEOUT > 0:
         exe += ['-t', str(TIMEOUT)]
      if DEBUG:
         print(exe)
      p = run(exe, check=True, stdout=PIPE, stderr=STDOUT, encoding='utf-8')
      d = datetime.now() - t

   except Exception as error:
      runtime = 'ERROR'
      print(runtime)
      outfile.flush()
      outfile.close()
      return

   # parse result
   n = p.stdout.find("Verification summary:\n")
   if n < 1:
      if "Error:" in p.stdout:
         print("ERROR", end='')
         outfile.write(p.stdout)
         outfile.close()
      elif "Out of time!" in p.stdout:
         print("OOT >", end = '')
         outfile.close()
         remove(outfile.name)
      else:
         print("OOM > " + str(LIMIT), end = ' GiB')
         outfile.write(p.stdout[-10000:])
         outfile.write("\nOut of memory!\n")
         outfile.close()
   else:
      m = p.stdout.find("\n\n--------------------------------------------------------------", n)
      results = split(" - Query",  p.stdout[n+35:m])
      separator = ''
      for result in results:
         r = search("is true.|is false.|cannot be proved.", result)
         if r == None:
            continue
         elif r.group(0) == "is true.":
            print(separator + "true", end='')
         elif r.group(0) == "is false.":
            print(separator + "FALSE", end='')
         elif r.group(0) == "cannot be proved.":
            print(separator + "????", end = '')
         separator = ', '
      outfile.write(p.stdout[n:])
      outfile.close()

   # running time
   D = datetime.min + d
   if d >= timedelta(hours=1):
      runtime = D.strftime(" %Hh %Mm")
   else:
      runtime = D.strftime(" %Mm %Ss")
   print(runtime)

# ------------------------------------------------

for query in query_list:
   select(query)
   test(args.config)
