#! env python3
# This is a test script for opcua.pv on ProVerif.
# usage :
#  $ python3 opcua.py [options]

from config import *
from argparse import ArgumentParser
from datetime import datetime, timedelta
from jinja2 import Template, Environment
from os import makedirs, path
import platform
import resource
from subprocess import run, CalledProcessError, TimeoutExpired, Popen, PIPE

CONF_TEMPLATE = "config-jinja.pvl"
TARG_TEMPLATE = "opcua-jinja.pv"
CONF = "tmp_conf"
TARG = "tmp_opcua"
OUTDIR = "output"

def str_of_bool(b):
   if b:
      return "true"
   else:
      return "false"

def generate_conf(conf_file, config, proverif, rnd_ext):
   with open(CONF_TEMPLATE, "r") as ctf:
      tmpl = Template(
         ctf.read(),
         block_start_string    = '(*{',
         block_end_string      = '}*)',
         variable_start_string = '(*<',
         variable_end_string   = '>*)',
         comment_start_string  = '(*#',
         comment_end_string    = '#*)')
   conf_file = CONF + rnd_ext + ".pvl"
   cf = open(conf_file, "w")
   cf.write(tmpl.render(
      config=config,
      proverif=proverif,
      str_of_bool=str_of_bool))
   cf.close
   return conf_file

def generate_targ(pv_file, config, proverif, queries, rnd_ext, auth, fixed, KCI, oracle):
   with open(TARG_TEMPLATE, "r") as ctf:
      tmpl = Template(
         ctf.read(),
         block_start_string    = '(*{',
         block_end_string      = '}*)',
         variable_start_string = '(*<',
         variable_end_string   = '>*)',
         comment_start_string  = '(*#',
         comment_end_string    = '#*)')
   pv_file = TARG + rnd_ext + ".pv"
   cf = open(pv_file, "w")
   cf.write(tmpl.render(
      config=config,
      proverif=proverif,
      queries=queries,
      str_of_bool=str_of_bool,
      authenticated=auth,
      fixed=fixed,
      KCI=KCI,
      oracle=oracle))
   cf.close
   return pv_file

def summary(config):
   test_case = ""
   separator = ""
   for crypto in config["crypto"]:
      test_case += separator + crypto
      if separator == "":
         separator = "|"
   test_case += ", "

   separator = ""
   for mode in config["chmode"]:
      test_case += separator + mode
      if separator == "":
         separator = "|"
   test_case += ", "

   if not config["reopen"]:
      test_case += "no_"
   test_case += "reopen, "
   
   separator = ""
   for mode in config["semode"]:
      test_case += separator + mode
      if separator == "":
         separator = "|"
   test_case += ", "

   separator = ""
   for token in config["utoken"]:
      test_case += separator + token
      if separator == "":
         separator = "|"
   test_case += ", "

   if not config["switch"]:
      test_case += "no_"
   test_case += "switch, "

   separator = ""
   for token in config["leaks"]:
      test_case += separator + token
      if separator == "":
         separator = "|"

   return test_case

# -- Main program ---

# Parse arguments:
parser = ArgumentParser(
   prog = 'opcua.py',
   description = 'launch proverif on opcua.pv with the given configuration'
)
parser.add_argument('-a', '--authenticated', action='store_true')
parser.add_argument('-c', '--config')
parser.add_argument('-d', '--development',   help='use customized proverif',           action='store_true')
parser.add_argument(      '--html',          help='put results in directory "output"', action='store_true')
parser.add_argument('-l', '--limit')
parser.add_argument('-m', '--model',         help='location and name of the main proverif file')
parser.add_argument('-n', '--not_fixed',     action='store_true')
parser.add_argument(   '--no_reconstruction',action='store_true')
parser.add_argument('-o', '--oracle',        action='store_true')
parser.add_argument('-q', '--query')
parser.add_argument('-r', '--random')
parser.add_argument('-s', '--sanity_checks', action='store_true')
parser.add_argument('-t', '--timeout')
parser.add_argument('-u', '--unconditioned', action='store_true')
parser.add_argument('-v', '--verbose',       action='store_true')

args = parser.parse_args()
if args.authenticated:
   authenticated = True
if args.config != None:
   configuration = args.config
if args.development:
   proverif["dev"] = True
GiB = 1024*1024*1024 # Bytes
if args.limit != None:
   DATA_LIMIT = int(args.limit) * GiB
else:
   DATA_LIMIT = 100 * GiB
if args.model:
   TARG_TEMPLATE = args.model
if args.no_reconstruction:
   proverif["reconstructTrace"] = False
if args.not_fixed:
   fixed = False
if args.oracle:
   oracle = True
if args.query != None:
   queries["list"] = args.query.replace(' ', '').split(',')
   queries["Sanity"]          = False
if args.random != None:
   rnd_ext = args.random
else:
   rnd_ext = ''
if args.sanity_checks:
   queries["Sanity"]          = True
if args.timeout != None:
      TIMEOUT = int(args.timeout)
else:
      TIMEOUT = 7 * 24 * 3600 # 7 days
if args.unconditioned:
   queries["Unconditioned"]   = True
else:
   queries["Unconditioned"]   = False
if args.verbose:
   proverif["verboseClauses"] = "short"
   proverif["verboseRules"]   = True

# Parse configuration:
if configuration != None and configuration != "":
   cfg_lst = configuration.replace(' ', '').split(',')
   config["crypto"] = cfg_lst[0].split('|')
   config["chmode"] = cfg_lst[1].split('|')
   config["reopen"] = cfg_lst[2] == 'reopen'
   config["semode"] = cfg_lst[3].split('|')
   config["utoken"] = cfg_lst[4].split('|')
   config["switch"] = cfg_lst[5] == 'switch'
   config["leaks"]  = cfg_lst[6].split('|')

# Generate input files:
conf_file = generate_conf(CONF, config, proverif, rnd_ext)
targ_file = generate_targ(TARG, config, proverif, queries, rnd_ext, authenticated, fixed, KCI, oracle)

# Choose prover:
exe = ["proverif-dev"] if proverif["dev"] else ["proverif"]

if args.html or proverif["html"]:
   OUTDIR += rnd_ext
   if not path.isdir(OUTDIR):
      makedirs(OUTDIR)
   exe += ['-html'] + [OUTDIR]

exe += ['-lib', conf_file, targ_file]

# Run prover:
try:
   t = datetime.now()
   p = Popen(exe, start_new_session=False, stdin=PIPE, encoding='utf-8')
   if args.limit != None and platform.system() == "Linux":
      resource.prlimit(p.pid, resource.RLIMIT_AS, (DATA_LIMIT*8//10, DATA_LIMIT))
   if args.timeout != None:
      outs, errs = p.communicate(timeout = TIMEOUT)
   else:
      outs, errs = p.communicate()
except TimeoutExpired:
    print("\nOut of time!\n")
    p.kill()
    outs, errs = p.communicate()
except CalledProcessError as e:
    print("Failed with ProVerif error.")
    p.kill()
    outs, errs = p.communicate()

d = datetime.now() - t
D = datetime.min + d

# Conclude:
if queries["list"] != []:
   if len(queries["list"]) > 1:
      print("Queries: " + ", ".join(queries["list"]))
   else:
      print("Query: " +  queries["list"][0])
print("Configuration: " + summary(config))

print("Running time: ", end='')
if d >= timedelta(hours=1):
   print(D.strftime("%Hh %Mm"))
else:
   print(D.strftime("%Mm %Ss"))
if rnd_ext != '':
   _ = run(['rm', conf_file, targ_file], capture_output=False, encoding='utf-8')
