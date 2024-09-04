# This is a proof script for opcua.pv on ProVerif.
# usage :
#  $ python3 prove.py -q "1.2.2" -c "RSA|ECC, None|Sign|Encrypt, reopen, SNone|SSec, anon|pwd|cert, switch, leaks" -t 300 -s previous.txt --skip -p 5 | tee results.txt
#  $ cat results.txt

from argparse import ArgumentParser
from datetime import datetime, timedelta, time
from enum import Enum, StrEnum
from hashlib import sha256
from itertools import chain, combinations
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


# debug:
DEBUG = False
def debug(s):
   if DEBUG:
      print(s)

# configuration

class Crypto(StrEnum):
   RSA = 'RSA'
   ECC = 'ECC'

class Mode(StrEnum):
   CNone   = 'None'
   Sign    = 'Sign'
   Encrypt = 'Encrypt'

class Smode(StrEnum):
   SNone = 'SNone'
   SNoAA = 'SNoAA'
   AAuth = 'SSec'

class Utoken(StrEnum):
   Anonymous   = 'anon'
   Password    = 'pwd'
   Certificate = 'cert'

class Leak(StrEnum):
   No_leaks    = 'no_leaks'
   Channel     = 'ch_leaks'
   Long_term   = 'lt_leaks'

class Option(StrEnum):
   Reopen = 'reopen'
   Switch = 'switch'


order = {Crypto.RSA:          0,
         Crypto.ECC:          1,
         Mode.CNone:          2,
         Mode.Sign:           3,
         Mode.Encrypt:        4,
         Option.Reopen:       5,
         Smode.SNoAA:         6,
         Smode.AAuth:         7,
         Utoken.Anonymous:    8,
         Utoken.Password:     9,
         Utoken.Certificate: 10,
         Option.Switch:      11,
         Leak.Channel:       12,
         Leak.Long_term:     13}

def str_of_set(s):
   line = ""
   separator = ''
   for element in sorted(s):
      line += separator + element
      if separator == '':
         separator = '|'
   return line

class configuration:

   def __init__(self, crypto, chmode, reopen, semode, utoken, switch, leaks):
      self.crypto = crypto
      self.chmode = chmode
      self.reopen = reopen
      self.semode = semode
      self.utoken = utoken
      self.switch = switch
      self.leaks  = leaks
   
   @classmethod
   def from_str(cls, line):
      cfg_lst = line.replace(' ', '').split(',')
      smode_lst = cfg_lst[3].split('|')
      leak_lst  = cfg_lst[6].split('|')
      return cls(
         frozenset([ Crypto(e) for e in cfg_lst[0].split('|') ]),
         frozenset([ Mode(e)   for e in cfg_lst[1].split('|') ]),
         cfg_lst[2] == Option.Reopen,
         frozenset([ Smode(e)  for e in smode_lst if e != Smode.SNone]),
         frozenset([ Utoken(e) for e in cfg_lst[4].split('|') ]),
         cfg_lst[5] == Option.Switch,
         frozenset([ Leak(e)   for e in leak_lst if e != Leak.No_leaks]),
         )

   @classmethod
   def from_list(cls, lst):
      crypto_list = []; mode_list   = []; reopen = False
      smode_list  = []; utoken_list = []; switch = False
      leak_list   = []
      for e in lst:
         match e:
            case Crypto.RSA | Crypto.ECC:
               crypto_list += [e]
            case Mode.CNone | Mode.Sign | Mode.Encrypt:
               mode_list += [e]
            case Option.Reopen:
               reopen = True
            case Smode.SNoAA | Smode.AAuth:
               smode_list += [e]
            case Utoken.Anonymous | Utoken.Password | Utoken.Certificate:
               utoken_list += [e]
            case Option.Switch:
               switch = True
            case Leak.Channel | Leak.Long_term:
               leak_list += [e]
      if crypto_list == [] or\
         mode_list   == [] or\
         smode_list  == [] or\
         utoken_list == []:
         raise ConfigurationError
      return cls(
         frozenset(crypto_list),
         frozenset(mode_list),
         reopen,
         frozenset(smode_list),
         frozenset(utoken_list),
         switch,
         frozenset(leak_list))


   def __str__(self):
      line = ""
      line += str_of_set(self.crypto) + ", "
      line += str_of_set(self.chmode) + ", "
      if not self.reopen:
         line += "no_"
      line += "reopen, "
      line += str_of_set(self.semode) + ", "
      line += str_of_set(self.utoken) + ", "
      if not self.switch:
         line += "no_"
      line += "switch, "
      end_of_line = str_of_set(self.leaks)
      if end_of_line == "":
         line += "no_leaks"
      else:
         line += end_of_line
      return line
      
   def __or__(self, other):
      # sup(a, b) = a | b
      # sup(a, b) = b <=> a <= b
      return configuration(
         self.crypto | other.crypto,
         self.chmode | other.chmode,
         self.reopen | other.reopen,
         self.semode | other.semode,
         self.utoken | other.utoken,
         self.switch | other.switch,
         self.leaks  | other.leaks)

   def compare(self, other):
      # a.compare(b) > 0 means a >= b
      # a.compare(b) < 0 means a <= b
      # a compare(b) = 0 means a doesn't compare to b
      if self.crypto.issubset(other.crypto):
         if self.chmode.issubset(other.chmode) and \
            (not self.reopen or  other.reopen) and \
            self.semode.issubset(other.semode) and \
            self.utoken.issubset(other.utoken) and \
            (not self.switch or  other.switch) and \
            self.leaks.issubset(other.leaks):
            return -1
         else:  
            return 0
      elif self.crypto.issuperset(other.crypto):
         if self.chmode.issuperset(other.chmode) and \
            (not other.reopen or    self.reopen) and \
            self.semode.issuperset(other.semode) and \
            self.utoken.issuperset(other.utoken) and \
            (not other.switch or    self.switch) and \
            self.leaks.issuperset(other.leaks):
            return +1
         else:
            return 0
      else:
         return 0
       

# Convert a configuration to an ordered list of Elements
# note we could make a class of element list...
def elem_list_from(c):
   l  = [Crypto.RSA]         if Crypto.RSA         in c.crypto else []
   l += [Crypto.ECC]         if Crypto.ECC         in c.crypto else []
   l += [Mode.CNone]         if Mode.CNone         in c.chmode else []
   l += [Mode.Sign]          if Mode.Sign          in c.chmode else []
   l += [Mode.Encrypt]       if Mode.Encrypt       in c.chmode else []
   l += [Option.Reopen]      if                       c.reopen else []
   l += [Smode.SNoAA]        if Smode.SNoAA        in c.semode else []
   l += [Smode.AAuth]        if Smode.AAuth        in c.semode else []
   l += [Utoken.Anonymous]   if Utoken.Anonymous   in c.utoken else []
   l += [Utoken.Password]    if Utoken.Password    in c.utoken else []
   l += [Utoken.Certificate] if Utoken.Certificate in c.utoken else []
   l += [Option.Switch]      if                       c.switch else []
   l += [Leak.Channel]       if Leak.Channel       in c.leaks  else []
   l += [Leak.Long_term]     if Leak.Long_term     in c.leaks  else []
   return l

def elem_list_insert(l, e):
   i = 0
   while i < len(l):
      if l[i] == e:
         return l
      elif order[l[i]] > order[e]:
         return l[:i] + [e] + l[i:]
      i += 1
   return l + [e]

def elem_list(s):
   l = []
   for e in s.replace(' ', '').split(','):
      l += [Crypto.RSA]         if e == Crypto.RSA         else []
      l += [Crypto.ECC]         if e == Crypto.ECC         else []
      l += [Mode.CNone]         if e == Mode.CNone         else []
      l += [Mode.Sign]          if e == Mode.Sign          else []
      l += [Mode.Encrypt]       if e == Mode.Encrypt       else []
      l += [Option.Reopen]      if e == Option.Reopen      else []
      l += [Smode.SNoAA]        if e == Smode.SNoAA        else []
      l += [Smode.AAuth]        if e == Smode.AAuth        else []
      l += [Utoken.Anonymous]   if e == Utoken.Anonymous   else []
      l += [Utoken.Password]    if e == Utoken.Password    else []
      l += [Utoken.Certificate] if e == Utoken.Certificate else []
      l += [Option.Switch]      if e == Option.Switch      else []
      l += [Leak.channel]       if e == Leak.Channel       else []
      l += [Leak.long_term]     if e == Leak.Long_term     else []
   return l

def str_of_elem_list(l):
   line = ""
   separator = ''
   for element in l:
      line += separator + str(element)
      if separator == '':
         separator = ', '
   return line


# half-lattice of configurations
# a set of configurations forms a half lattice, since it always has an upper bound but not always a lower bound,
# because the mathematical lower bound is not always a valid configuration.

class status(Enum):
   ready = 0  # need to do something
   done  = 1  # the prover has run with this configuration without error
   error = 2  # the prover has run with this configuration but an error occurred (Out of memory or time)
   void  = 3  # a smaller configuration produced an error or a result "False".

# Prover's result
class Result(Enum):
   FALSE   = 0
   TRUE    = 1
   CANNOT  = 2  # Cannot be proved
   MEM_OUT = 3  # Out of Memory
   TIMEOUT = 4  # Out of Time
   ERROR   = 5  # Proverif error
   UNKNOWN = 6  # remained to be tested
   PENDING = 7  # is currently tested

# Trie structure

class TrieNode:
   def __init__(self, element):
      # the binary element from the Element enumeration
      self.element = element
      # this a valid node
      self.valid = True
      # this node is not the end of a configuration
      self.result = None
      # if this node is a configuration, is it a min or a max?
      self.min = False
      self.max = False
      self.time = None
      # the lists of parent nodes and child nodes
      self.parent   = None
      self.children = []

   def is_end(self):
      return (self.result != None)

   def is_pending(self):
      return (self.result == Result.PENDING)

   def is_valid_conf(self):
      return (self.result == Result.UNKNOWN)

   def is_orphan(self):
      r = not (self.result == Result.UNKNOWN or self.result == Result.PENDING)
      for c in self.children:
         if c.valid:
            r = False
      return r

class Trie(object):

   def __init__(self, sup):
      self.root = TrieNode(None)
      self.max  = sup

   def is_void(self):
      for c in self.root.children:
         if c.valid:
            return False
      return True

   # insert a configuration
   def insert(self, conf):
      def find_or_add(n, l):
         if l == []:
            n.result = Result.UNKNOWN
         else:
            for child in n.children:
               if child.element == l[0]:
                  child.valid = True
                  find_or_add(child, l[1:])
                  break
            else:
               child = TrieNode(l[0])
               child.parent = n
               n.children  += [child]
               find_or_add(child, l[1:])
      find_or_add(self.root, elem_list_from(conf))


   @classmethod
   def from_conf(cls, sup):
      t = Trie(sup)
      def power_set_list(s):
         return list(chain.from_iterable(combinations(s,r) for r in reversed(range(1,len(s)+1))))
      def boolean_list(b):
         if b:
            return [False, True]
         else:
            return [False]
      for crypto in power_set_list(sup.crypto):
         for chmode in power_set_list(sup.chmode):
            for reopen in boolean_list(sup.reopen):
               for semode in power_set_list(sup.semode):
                  for utoken in power_set_list(sup.utoken):
                     for switch in boolean_list(sup.switch):
                        for leaks in (power_set_list(sup.leaks) + [set()]):
                           c = configuration(set(crypto), set(chmode), reopen, set(semode), set(utoken), switch, set(leaks))
                           t.insert(c)
      return t

   # First valid configuration in the Trie. When we parallelize we want to avoid
   # having 4 threads with < c >, no_switch, no_leaks; < c >, switch, no_leaks, etc.
   # so we better stop searching down the Trie when we encounter a pending configuration.
   def first(self):

      def rec_parallel_first(n, l):
         if n.is_valid_conf():
            return l
         else:
            for c in n.children:
               if c.valid and not c.is_pending():
                  r = rec_first(c, l + [c.element])
                  if r != []:
                     return r
            return []

      def rec_first(n, l):
         if n.is_valid_conf():
            return l
         else:
            for c in n.children:
               if c.valid:
                  r = rec_first(c, l + [c.element])
                  if r != []:
                     return r
            return []

      r = rec_parallel_first(self.root, [])
      if r != []:
         return r
      else:
         return rec_first(self.root, [])

   # check if a configuration is valid in the Trie
   def find(self, conf):
      def rec_find(n, l):
         if l==[]:
            if n.is_valid_conf():
               return True
            else:
               return False
         for c in n.children:
            if c.valid and c.element == l[0]:
               return rec_find(c, l[1:])
         else:
            return False
      return rec_find(self.root, conf)

   # Reserve a valid configuration in the Trie to test it
   def reserve(self, conf):
      def rec_find(n, l):
         if l==[]:
            if n.is_valid_conf():
               n.result = Result.PENDING
               return True
            else:
               return False
         for c in n.children:
            if c.valid and c.element == l[0]:
               return rec_find(c, l[1:])
         else:
            return False
      return rec_find(self.root, conf)

   # Delete only one configuration and mark it as MIN or MAX
   def delete(self, conf, result, T):
      print("Delete configuration: "+ str_of_elem_list(conf))

      def rec_del(n, l):
         # search for exactly the given list.
         # return True if the subtree must be cut, False otherwise.
         debug("rec_del(n, " + str(l) +")")
         if l==[]:
            if n.is_valid_conf():
               n.result = result
               n.time = T
               n.min = False
               n.max = False
               if result == Result.TRUE:
                  n.max = True
               elif result == Result.FALSE   or result == Result.CANNOT or\
                    result == Result.MEM_OUT or result == Result.TIMEOUT:
                  n.min = True
               if n.children == []:
                  debug("found a final configuration node! (" + str(n.element) + ")")
                  return True
               else:
                  debug("found an intermediary configuration node! (" + str(n.element) +")")
                  return False
            else:
               print("'Delete' couldn't find the configuration: "+ str_of_elem_list(conf))
               return False
         else:
            for c in n.children:
               if c.valid and c.element == l[0]:
                  if rec_del(c, l[1:]):
                     debug("Delete a node (" + str(c.element) + ")")
                     n.valid = False
                  break
         return n.is_orphan()

      _ = rec_del(self.root, conf)

   # Mark only one configuration as MIN or MAX.
   # Note carefully that it is possible that the configuration is no more PENDING
   # because of race conditions with other threads, that have already propagated
   # their results.
   def mark(self, conf, result, T):
      def rec_mark(n, l):
         # search exactly the given list.
         debug("rec_mark(n, " + str(l) +")")
         if l==[]:
            if n.result == Result.UNKNOWN or n.result == Result.PENDING:
               n.result = result
               n.time = T
               n.min = False
               n.max = False
               if result == Result.TRUE:
                  n.max = True
               elif result == Result.FALSE   or result == Result.CANNOT or\
                    result == Result.MEM_OUT or result == Result.TIMEOUT:
                  n.min = True
               if n.children == []:
                  debug("found a final configuration node! (" + str(n.element) + ")")
                  return
               else:
                  debug("found an intermediary configuration node! (" + str(n.element) +")")
                  return
            else:
               print("'Mark' couldn't find the configuration: "+ str_of_elem_list(conf))
               return
         else:
            for c in n.children:
               if c.valid and c.element == l[0]:
                  rec_mark(c, l[1:])
                  break
      _ = rec_mark(self.root, conf)


   # delete all valid configurations inferior or equal to the given one so that one can't select them
   # for a new computation run.
   def delete_inf(self, conf, result):
      debug("Delete all configurations inferior or equal to: "+ str_of_elem_list(conf))

      def del_inf(n, l):
         # search for a a subtree that fits in the given list.
         # return true if the subtree must be cut, false otherwise.
         debug("del_inf(n, " + str(l))
         if n.result == Result.UNKNOWN or n.result == Result.PENDING:
            n.result = result
            if n.children == []:
               debug("Found a final configuration node! (" + str(n.element) + ")")
               return True
            else:
               debug("Found an intermediary configuration node! (" + str(n.element) +")")
         for c in n.children:
            if not c.valid:
               continue
            for p in range(len(l)):
               if c.element == l[p]:
                  if del_inf(c, l[p+1:]):
                     debug("Delete a node (" + str(c.element) + ")")
                     c.valid = False
                  break
         return n.is_orphan()

      _ = del_inf(self.root, conf)


   # unmark max flag for all configurations strictly inferior to the given one.
   def unmark_inf(self, conf):
      def rec_unmark_inf(n, l, equal):
         # search for a a subtree that fits in the given list.
         debug("rec_unmark_inf(n, " + str(l))
         if n.result != None:
            if not (equal and l == []):
               n.max = False
               if n.children == []:
                  debug("Unmark a final configuration node! (" + str(n.element) + ")")
                  return
               else:
                  debug("Unmark an intermediary configuration node! (" + str(n.element) +")")
         for c in n.children:
            for p in range(len(l)):
               if c.element == l[p]:
                  rec_unmark_inf(c, l[p+1:], equal and p == 0)
                  break
      _ = rec_unmark_inf(self.root, conf, True)


    # delete all valid configurations superior or equal to the given one and propagate the result.
   def delete_sup(self, conf, result):
      debug("Delete all configurations superior or equal to: "+ str_of_elem_list(conf))

      def del_sup(n, l):
         # search for a a subtree that includes the given list.
         # return True if the subtree must be cut, False otherwise.
         debug("del_sup(n, " + str(l) +")")
         if l==[] and (n.result == Result.UNKNOWN or n.result == Result.PENDING):
            n.result = result
            if n.children == []:
               debug("Found a final configuration node! (" + str(n.element) + ")")
               return True
            else:
               debug("Found an intermediary configuration node! (" + str(n.element) +")")
         for c in n.children:
            if not c.valid:
               continue
            if l == [] or c.element == l[0]:
               if del_sup(c, l[1:]):
                  debug("Delete a node (" + str(c.element) + ")")
                  c.valid = False
            elif order[c.element] < order[l[0]]:
               if del_sup(c, l):
                  debug("Delete a node (" + str(c.element) + ")")
                  c.valid = False
         return n.is_orphan()

      _ = del_sup(self.root, conf)

   # Unmark min flag for all configurations strictly superior to the given one.
   def unmark_sup(self, conf):
      def rec_unmark_sup(n, l, equal):
         # search for a a subtree that includes the given list.
         debug("rec_unmark_sup(n, " + str(l) +")")
         if l==[] and n.result != None:
            if not equal:
               n.min = False
            if n.children == []:
               debug("Unmark a final configuration node! (" + str(n.element) + ")")
               return
            else:
               debug("Unmark an intermediary configuration node! (" + str(n.element) +")")
         for c in n.children:
            if equal and l != [] and c.element == l[0]:
               rec_unmark_sup(c, l[1:], True)
            elif l == [] or c.element == l[0]:
               rec_unmark_sup(c, l[1:], False)
            elif order[c.element] < order[l[0]]:
               rec_unmark_sup(c, l, False)
      _ = rec_unmark_sup(self.root, conf, True)

   # find a "nearest" configuration in the trie.
   def mutate_up(self, lst):

      debug("Mutate Up : " + str(lst))

      if not Mode.Encrypt in lst:
         result = elem_list_insert(lst, Mode.Encrypt)
         if self.find(result):
            return result
      if not Mode.Sign in lst:
         result = elem_list_insert(lst, Mode.Sign)
         if self.find(result):
            return result
      if not Mode.CNone in lst:
         result = elem_list_insert(lst, Mode.CNone)
         if self.find(result):
            return result
      if Crypto.RSA in lst:
         if not Crypto.ECC in lst:
            result = [Crypto.ECC] + lst[1:]
            if self.find(result):
               return result
      else:
         if Crypto.ECC in lst:
            result = [Crypto.RSA] + lst
            if self.find(result):
               return result

      if self.max.reopen:
         if not Option.Reopen in lst:
            result = elem_list_insert(lst, Option.Reopen)
            if self.find(result):
               return result

      if not Utoken.Certificate in lst:
         result = elem_list_insert(lst, Utoken.Certificate)
         if self.find(result):
            return result
      if not Utoken.Password in lst:
         result = elem_list_insert(lst, Utoken.Password)
         if self.find(result):
            return result
      if not Utoken.Certificate in lst:
         result = elem_list_insert(lst, Utoken.Anonymous)
         if self.find(result):
            return result
      if not Smode.AAuth in lst:
         result = elem_list_insert(lst, Smode.AAuth)
         if self.find(result):
            return result
      if not Smode.SNoAA in lst:
         result = elem_list_insert(lst, Smode.SNoAA)
         if self.find(result):
            return result

      if self.max.switch:
         if not Option.Switch in lst:
            result = elem_list_insert(lst, Option.Switch)
            if self.find(result):
               return result

      if not Leak.Long_term in lst:
         # this will almost certainly result in a need to downgrade the configuration.
         # shouldn't we try it before arriving with such a complete configuration ?
         result = elem_list_insert(lst, Leak.Long_term)
         if self.find(result):
            return result

      return None

   def mutate_down(self, lst):
     # Downgrade is brutal since it will very often be called after the setting of a strong option.
     # the goal it to try to find a small configuration from which to restart the growing up.

      def is_sublist(l, lst):
         i = 0
         for e in l:
            while i < len(lst):
                if lst[i] == e:
                   break
                else:
                   i += 1
            #if i==len(lst):
            else:
               return False
         return True

      debug("mutate down : " + str(lst))

      if self.max.reopen:
         if is_sublist([Crypto.RSA, Crypto.ECC], lst):
            lst = [Crypto.RSA] + lst[2:]
            if self.find(lst):
               return lst
         if is_sublist([Mode.CNone, Mode.Encrypt], lst) or \
            is_sublist([Mode.CNone, Mode.Sign   ], lst):
            lst.remove(Mode.CNone)
            if self.find(lst):
               return lst
         if is_sublist([Mode.Sign, Mode.Encrypt], lst):
            lst.remove(Mode.Sign)
            if self.find(lst):
               return lst
         if Option.Reopen in lst:
            lst.remove(Option.Reopen)
            if self.find(lst):
               return lst

      if self.max.switch:
         if is_sublist([Smode.SNoAA, Smode.AAuth], lst):
            lst.remove(Smode.AAuth)
            if self.find(lst):
               return lst
         if is_sublist([Utoken.Anonymous, Utoken.Password],    lst) or \
            is_sublist([Utoken.Password,  Utoken.Certificate], lst):
            lst.remove(Utoken.Password)
            if self.find(lst):
               return lst
         if is_sublist([Utoken.Anonymous, Utoken.Certificate], lst):
            lst.remove(Utoken.Certificate)
            if self.find(lst):
               return lst
         if Option.Switch in lst:
            lst.remove(Option.Switch)
            if self.find(lst):
               return lst

      return None

def format_time(d):
   D = datetime.min + d
   if d >= timedelta(days=1):
      if d < timedelta(days=2):
         return str(d.days) + " day" + D.strftime(" %Hh")
      else:
         return str(d.days) + " days" + D.strftime(" %Hh")
   elif d >= timedelta(hours=1):
      return D.strftime(" %Hh %Mm")
   else:
      return D.strftime(" %Mm %Ss")

def Print_Trie(t):
   def trace(n, tr):
      if n.is_valid_conf():
         print(tr + ", " + str(n.element))
      for c in n.children:
         if c.valid:
            trace(c, tr + ", " + str(n.element))
   for c in t.root.children:
      if c.valid:
         trace(c, ">")

def Print_Full_Trie(t):
   def rec_full_trace(n, tr):
      if n.is_valid_conf():
         print(tr + ", " + str(n.element))
      elif n.is_end():
         print(tr + ", " + str(n.element) + ": " + str(n.result))
      for c in n.children:
         if c.valid:
            rec_full_trace(c, tr + ", " + str(n.element))
         else:
            rec_full_trace(c, tr + ", (" + str(n.element) + ")")
   for c in t.root.children:
      rec_full_trace(c, ">")

def Print_Min_Trie(t):
   def rec_min_trace(n, tr):
      if (n.result == Result.TIMEOUT or n.result == Result.MEM_OUT) and n.min == True:
         print(str(configuration.from_list(tr + [n.element])) + ": " + str(n.result)[7:] + " " + format_time(n.time))
      for c in n.children:
         rec_min_trace(c, tr + [n.element])
      return
   for c in t.root.children:
      rec_min_trace(c, [])

def Print_False_Trie(t):
   def rec_min_trace(n, tr):
      if (n.result == Result.FALSE or n.result == Result.CANNOT) and n.min == True:
         print(str(configuration.from_list(tr + [n.element])) + ": " + str(n.result)[7:] + " " + format_time(n.time))
      for c in n.children:
         rec_min_trace(c, tr + [n.element])
      return
   for c in t.root.children:
      rec_min_trace(c, [])

def Print_Max_Trie(t):
   def rec_max_trace(n, tr):
      if n.result != None and n.max == True:
         print(str(configuration.from_list(tr + [n.element])) + ": " + str(n.result)[7:] + " " + format_time(n.time))
      for c in n.children:
         rec_max_trace(c, tr + [n.element])
      return
   for c in t.root.children:
      rec_max_trace(c, [])


#  --- Parse arguments:

parser = ArgumentParser(
   prog = 'prove.py',
   description = 'launch proverif to prove a query on different configurations'
)
parser.add_argument('-c', '--config',     help='maximal configuration')
parser.add_argument('-g', '--git',        help='get git commit', action = 'store_true')
parser.add_argument('-l', '--logs'       ,help='record complete proverif output', action = 'store_true')
parser.add_argument('-p', '--processes',  help='parallelize calls to proverif', type=int, const=PROCESSES, nargs='?')
parser.add_argument('-q', '--query')
parser.add_argument(      '--skip',       help='skip recomputing maximal TRUE or maximal FALSE configurations', action='store_true')
parser.add_argument('-s', '--start',      help='last results file to start from')
parser.add_argument('-t', '--timeout',    help='timeout in seconds',  type=int)
args = parser.parse_args()

# Machine:
server = True

# Get commit:
if args.git:
   p = run(['git', 'rev-parse', 'HEAD'], capture_output = True)
   REVISION = p.stdout.decode('utf-8')[:-1]
else:
   REVISION = '?'

# query and maximal configuration
QUERY  = args.query
print("Proving query: " + QUERY + " in version " + REVISION)
CONFIG = configuration.from_str(args.config)
T = Trie.from_conf(CONFIG)
if DEBUG:
   Print_Trie(T)
print("With maximal configuration: " + str(CONFIG))

# timeout
if args.timeout == None:
   if server:
      TIMEOUT = 5 * 60 # seconds
   else:
      TIMEOUT = 5      # seconds
   user_timeout = input(f"Enter timeout in seconds (by default {str(TIMEOUT)}): ")
   if user_timeout.strip():
      TIMEOUT = int(user_timeout)
else:
   TIMEOUT = args.timeout

# LIMITS
# at most:   4 processes during 2h or more
#           20 processes during 7m or less
#

# processes
if args.processes != None:
   if server:
      PROCESSES = min(args.processes, max(20 - 8*TIMEOUT // 3600, 4))
   else:
      PROCESSES = args.processes

# memory
# at most:   4 x 100 GiB during 2h or more
# at least: 20 x  20 GiB during 7m or less
GiB = 1 # Gi Bytes
if server:
   DATA_LIMIT = 4 * 100 * GiB // PROCESSES
else:
   DATA_LIMIT = 15 * GiB

print("Computations with a timeout of " + str(TIMEOUT) + " seconds", end='')
if args.processes != None:
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

def test(config, timeout):
   global QUERY
   global REVISION
   global ERROR
   config = str(config)
   t = datetime.now()
   random_ext = f"_{QUERY}_" + SHA256(config) # t.strftime("_%Y-%m-%d-%Hh%Mm%Ss%f")
   outfile = open(OUTPUT + random_ext + ".txt", "w")
   outfile.write("TEST CASE:\nQuery: " + QUERY + "\nConfiguration: " + config + "\n")
   outfile.flush()
   result = Result.MEM_OUT # Out of Memory is the worst case, because we may not be able to get an output file, nor clean the temporary files.
   try:
      prover = ["python3", "opcua.py"] #['--development']
      prover += ['-l', str(DATA_LIMIT), '-q', QUERY, '-c', config, '-r', random_ext]
      if timeout != 0:
         prover += ['-t', str(timeout)]
      t = datetime.now()
      p = run(prover, check=True, stdout=PIPE, stderr=STDOUT, encoding='utf-8')
      d = datetime.now() - t

   except Exception as e:
      d = datetime.now() - t
      runtime = "ERROR " + str(e) + ", " + str(type(e))
      print(config, end=': ')
      print(runtime)
      outfile.write(runtime +"\n")
      outfile.flush()
      outfile.close()
      _ = run(['rm', '-f', CONF+random_ext+".pvl", TARG+random_ext+".pv"])
      return Result.ERROR, d

   if "Out of time!" in p.stdout:
      d = datetime.now() - t
      runtime = "OOT ERROR >" + format_time(d)
      print(config, end=': ')
      print(runtime)
      outfile.write(runtime +"\n")
      outfile.flush()
      outfile.close()
      _ = run(['rm', '-f', CONF+random_ext+".pvl", TARG+random_ext+".pv"])
      return Result.TIMEOUT, d

   n = p.stdout.find("Verification summary:\n")
   m = p.stdout.find("\n\n--------------------------------------------------------------", n)
   results = split(" - Query",  p.stdout[n+35:m])
   separator = config + ': '
   if results != []:
         for res in results[1:]:
            result = Result.UNKNOWN
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
               if result != Result.FALSE and result != Result.CANNOT:
                  result = Result.TRUE
            elif r.group(0) == "is false.":
               print(separator + "FALSE", end='')
               separator = ','
               result = Result.FALSE
            elif r.group(0) == "cannot be proved.":
               print(separator + "?????", end = '')
               separator = ','
               if result != Result.FALSE:
                  result = Result.CANNOT

   if result == Result.MEM_OUT:
      n = 0
      r = search("Error:.*.", p.stdout)
      if r != None:
         print(separator + "ERROR", end='')
         result = Result.ERROR
         ERROR = r.group(0)
      else:
         print(separator + "OOM ERROR", end = '')
         result = Result.MEM_OUT

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


def mark_trie(cfg_lst, result, duration):
   if result == Result.TRUE:
      T.mark(cfg_lst, result, duration)
      T.delete_inf(cfg_lst, result)
      T.unmark_inf(cfg_lst)
   elif result == Result.FALSE   or result == Result.CANNOT or\
        result == Result.TIMEOUT or result == Result.MEM_OUT:
      T.mark(cfg_lst, result, duration)
      T.delete_sup(cfg_lst, result)
      T.unmark_sup(cfg_lst)
   if result == Result.ERROR:
      print("Proverif says: << " + ERROR + " >> Aborting.")
      raise


# Skip the previous results:
if args.skip and args.start != None:

   # Get rid of false (or cannot be proved) configurations
   if MIN_FALSE_CFG_LIST != []:
      print("\n --- Skipping the minimal FALSE configurations from " + args.start + "\n")
   while MIN_FALSE_CFG_LIST != []:
      min_cfg, result, duration = MIN_FALSE_CFG_LIST.pop(0)
      debug(str(min_cfg) + " " + str(result) + " " + str(duration));
      cfg_lst = elem_list_from(min_cfg)
      if T.find(cfg_lst):
         mark_trie(cfg_lst, result, duration)

   # Get rid of Out of Memory configurations
   if MIN_OOM_CFG_LIST != []:
      print("\n --- Skipping the minimal Out of Memory configurations from " + args.start + "\n")
   while MIN_OOM_CFG_LIST != []:
      oom_cfg, duration = MIN_OOM_CFG_LIST.pop(0)
      debug(str(oom_cfg) + " " + str(duration));
      cfg_lst = elem_list_from(oom_cfg)
      if T.find(cfg_lst):
         mark_trie(cfg_lst, Result.MEM_OUT, duration)

   # Get rid of maximal TRUE configurations
   if MAX_CFG_LIST != []:
      print("\n --- Skipping the maximal TRUE configurations from " + args.start + "\n")
   while MAX_CFG_LIST != []:
    max_cfg, duration = MAX_CFG_LIST.pop(0)
    debug(str(max_cfg) + " " + str(duration));
    cfg_lst = elem_list_from(max_cfg)
    if T.find(cfg_lst):
       mark_trie(cfg_lst, Result.TRUE, duration)

# Start from a known high configuration, without timeout:
if not args.skip:
   entry = input("\nEnter a configuration to start from, without timeout, or simply press ENTER: ")
   if entry != "":
      input_cfg = configuration.from_str(entry)
      cfg_lst = elem_list_from(input_cfg)
      if T.find(cfg_lst):
         # Starting from a supposed maximal true configuration we hope to prune down the Trie.
         debug(str(input_cfg) + " no timeout!");
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
        debug(str(min_cfg) + " " + str(result) + " " + str(duration));
        cfg_lst = elem_list_from(min_cfg)
        if T.reserve(cfg_lst):
           result, duration = test(min_cfg, max(2*duration.seconds, TIMEOUT))
           mark_trie(cfg_lst, result, duration)
           if result == Result.TRUE:
              print("This supposed minimal false configuration above is now TRUE! ")

      # Then starting from known proved maximal configurations we prune down the Trie.
      elif cfg_lst == [] and MAX_CFG_LIST != []:
        max_cfg, duration = MAX_CFG_LIST.pop(0)
        debug(str(max_cfg) + " " + str(duration));
        cfg_lst = elem_list_from(max_cfg)
        if T.reserve(cfg_lst):
           result, duration = test(configuration.from_list(cfg_lst), max(2*duration.seconds, TIMEOUT))
           mark_trie(cfg_lst, result, duration)
           if result == Result.FALSE   or result == Result.CANNOT or\
              result == Result.TIMEOUT or result == Result.MEM_OUT:
              print("This supposed maximal true configuration above is not true anymore! ")
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
   for i in range(PROCESSES):
      t = Thread(target = test_loop_A)
      t.start()
      tasks += [t]
   while tasks != []:
      t = tasks.pop();
      t.join()
   for i in range(PROCESSES):
      t = Thread(target = test_loop_B)
      t.start()
      tasks += [t]
   while tasks != []:
      t = tasks.pop();
      t.join()
else:
   test_loop_A()
   test_loop_B()

# --- results: ---

now = datetime.now()
day = now.strftime(" %d/%m ")

# Smallest configurations with OOM or OOT
run_info = " the" + day + "for " + QUERY
if args.git:
   run_info += " in version " + REVISION[:7]
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
