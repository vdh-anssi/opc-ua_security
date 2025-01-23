# configuration

from datetime import datetime, timedelta, time
from enum import Enum, StrEnum
from itertools import chain, combinations

# debug:
DEBUG = False
def debug(s):
   if DEBUG:
      print(s)

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
# a set of configurations forms a half lattice, since it always has an upper bound,
# but not always a lower bound because the mathematical lower bound is not always a valid configuration.

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
      self.min = True # if Result.FALSE, this node may be a minimal configuration
      self.max = True # if Result.TRUE,  this node may be a maximal configuration
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

   # Mark only one configuration with the result of a run, but not as MIN or MAX.
   # Note carefully that it is possible that the configuration is no more PENDING
   # because of race conditions with other threads, that have already propagated
   # their results.
   def mark(self, conf, result, duration):
      found = False

      def rec_mark(n, l):
         # search exactly the given list.
         global found
         debug("rec_mark(n, " + str(l) +")")
         if l==[]:
            if n.result == Result.UNKNOWN or n.result == Result.PENDING:
               n.result = result
               n.time = duration
               if n.children == []:
                  debug("found a final configuration node! (" + str(n.element) + ")")
                  found = True
                  return
               else:
                  debug("found an intermediary configuration node! (" + str(n.element) +")")
                  found = True
                  return
            elif n.result == Result.TRUE and result == Result.FALSE:
               print("'Mark' found "+str_of_elem_list(conf)+": TRUE but it is FALSE!")
               raise
            elif n.result == Result.FALSE and result == Result.TRUE:
               print("'Mark' found "+str_of_elem_list(conf)+": FALSE but it is TRUE!")
               raise
            elif n.result != result:
               print("'Mark' found "+str_of_elem_list(conf)+": "+str(n.result) +" but it is "+str(result)+"!")
               n.result = result
               n.time = duration
               found = True
         else:
            for c in n.children:
               if c.valid and c.element == l[0]:
                  rec_mark(c, l[1:])
                  break
            if not found:
               print("'Mark' couldn't find the configuration: "+ str_of_elem_list(conf))
            return
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


   # unmark max flag for all configurations strictly inferior to the given one (supposed TRUE)
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

      if self.max.reopen:
         if not Option.Reopen in lst:
            result = elem_list_insert(lst, Option.Reopen)
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
            else:
               return False
         return True

      debug("mutate down : " + str(lst))

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
      if n.result == Result.TRUE and n.max == True:
         print(str(configuration.from_list(tr + [n.element])) + ": " + str(n.result)[7:] + " " + format_time(n.time))
      for c in n.children:
         rec_max_trace(c, tr + [n.element])
      return
   for c in t.root.children:
      rec_max_trace(c, [])
