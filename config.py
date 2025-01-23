# This is the configuration file for opcua.py.
# usage :
# - put default configuration here.
# - $ python3 opcua.py

config = {}
config["crypto"] = ["RSA", "ECC"]
config["chmode"] = ["None", "Sign", "Encrypt"]
config["semode"] = ["SNone", "SNoAA", "SSec"]
config["utoken"] = ["anon", "pwd", "cert"]
config["reopen"] = False
config["switch"] = False
config["leaks"]  = ["no_leaks", "ch_leaks", "lt_leaks"]

authenticated = False # Authenticated cryptography in ECC.
KCI = True # Key Compromise Impersonation of user authenticated by certificate.
           # True, since the fix we designed for the KCI attack is not yet accepted/standardized.
oracle = False # ECC signature oracle. False by default since the fix we designed is accepted.
fixed = True # Fixed ECC client impersonation attack. True since by default since the fix we designed is accepted.

queries = {}
proverif = {}

# -------- PUT YOUR CONFIGURATION HERE : --------------------------------------- #

configuration = "ECC, None, no_reopen, SSec, pwd, no_switch, no_leaks"

# Custom queries:
queries["Sanity"]          = True
queries["Unconditioned"]   = True

# To target specific queries
queries["list"] = []

# ProVerif config:
proverif["dev"]              = False #if true use a customized proverif.
proverif["html"]             = False
proverif["movenew"]          = False
proverif["reconstructTrace"] = True
proverif["verboseClauses"]   = "none" #"none" or "short" or "explained".
proverif["verboseRules"]     = False


# ----------------------------------------------------------------------------- #
