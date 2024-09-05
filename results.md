A Formal Security Analysis of OPC-UA.
=====================================

See the file README.md for detailed instruction on how to use proverif.
We present here, for each security properties, some configurations for which we have proofs. Those configurations are maximal with respect to the timeout we used and explicitly indicate.

# Confidentiality Properties
In the paper (Section 5.1), we make the following claims:
> The obtained proofs for Conf[C] and Conf[S] (in less than 2 hours) are with respect to almost maximal configurations. Namely, we achieve the maximal configuration for RSA. For ECC, we can prove the maximal configuration without Switch and the maximal configuration without Leak. Similarly, we need to choose between Switch and Leak to prove Conf[Pwd] in ECC and captures the maximal configuration for RSA.

The configurations we list in the README.md (recalled below) support those claims. They are maximal with respect to a time-out of 2h.

### For the property Conf[C]:
Maximal configurations (including "switch") when the Security Policy is RSA:
 - `$ python3 opcua.py -q "Conf[C]" -c "RSA, None|Sign|Encrypt, reopen, SNoAA|SSec, anon|pwd|cert, switch, lt_leaks"` (30s)
Maximal configurations (including "switch"), but no key leaks when the Security Policy is ECC:
 - `$ python3 opcua.py -q "Conf[C]" -c "ECC, None|Sign|Encrypt, reopen, SNoAA|SSec, anon|pwd|cert, switch, no_leaks"` (10s)
Maximal configurations except when "switch" is disabled:
 - `$ python3 opcua.py -q "Conf[C]" -c "RSA|ECC, None|Sign|Encrypt, reopen, SNoAA|SSec, anon|pwd|cert, no_switch, lt_leaks"` (5m)

## For the property Conf[S]:
Maximal configurations (including "switch") when the Security Policy is RSA:
 - `$ python3 opcua.py -q "Conf[S]" -c "RSA, None|Sign|Encrypt, reopen, SNoAA|SSec, anon|pwd|cert, switch, lt_leaks"` (3m)
Maximal configurations (including "switch"), but no key leaks when the Security Policy is ECC:
 - `$ python3 opcua.py -q "Conf[S]" -c "ECC, Sign|Encrypt, reopen, SNoAA|SSec, anon|pwd|cert, switch, no_leaks"` (10s)
Maximal configurations except when "switch" is disabled:
 - `$ python3 opcua.py -q "Conf[S]" -c "RSA|ECC, None|Sign|Encrypt, reopen, SNoAA|SSec, anon|pwd|cert, no_switch, lt_leaks"` (25m)
In a subset of this configuration an attack was found using `--oracle`. The version 1.05.04 RC with our fix to the signature oracle attack is obtained without `--oracle` and can be proven secure with the command just above.

## For the property Conf[Pwd]:
Configuration with long-term key leaks, but no channel leaks:
 - `$ python3 opcua.py -q "Conf[Pwd]" -c "ECC, Encrypt, no_reopen, SSec, pwd, no_switch, lt_leaks"` (1s)
Password confidentiality when no signature oracle is allowed (i.e., we enforce parsing of certificates even when SessionSecurity includes SNoAA):
 - `$ python3 opcua.py -q "Conf[Pwd]" -c "ECC, None, reopen, SNoAA|SSec, pwd, switch, lt_leaks"`: (3s)
 - `$ python3 opcua.py -q "Conf[Pwd]" -c "RSA|ECC, None|Sign|Encrypt, reopen, SNoAA, pwd, switch, no_leaks"` (24s)

We additionally report on two other results that require more time:
 - `$ python3 opcua.py -q "Conf[Pwd]" -c "ECC|RSA, Encrypt|None, reopen, SNoAA, pwd, no_switch, lt_leaks"` (02h 20m)
 - `$ python3 opcua.py -q "Conf[Pwd]" -c "RSA, Encrypt|None, no_reopen, SNoAA, pwd, switch, lt_leaks"` (00m 57s)


# Agreement Properties
As mentioned in the paper, the agreement properties are much more complex to prove. They rely on more complex injective agreement properties but more importantly, we had to weaken them, which resulted in much more complicated queries with a lot of side-conditions to take into account the residual risks.

However, we make two claims:
 1. We can prove our fixes provably repair the protocol for the configuration in which we found the attacks
 2. We can establish proofs for a variety of configurations whose the union capture all configuration options.
We leave as future work the proof of the maximal configuration for the weakened agreement properties.

The claim 1. is supported by the results mentioned in the README.md file:
Proofs for this property requires to first prove a number of lemmas that we assume (axioms) during the proof of the weakened Agr[S->C].
 - `$ python3 opcua.py -q "3.1.axioms" -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (5s)
 - `$ python3 opcua.py -q "3.1.axioms.1" -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (5s)
 - `$ python3 opcua.py -q "3.1.A" -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (5s)
 - `$ python3 opcua.py -q "3.1.B" -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (1m)
 - `$ python3 opcua.py -q "3.1.C" -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (1s)
 - `$ python3 opcua.py -q "3.1.D" -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (5s)
 - `$ python3 opcua.py -q "3.1.E" -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (1m)
 - `$ python3 opcua.py -q "3.1"   -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (1m)
Similarly, the query "3.2" relies on "3.2.axioms", "3.2.A" and all "3.1.*" queries discussed above.
One should launch:
 - `$ python3 opcua.py -q "3.2.axioms" -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (5s)
 - `$ python3 opcua.py -q "3.2.A"   -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (5s)
 - `$ python3 opcua.py -q "3.2"   -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (2m)

The claim 2. is supported by the results we obtained through lattice exploration campaigns results we report on below and that can be reproduced as explained in the README.md file.

##  Summary of results for the weakened property Agr-[S->C]

To prove the weakened property Agr-[S->C] we need to prove a number of lemmas as well (assumed as axioms in the proof of the weakened property Agr-[S->C]). Examples of configurations where all lemmas and the property are proven are 

- ECC, Encrypt, no_reopen, SNoAA,  anon|cert, no_switch, lt_leaks
- RSA, None|Sign, no_reopen, SSec, anon|cert, no_switch, lt_leaks
- ECC|RSA, None, reopen, SNoAA, cert|pwd, no_switch, lt_leaks
- ECC|RSA, None, reopen, SNoAA, anon, switch, no_leaks: TRUE  00m 00s

In particular this shows the absence of the impersonation attack that was found on configuration "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks".

##  Summary of results for the weakened property Agr-[C->S]

To prove the weakened version of Agr-[C->S] we rely on axioms from Agr-[S->C] and some additional axioms. In particular the same configurations as for Agr-[S->C] can be proved.

- ECC, Encrypt, no_reopen, SNoAA,  anon|cert, no_switch, lt_leaks
- RSA, None|Sign, no_reopen, SSec, anon|cert, no_switch, lt_leaks
- ECC|RSA, None, reopen, SNoAA, cert|pwd, no_switch, lt_leaks
- ECC|RSA, None, reopen, SNoAA, anon, switch, no_leaks


## Raw results for agreement properties
Most of those results were obtained from our lattice exploration tooling.

### 3.1 

 - ECC|RSA, Encrypt|None|Sign, no_reopen, SNoAA, anon, no_switch, no_leaks: TRUE  18m 33s
 - ECC|RSA, Encrypt|None|Sign, no_reopen, SSec, anon, no_switch, no_leaks: TRUE  17m 09s
 - ECC|RSA, None|Sign, no_reopen, SNoAA|SSec, anon, no_switch, no_leaks: TRUE  20m 53s
 - ECC|RSA, None|Sign, no_reopen, SNoAA, anon, no_switch, lt_leaks: TRUE  10m 31s
 - ECC|RSA, None|Sign, no_reopen, SSec, anon, no_switch, lt_leaks: TRUE  09m 02s
 - ECC|RSA, Encrypt|None, no_reopen, SNoAA, anon, no_switch, lt_leaks: TRUE  18m 11s
 - ECC|RSA, Encrypt|None, no_reopen, SSec, anon, no_switch, lt_leaks: TRUE  16m 23s
 - ECC|RSA, Encrypt|None, reopen, SNoAA, anon, switch, no_leaks: TRUE  25m 30s
 - ECC|RSA, None, reopen, SNoAA|SSec, anon|cert, no_switch, lt_leaks: TRUE  01m 25s
 - ECC|RSA, None, reopen, SNoAA, anon|cert|pwd, no_switch, lt_leaks: TRUE  15m 59s
 - ECC|RSA, None, reopen, SNoAA|SSec, cert, switch, lt_leaks: TRUE  01m 46s
 - ECC|RSA, None, reopen, SNoAA, anon|cert|pwd, no_switch, lt_leaks: TRUE  15m 59s
 - ECC|RSA, None, reopen, SNoAA, anon|cert, switch, lt_leaks: TRUE  00m 53s
 - ECC|RSA, None, reopen, SNoAA, pwd, switch, lt_leaks: TRUE  37m 10s
 - ECC|RSA, None, reopen, SSec, anon|cert|pwd, no_switch, lt_leaks: TRUE  19m 13s
 - ECC|RSA, None, reopen, SSec, anon|cert, switch, lt_leaks: TRUE  01m 32s
 - ECC|RSA, None, reopen, SSec, pwd, switch, lt_leaks: TRUE  39m 26s
 - ECC|RSA, Encrypt|Sign, no_reopen, SSec, anon, no_switch, lt_leaks: TRUE  38m 45s
 - ECC|RSA, Sign, no_reopen, SNoAA|SSec, anon, no_switch, lt_leaks: TRUE  42m 19s
 - RSA, Encrypt|None|Sign, no_reopen, SNoAA|SSec, anon, no_switch, lt_leaks: TRUE  12m 22s
 - RSA, Encrypt|None|Sign, no_reopen, SNoAA, anon|cert, no_switch, lt_leaks: TRUE  14m 27s
 - RSA, Encrypt|None|Sign, no_reopen, SSec, anon|cert, no_switch, lt_leaks: TRUE  14m 32s
 - RSA, Encrypt|None|Sign, reopen, SNoAA, anon, switch, no_leaks: TRUE  06m 22s
 - RSA, None|Sign, no_reopen, SNoAA|SSec, anon|cert, no_switch, no_leaks: TRUE  41m 02s
 - RSA, None|Sign, no_reopen, SNoAA|SSec, cert, no_switch, lt_leaks: TRUE  37m 08s
 - RSA, None|Sign, no_reopen, SNoAA, anon|pwd, switch, lt_leaks: TRUE  35m 54s
 - RSA, None|Sign, no_reopen, SNoAA, anon|cert, switch, lt_leaks: TRUE  26m 53s
 - RSA, None|Sign, no_reopen, SSec, anon|cert, switch, lt_leaks: TRUE  19m 27s
 - RSA, None|Sign, no_reopen, SSec, pwd, switch, lt_leaks: TRUE  26m 43s
 - RSA, None|Sign, reopen, SNoAA|SSec, anon, switch, lt_leaks: TRUE  20m 30s
 - RSA, None|Sign, reopen, SNoAA, anon|cert|pwd, no_switch, lt_leaks: TRUE  37m 47s
 - RSA, None|Sign, reopen, SNoAA, pwd, switch, no_leaks: TRUE  39m 39s
 - RSA, None|Sign, reopen, SNoAA, cert, switch, no_leaks: TRUE  24m 27s
 - RSA, None|Sign, reopen, SSec, anon|cert|pwd, no_switch, lt_leaks: TRUE  42m 19s
 - RSA, None|Sign, reopen, SSec, anon|cert, switch, no_leaks: TRUE  31m 46s
 - RSA, None|Sign, reopen, SSec, pwd, switch, no_leaks: TRUE  39m 42s
 - RSA, Encrypt|None, no_reopen, SNoAA, pwd, no_switch, lt_leaks: TRUE  21m 55s
 - RSA, Encrypt|None, no_reopen, SSec, pwd, no_switch, lt_leaks: TRUE  20m 11s
 - RSA, Encrypt|None, reopen, SNoAA, pwd, no_switch, no_leaks: TRUE  23m 35s
 - RSA, None, reopen, SNoAA|SSec, anon|cert|pwd, no_switch, lt_leaks: TRUE  16m 47s
 - RSA, None, reopen, SNoAA|SSec, anon|cert, switch, lt_leaks: TRUE  00m 20s
 - RSA, None, reopen, SNoAA, anon|cert|pwd, switch, lt_leaks: TRUE  09m 18s
 - RSA, None, reopen, SSec, anon|cert|pwd, switch, lt_leaks: TRUE  08m 45s
 - RSA, Encrypt|Sign, no_reopen, SSec, pwd, no_switch, lt_leaks: TRUE  30m 08s
 - RSA, Sign, no_reopen, SNoAA|SSec, anon|cert, no_switch, lt_leaks: TRUE  42m 28s
 - RSA, Sign, no_reopen, SSec, anon|pwd, switch, lt_leaks: TRUE  30m 33s
 - RSA, Sign, reopen, SNoAA, anon|pwd, switch, no_leaks: TRUE  38m 58s
 - RSA, Encrypt, no_reopen, SNoAA, anon|cert|pwd, no_switch, lt_leaks: TRUE  20m 05s
 - RSA, Encrypt, no_reopen, SSec, anon|cert|pwd, no_switch, lt_leaks: TRUE  20m 56s
 - RSA, Encrypt, reopen, SNoAA, anon|pwd, switch, no_leaks: TRUE  13m 11s
 - ECC, Encrypt|None|Sign, no_reopen, SNoAA|SSec, anon, no_switch, no_leaks: TRUE  32m 44s
 - ECC, Encrypt|None|Sign, no_reopen, SNoAA, anon|cert, no_switch, no_leaks: TRUE  25m 44s
 - ECC, Encrypt|None|Sign, no_reopen, SNoAA, anon, no_switch, lt_leaks: TRUE  15m 20s
 - ECC, Encrypt|None|Sign, no_reopen, SSec, anon|cert, no_switch, no_leaks: TRUE  27m 47s
 - ECC, Encrypt|None|Sign, no_reopen, SSec, anon, no_switch, lt_leaks: TRUE  11m 15s
 - ECC, None|Sign, no_reopen, SNoAA|SSec, anon, no_switch, lt_leaks: TRUE  13m 38s
 - ECC, None|Sign, no_reopen, SNoAA, anon|pwd, no_switch, no_leaks: TRUE  37m 14s
 - ECC, None|Sign, no_reopen, SNoAA, anon|cert, no_switch, lt_leaks: TRUE  17m 07s
 - ECC, None|Sign, no_reopen, SNoAA, pwd, no_switch, lt_leaks: TRUE  31m 29s
 - ECC, None|Sign, no_reopen, SSec, anon|cert, no_switch, lt_leaks: TRUE  15m 50s
 - ECC, Encrypt|None, no_reopen, SNoAA|SSec, anon, no_switch, lt_leaks: TRUE  21m 32s
 - ECC, Encrypt|None, no_reopen, SNoAA, anon|pwd, no_switch, lt_leaks: TRUE  41m 19s
 - ECC, Encrypt|None, no_reopen, SNoAA, anon|cert, no_switch, lt_leaks: TRUE  23m 46s
 - ECC, Encrypt|None, no_reopen, SSec, anon|pwd, no_switch, lt_leaks: TRUE  41m 54s
 - ECC, Encrypt|None, no_reopen, SSec, anon|cert, no_switch, lt_leaks: TRUE  23m 31s
 - ECC, Encrypt|None, reopen, SNoAA, anon|pwd, no_switch, no_leaks: TRUE  38m 33s
 - ECC, None, reopen, SNoAA, anon|pwd, switch, lt_leaks: TRUE  36m 25s
 - ECC, Encrypt|Sign, no_reopen, SNoAA, anon|pwd, no_switch, no_leaks: TRUE  42m 00s
 - ECC, Encrypt|Sign, no_reopen, SSec, cert, no_switch, lt_leaks: TRUE  36m 20s
 - ECC, Sign, no_reopen, SNoAA, anon|cert|pwd, no_switch, no_leaks: TRUE  42m 25s
 - ECC, Sign, no_reopen, SNoAA, anon|pwd, no_switch, lt_leaks: TRUE  29m 13s
 - ECC, Encrypt, no_reopen, SNoAA, anon|cert|pwd, no_switch, no_leaks: TRUE  37m 37s
 - ECC, Encrypt, no_reopen, SSec, anon|cert|pwd, no_switch, no_leaks: TRUE  39m 45s
 

### 3.1.axioms

 - ECC|RSA, Encrypt|None|Sign, no_reopen, SNoAA|SSec, anon|cert|pwd, no_switch, no_leaks: TRUE  13m 43s
 - ECC|RSA, Encrypt|None|Sign, no_reopen, SNoAA, anon|cert, no_switch, lt_leaks: TRUE  33m 34s
 - ECC|RSA, Encrypt|None|Sign, no_reopen, SNoAA, pwd, no_switch, lt_leaks: TRUE  44m 04s
 - ECC|RSA, Encrypt|None|Sign, no_reopen, SSec, anon|cert, no_switch, lt_leaks: TRUE  34m 19s
 - ECC|RSA, Encrypt|None|Sign, no_reopen, SSec, pwd, no_switch, lt_leaks: TRUE  01h 18m
 - ECC|RSA, Encrypt|None|Sign, reopen, SNoAA|SSec, anon, no_switch, no_leaks: TRUE  04m 09s
 - ECC|RSA, Encrypt|None|Sign, reopen, SNoAA, anon|cert|pwd, no_switch, no_leaks: TRUE  02m 11s
 - ECC|RSA, Encrypt|None|Sign, reopen, SSec, anon|cert|pwd, no_switch, no_leaks: TRUE  02m 39s
 - ECC|RSA, None|Sign, no_reopen, SNoAA|SSec, anon, no_switch, lt_leaks: TRUE  41m 51s
 - ECC|RSA, None|Sign, no_reopen, SNoAA, anon|cert|pwd, no_switch, lt_leaks: TRUE  07m 24s
 - ECC|RSA, None|Sign, no_reopen, SSec, anon|cert|pwd, no_switch, lt_leaks: TRUE  09m 21s
 - ECC|RSA, None|Sign, reopen, SNoAA, anon, no_switch, lt_leaks: TRUE  15m 45s
 - ECC|RSA, None|Sign, reopen, SSec, anon, no_switch, lt_leaks: TRUE  11m 29s
 - ECC|RSA, Encrypt|None, no_reopen, SNoAA|SSec, anon, no_switch, lt_leaks: TRUE  27m 17s
 - ECC|RSA, Encrypt|None, no_reopen, SNoAA, anon|cert|pwd, no_switch, lt_leaks: TRUE  21m 13s
 - ECC|RSA, Encrypt|None, no_reopen, SSec, anon|cert|pwd, no_switch, lt_leaks: TRUE  24m 34s
 - ECC|RSA, Encrypt|None, reopen, SNoAA|SSec, anon, switch, no_leaks: TRUE  02m 26s
 - ECC|RSA, Encrypt|None, reopen, SNoAA, anon|cert|pwd, switch, no_leaks: TRUE  01m 10s
 - ECC|RSA, Encrypt|None, reopen, SNoAA, anon, no_switch, lt_leaks: TRUE  10m 44s
 - ECC|RSA, Encrypt|None, reopen, SSec, anon|cert|pwd, switch, no_leaks: TRUE  00m 52s
 - ECC|RSA, Encrypt|None, reopen, SSec, anon, no_switch, lt_leaks: TRUE  13m 03s
 - ECC|RSA, None, reopen, SNoAA|SSec, anon, switch, lt_leaks: TRUE  00m 29s
 - ECC|RSA, None, reopen, SNoAA, anon|cert|pwd, switch, lt_leaks: TRUE  00m 15s
 - ECC|RSA, None, reopen, SSec, anon|cert|pwd, switch, lt_leaks: TRUE  00m 22s
 - ECC|RSA, Encrypt|Sign, no_reopen, SNoAA|SSec, anon|cert|pwd, switch, no_leaks: TRUE  07m 07s
 - ECC|RSA, Encrypt|Sign, no_reopen, SNoAA, anon|cert|pwd, no_switch, lt_leaks: TRUE  57m 46s
 - ECC|RSA, Encrypt|Sign, no_reopen, SSec, anon|cert|pwd, no_switch, lt_leaks: TRUE  53m 07s
 - ECC|RSA, Encrypt|Sign, reopen, SNoAA|SSec, anon, switch, no_leaks: TRUE  14m 17s
 - ECC|RSA, Encrypt|Sign, reopen, SNoAA, anon|cert|pwd, switch, no_leaks: TRUE  03m 10s
 - ECC|RSA, Encrypt|Sign, reopen, SNoAA, anon, no_switch, lt_leaks: TRUE  54m 38s
 - ECC|RSA, Encrypt|Sign, reopen, SSec, anon|cert|pwd, switch, no_leaks: TRUE  02m 12s
 - ECC|RSA, Encrypt|Sign, reopen, SSec, anon, no_switch, lt_leaks: TRUE  01h 01m
 - ECC|RSA, Sign, no_reopen, SNoAA|SSec, anon|cert|pwd, switch, lt_leaks: TRUE  59m 08s
 - ECC|RSA, Sign, reopen, SNoAA|SSec, anon, no_switch, lt_leaks: TRUE  47m 58s
 - ECC|RSA, Encrypt, no_reopen, SNoAA|SSec, anon|cert|pwd, no_switch, lt_leaks: TRUE  47m 19s
 - ECC|RSA, Encrypt, reopen, SNoAA|SSec, anon, no_switch, lt_leaks: TRUE  01h 09m
 - RSA, Encrypt|None|Sign, no_reopen, SNoAA|SSec, anon|cert|pwd, switch, lt_leaks: TRUE  01h 03m
 - RSA, Encrypt|None|Sign, reopen, SNoAA|SSec, anon, switch, lt_leaks: TRUE  17m 58s
 - RSA, Encrypt|None|Sign, reopen, SNoAA, anon|cert|pwd, switch, no_leaks: TRUE  00m 40s
 - RSA, Encrypt|None|Sign, reopen, SSec, anon|cert|pwd, switch, no_leaks: TRUE  00m 38s
 - RSA, None|Sign, reopen, SNoAA, anon|cert|pwd, switch, lt_leaks: TRUE  01m 08s
 - RSA, None|Sign, reopen, SSec, anon|cert|pwd, switch, lt_leaks: TRUE  01m 17s
 - RSA, Encrypt|Sign, reopen, SNoAA, anon|cert|pwd, switch, lt_leaks: TRUE  09m 12s
 - RSA, Encrypt|Sign, reopen, SSec, anon|cert|pwd, switch, lt_leaks: TRUE  10m 17s
 - ECC, Encrypt|None|Sign, no_reopen, SNoAA, anon|cert|pwd, no_switch, lt_leaks: TRUE  37m 10s
 - ECC, Encrypt|None|Sign, no_reopen, SSec, anon|cert|pwd, no_switch, lt_leaks: TRUE  41m 21s
 - ECC, Encrypt|None|Sign, reopen, SNoAA, anon, no_switch, lt_leaks: TRUE  58m 51s
 - ECC, Encrypt|None|Sign, reopen, SSec, anon, no_switch, lt_leaks: TRUE  59m 50s
 
### 3.1.axioms.1

 - ECC|RSA, Encrypt|None|Sign, reopen, SNoAA, anon|cert|pwd, no_switch, no_leaks: TRUE  01m 16s
 - ECC|RSA, Encrypt|None|Sign, reopen, SSec, anon|cert|pwd, no_switch, no_leaks: TRUE  02m 15s
 - ECC|RSA, None|Sign, no_reopen, SNoAA, anon, no_switch, lt_leaks: TRUE  04m 52s
 - ECC|RSA, None|Sign, no_reopen, SSec, anon, no_switch, lt_leaks: TRUE  05m 49s
 - ECC|RSA, Encrypt|None, no_reopen, SNoAA, anon|cert, no_switch, lt_leaks: TRUE  42m 40s
 - ECC|RSA, Encrypt|None, no_reopen, SNoAA, pwd, no_switch, lt_leaks: TRUE  28m 29s
 - ECC|RSA, Encrypt|None, no_reopen, SSec, anon, no_switch, lt_leaks: TRUE  01m 44s
 - ECC|RSA, None, reopen, SNoAA|SSec, anon|cert|pwd, switch, lt_leaks: TRUE  00m 50s
 - ECC|RSA, Encrypt|Sign, no_reopen, SNoAA, anon, no_switch, lt_leaks: TRUE  18m 07s
 - ECC|RSA, Encrypt|Sign, no_reopen, SSec, anon, no_switch, lt_leaks: TRUE  18m 27s
 - ECC|RSA, Sign, no_reopen, SNoAA, anon|cert, no_switch, lt_leaks: TRUE  04m 16s
 - ECC|RSA, Sign, no_reopen, SSec, anon|cert, no_switch, lt_leaks: TRUE  03m 41s
 - ECC|RSA, Encrypt, no_reopen, SNoAA, anon|cert|pwd, no_switch, lt_leaks: TRUE  22m 58s
 - RSA, Encrypt|None|Sign, no_reopen, SNoAA, anon, no_switch, lt_leaks: TRUE  04m 39s
 - RSA, Encrypt|None|Sign, no_reopen, SSec, anon, no_switch, lt_leaks: TRUE  06m 33s
 - RSA, None|Sign, no_reopen, SNoAA, anon|pwd, no_switch, lt_leaks: TRUE  42m 34s
 - RSA, None|Sign, no_reopen, SNoAA, anon|cert, no_switch, lt_leaks: TRUE  01h 05m
 - RSA, None|Sign, no_reopen, SSec, pwd, no_switch, lt_leaks: TRUE  33m 54s
 - RSA, None|Sign, no_reopen, SSec, cert, no_switch, lt_leaks: TRUE  41m 30s
 - RSA, Encrypt|None, no_reopen, SNoAA, anon|pwd, no_switch, lt_leaks: TRUE  14m 21s
 - RSA, Encrypt|None, no_reopen, SNoAA, cert|pwd, no_switch, lt_leaks: TRUE  37m 30s
 - RSA, Encrypt|None, no_reopen, SSec, anon|pwd, no_switch, lt_leaks: TRUE  26m 55s
 - RSA, Encrypt|None, no_reopen, SSec, anon|cert, no_switch, lt_leaks: TRUE  20m 43s
 - RSA, Encrypt|Sign, no_reopen, SNoAA, anon|pwd, no_switch, lt_leaks: TRUE  36m 30s
 - RSA, Encrypt|Sign, no_reopen, SNoAA, anon|cert, no_switch, lt_leaks: TRUE  20m 58s
 - RSA, Encrypt|Sign, no_reopen, SSec, anon|pwd, no_switch, lt_leaks: TRUE  01h 21m
 - RSA, Encrypt|Sign, no_reopen, SSec, anon|cert, no_switch, lt_leaks: TRUE  20m 56s
 - RSA, Sign, no_reopen, SNoAA, anon|cert|pwd, no_switch, lt_leaks: TRUE  14m 17s
 - RSA, Sign, no_reopen, SSec, anon|cert|pwd, no_switch, lt_leaks: TRUE  16m 33s
 - RSA, Encrypt, no_reopen, SSec, anon|cert|pwd, no_switch, lt_leaks: TRUE  16m 28s
 - ECC, Encrypt|None|Sign, no_reopen, SNoAA, anon|cert, no_switch, lt_leaks: TRUE  17m 41s
 - ECC, Encrypt|None|Sign, no_reopen, SSec, anon, no_switch, lt_leaks: TRUE  03m 22s
 - ECC, None|Sign, no_reopen, SNoAA, anon|pwd, no_switch, lt_leaks: TRUE  22m 08s
 - ECC, None|Sign, no_reopen, SSec, anon|cert, no_switch, lt_leaks: TRUE  15m 24s
 - ECC, Encrypt|None, no_reopen, SNoAA, anon|cert|pwd, no_switch, lt_leaks: TRUE  00m 39s
 - ECC, Encrypt|None, no_reopen, SSec, anon|cert|pwd, no_switch, lt_leaks: TRUE  00m 45s
 - ECC, Encrypt|Sign, no_reopen, SNoAA, anon|cert|pwd, no_switch, lt_leaks: TRUE  04m 40s
 - ECC, Encrypt|Sign, no_reopen, SSec, anon|cert|pwd, no_switch, lt_leaks: TRUE  02m 57s
 

### Query: 3.1.A

 - ECC|RSA, None, reopen, SNoAA, cert|pwd, switch, lt_leaks: TRUE  01m 21s
 - ECC, None|Sign|Encrypt, no_reopen, SNoAA, anon|pwd|cert, no_switch, lt_leaks: TRUE  12m 24
 - ECC, None|Sign|Encrypt, no_reopen, SNoAA|SSec, cert, no_switch, lt_leaks: TRUE  08m 33s
 - RSA, None|Sign|Encrypt, reopen, SNone|SSec, anon|pwd|cert, no_switch, lt_leaks: TRUE  39m 47s
 
### 3.1.B

 - ECC|RSA, Encrypt|None|Sign, no_reopen, SNoAA, anon|cert, no_switch, no_leaks: TRUE  33m 55s
 - ECC|RSA, Encrypt|None|Sign, no_reopen, SNoAA, anon, no_switch, lt_leaks: TRUE  30m 29s
 - ECC|RSA, Encrypt|None|Sign, no_reopen, SNoAA, cert, no_switch, lt_leaks: TRUE  15m 34s
 - ECC|RSA, Encrypt|None|Sign, no_reopen, SSec, anon|cert, no_switch, no_leaks: TRUE  24m 32s
 - ECC|RSA, Encrypt|None|Sign, no_reopen, SSec, anon, no_switch, lt_leaks: TRUE  20m 02s
 - ECC|RSA, Encrypt|None|Sign, no_reopen, SSec, pwd, no_switch, no_leaks: TRUE  39m 02s
 - ECC|RSA, Encrypt|None|Sign, no_reopen, SSec, cert, no_switch, lt_leaks: TRUE  19m 25s
 - ECC|RSA, None|Sign, no_reopen, SNoAA|SSec, anon, no_switch, no_leaks: TRUE  26m 07s
 - ECC|RSA, None|Sign, no_reopen, SNoAA|SSec, cert, no_switch, lt_leaks: TRUE  34m 03s
 - ECC|RSA, None|Sign, no_reopen, SNoAA, anon|cert, no_switch, lt_leaks: TRUE  13m 47s
 - ECC|RSA, None|Sign, no_reopen, SNoAA, anon, switch, lt_leaks: TRUE  18m 58s
 - ECC|RSA, None|Sign, no_reopen, SNoAA, pwd, no_switch, lt_leaks: TRUE  34m 46s
 - ECC|RSA, None|Sign, no_reopen, SNoAA, cert, switch, lt_leaks: TRUE  15m 23s
 - ECC|RSA, None|Sign, no_reopen, SSec, anon|cert, no_switch, lt_leaks: TRUE  10m 29s
 - ECC|RSA, None|Sign, no_reopen, SSec, anon|cert, switch, no_leaks: TRUE  34m 42s
 - ECC|RSA, None|Sign, no_reopen, SSec, anon, switch, lt_leaks: TRUE  19m 54s
 - ECC|RSA, None|Sign, no_reopen, SSec, pwd, no_switch, lt_leaks: TRUE  31m 42s
 - ECC|RSA, None|Sign, no_reopen, SSec, cert, switch, lt_leaks: TRUE  19m 24s
 - ECC|RSA, Encrypt|None, no_reopen, SNoAA|SSec, cert, no_switch, no_leaks: TRUE  30m 43s
 - ECC|RSA, Encrypt|None, no_reopen, SNoAA, anon|cert, no_switch, lt_leaks: TRUE  17m 27s
 - ECC|RSA, Encrypt|None, no_reopen, SNoAA, cert|pwd, no_switch, lt_leaks: TRUE  32m 27s
 - ECC|RSA, Encrypt|None, no_reopen, SSec, anon|pwd, no_switch, lt_leaks: TRUE  26m 30s
 - ECC|RSA, Encrypt|None, no_reopen, SSec, anon|cert, no_switch, lt_leaks: TRUE  15m 28s
 - ECC|RSA, Encrypt|None, no_reopen, SSec, cert|pwd, no_switch, lt_leaks: TRUE  26m 23s
 - ECC|RSA, Encrypt|None, reopen, SNoAA, anon|pwd, no_switch, no_leaks: TRUE  42m 07s
 - ECC|RSA, Encrypt|None, reopen, SNoAA, anon, switch, no_leaks: TRUE  28m 33s
 - ECC|RSA, None, reopen, SNoAA|SSec, anon|cert, switch, lt_leaks: TRUE  03m 33s
 - ECC|RSA, None, reopen, SNoAA, anon|cert|pwd, no_switch, lt_leaks: TRUE  08m 05s
 - ECC|RSA, None, reopen, SNoAA, anon|pwd, switch, lt_leaks: TRUE  33m 28s
 - ECC|RSA, None, reopen, SNoAA, cert|pwd, switch, lt_leaks: TRUE  33m 38s
 - ECC|RSA, None, reopen, SSec, anon|cert|pwd, no_switch, lt_leaks: TRUE  08m 05s
 - ECC|RSA, None, reopen, SSec, anon|pwd, switch, lt_leaks: TRUE  35m 40s
 - ECC|RSA, Encrypt|Sign, no_reopen, SNoAA, pwd, no_switch, no_leaks: TRUE  31m 27s
 - ECC|RSA, Encrypt|Sign, no_reopen, SSec, anon|cert, no_switch, lt_leaks: TRUE  40m 38s
 - ECC|RSA, Sign, no_reopen, SNoAA, anon|pwd, no_switch, no_leaks: TRUE  41m 06s
 - ECC|RSA, Sign, no_reopen, SNoAA, cert|pwd, no_switch, lt_leaks: TRUE  38m 25s
 - ECC|RSA, Sign, no_reopen, SSec, anon|pwd, no_switch, lt_leaks: TRUE  40m 16s
 - ECC|RSA, Sign, no_reopen, SSec, cert|pwd, no_switch, lt_leaks: TRUE  34m 10s
 - ECC|RSA, Encrypt, no_reopen, SNoAA, anon|cert|pwd, no_switch, no_leaks: TRUE  29m 48s
 - ECC|RSA, Encrypt, no_reopen, SNoAA, anon|pwd, no_switch, lt_leaks: TRUE  21m 55s
 - ECC|RSA, Encrypt, no_reopen, SSec, anon|cert|pwd, no_switch, lt_leaks: TRUE  20m 29s
 - ECC|RSA, Encrypt, reopen, SNoAA, pwd, switch, no_leaks: TRUE  25m 17s
 - RSA, Encrypt|None|Sign, no_reopen, SNoAA|SSec, anon|pwd, no_switch, lt_leaks: TRUE  26m 46s
 - RSA, Encrypt|None|Sign, no_reopen, SNoAA|SSec, anon|cert, no_switch, lt_leaks: TRUE  07m 04s
 - RSA, Encrypt|None|Sign, no_reopen, SNoAA|SSec, cert|pwd, no_switch, lt_leaks: TRUE  32m 22s
 - RSA, Encrypt|None|Sign, no_reopen, SNoAA, anon|cert|pwd, no_switch, lt_leaks: TRUE  02m 56s
 - RSA, Encrypt|None|Sign, no_reopen, SSec, anon|cert|pwd, no_switch, lt_leaks: TRUE  03m 46s
 - RSA, Encrypt|None|Sign, reopen, SNoAA, anon|pwd, switch, no_leaks: TRUE  11m 01s
 - RSA, None|Sign, no_reopen, SNoAA|SSec, anon|cert, switch, no_leaks: TRUE  24m 57s
 - RSA, None|Sign, reopen, SNoAA|SSec, anon|cert|pwd, no_switch, lt_leaks: TRUE  26m 04s
 - RSA, None|Sign, reopen, SNoAA|SSec, anon, switch, lt_leaks: TRUE  03m 08s
 - RSA, None|Sign, reopen, SNoAA|SSec, cert, switch, lt_leaks: TRUE  03m 51s
 - RSA, None|Sign, reopen, SNoAA, anon|cert|pwd, switch, lt_leaks: TRUE  40m 43s
 - RSA, None|Sign, reopen, SSec, anon|cert|pwd, switch, lt_leaks: TRUE  11m 33s
 - RSA, Encrypt|None, no_reopen, SNoAA|SSec, anon|cert|pwd, no_switch, lt_leaks: TRUE  09m 40s
 - RSA, None, reopen, SNoAA|SSec, anon|cert|pwd, switch, lt_leaks: TRUE  01m 08s
 - ECC, Encrypt|None|Sign, no_reopen, SNoAA|SSec, anon, no_switch, no_leaks: TRUE  39m 21s
 - ECC, Encrypt|None|Sign, no_reopen, SNoAA|SSec, cert, no_switch, no_leaks: TRUE  30m 39s
 - ECC, Encrypt|None|Sign, no_reopen, SNoAA, anon|cert, no_switch, lt_leaks: TRUE  22m 50s
 - ECC, Encrypt|None|Sign, no_reopen, SNoAA, anon, switch, no_leaks: TRUE  16m 19s
 - ECC, Encrypt|None|Sign, no_reopen, SNoAA, pwd, no_switch, lt_leaks: TRUE  36m 49s
 - ECC, Encrypt|None|Sign, no_reopen, SSec, anon|cert, no_switch, lt_leaks: TRUE  22m 45s
 - ECC, Encrypt|None|Sign, no_reopen, SSec, pwd, no_switch, lt_leaks: TRUE  41m 48s
 - ECC, None|Sign, no_reopen, SNoAA|SSec, anon|cert, no_switch, no_leaks: TRUE  34m 22s
 - ECC, None|Sign, no_reopen, SNoAA|SSec, anon, no_switch, lt_leaks: TRUE  16m 17s
 - ECC, None|Sign, no_reopen, SNoAA, anon|pwd, no_switch, lt_leaks: TRUE  31m 27s
 - ECC, None|Sign, no_reopen, SNoAA, anon|cert, switch, lt_leaks: TRUE  24m 42s
 - ECC, None|Sign, no_reopen, SNoAA, cert|pwd, no_switch, lt_leaks: TRUE  35m 57s
 - ECC, None|Sign, no_reopen, SSec, anon|pwd, no_switch, lt_leaks: TRUE  34m 50s
 - ECC, None|Sign, no_reopen, SSec, anon|cert, switch, lt_leaks: TRUE  36m 24s
 - ECC, None|Sign, no_reopen, SSec, cert|pwd, no_switch, lt_leaks: TRUE  35m 23s
 - ECC, Encrypt|None, no_reopen, SNoAA|SSec, anon, no_switch, lt_leaks: TRUE  28m 59s
 - ECC, Encrypt|None, no_reopen, SNoAA|SSec, cert, no_switch, lt_leaks: TRUE  21m 48s
 - ECC, Encrypt|None, no_reopen, SNoAA, anon|cert|pwd, no_switch, lt_leaks: TRUE  30m 23s
 - ECC, Encrypt|None, no_reopen, SSec, anon|cert|pwd, no_switch, lt_leaks: TRUE  25m 30s
 - ECC, Encrypt|None, reopen, SNoAA, pwd, switch, no_leaks: TRUE  36m 41s
 - ECC, Encrypt|Sign, no_reopen, SNoAA, anon|pwd, no_switch, no_leaks: TRUE  32m 40s
 - ECC, Encrypt|Sign, no_reopen, SNoAA, cert|pwd, no_switch, no_leaks: TRUE  29m 59s
 - ECC, Encrypt|Sign, no_reopen, SSec, anon|pwd, no_switch, no_leaks: TRUE  26m 01s
 - ECC, Encrypt|Sign, no_reopen, SSec, cert|pwd, no_switch, no_leaks: TRUE  28m 03s
 - ECC, Sign, no_reopen, SNoAA|SSec, anon|cert, no_switch, lt_leaks: TRUE  37m 30s
 - ECC, Sign, no_reopen, SNoAA|SSec, anon, switch, no_leaks: TRUE  36m 52s
 - ECC, Sign, no_reopen, SNoAA, anon|cert|pwd, no_switch, lt_leaks: TRUE  27m 58s
 - ECC, Sign, no_reopen, SSec, anon|cert|pwd, no_switch, lt_leaks: TRUE  30m 26s
 - ECC, Encrypt, no_reopen, SNoAA|SSec, pwd, no_switch, lt_leaks: TRUE  20m 32s
 - ECC, Encrypt, reopen, SNoAA, anon|pwd, switch, no_leaks: TRUE  27m 56s

### 3.1.D

 - ECC|RSA, None, reopen, SNoAA, cert|pwd, switch, lt_leaks: TRUE  01m 17s
 - ECC|RSA, None, reopen, SNoAA, anon, switch, lt_leaks: TRUE  00m 00s
 - ECC, Sign, reopen, SNoAA, cert|pwd|anon, no_switch, no_leaks: TRUE  01m 01s
 - ECC, Encrypt|None, no_reopen, SNoAA, anon|cert, no_switch, lt_leaks: TRUE  00m 11s
 - ECC, Sign|Encrypt, no_reopen, SNoAA|SSec, pwd, no_switch, lt_leaks: TRUE  27m 27s
 - RSA, None|Sign, no_reopen, SSec, anon|cert, no_switch, lt_leaks: TRUE  00m 01s
 - RSA, Sign|Encrypt|None, reopen, SNoAA|SSec, cert|pwd|anon, no_switch, no_leaks: TRUE  05m 30s
 - RSA, Sign|Encrypt, reopen, SNoAA|SSec, pwd, no_switch, lt_leaks: TRUE  02m 29s
 - RSA, Sign|Encrypt|None, reopen, SNoAA|SSec, cert, no_switch, lt_leaks: TRUE  00m 38s
 - RSA, Sign|Encrypt|None, reopen, SNoAA|SSec, anon, no_switch, lt_leaks: TRUE  00m 25s
 - RSA, Sign|None, no_reopen, SNoAA|SSec, pwd, switch, lt_leaks: TRUE  07m 54s
 - RSA, Sign|None, no_reopen, SNoAA|SSec, cert, switch, lt_leaks: TRUE  00m 09s
 - RSA, Sign|None, no_reopen, SNoAA|SSec, anon, switch, lt_leaks: TRUE  00m 07s

### 3.1.E

 - ECC|RSA, Encrypt|None|Sign, no_reopen, SNoAA, anon, no_switch, no_leaks: TRUE  19m 33s
 - ECC|RSA, Encrypt|None|Sign, no_reopen, SNoAA, cert, no_switch, no_leaks: TRUE  23m 45s
 - ECC|RSA, Encrypt|None|Sign, no_reopen, SSec, anon, no_switch, no_leaks: TRUE  26m 39s
 - ECC|RSA, None|Sign, no_reopen, SNoAA, anon|pwd, no_switch, no_leaks: TRUE  31m 24s
 - ECC|RSA, None|Sign, no_reopen, SNoAA, anon|cert, no_switch, lt_leaks: TRUE  24m 06s
 - ECC|RSA, None|Sign, no_reopen, SNoAA, cert|pwd, no_switch, no_leaks: TRUE  30m 07s
 - ECC|RSA, None|Sign, no_reopen, SNoAA, pwd, no_switch, lt_leaks: TRUE  36m 44s
 - ECC|RSA, None|Sign, no_reopen, SSec, anon, no_switch, lt_leaks: TRUE  13m 23s
 - ECC|RSA, None|Sign, no_reopen, SSec, cert, no_switch, no_leaks: TRUE  38m 12s
 - ECC|RSA, Encrypt|None, no_reopen, SNoAA, anon|pwd, no_switch, no_leaks: TRUE  25m 43s
 - ECC|RSA, Encrypt|None, no_reopen, SNoAA, anon|cert, no_switch, no_leaks: TRUE  18m 54s
 - ECC|RSA, Encrypt|None, no_reopen, SNoAA, anon, no_switch, lt_leaks: TRUE  27m 13s
 - ECC|RSA, Encrypt|None, no_reopen, SNoAA, cert|pwd, no_switch, no_leaks: TRUE  25m 28s
 - ECC|RSA, Encrypt|None, no_reopen, SNoAA, pwd, no_switch, lt_leaks: TRUE  28m 52s
 - ECC|RSA, Encrypt|None, no_reopen, SNoAA, cert, no_switch, lt_leaks: TRUE  24m 34s
 - ECC|RSA, Encrypt|None, no_reopen, SSec, anon, no_switch, lt_leaks: TRUE  27m 50s
 - ECC|RSA, Encrypt|None, no_reopen, SSec, pwd, no_switch, no_leaks: TRUE  41m 14s
 - ECC|RSA, Encrypt|None, reopen, SNoAA, anon, no_switch, no_leaks: TRUE  29m 13s
 - ECC|RSA, Encrypt|None, reopen, SNoAA, pwd, no_switch, no_leaks: TRUE  29m 47s
 - ECC|RSA, None, reopen, SNoAA|SSec, anon, switch, lt_leaks: TRUE  01m 48s
 - ECC|RSA, None, reopen, SNoAA|SSec, cert, no_switch, lt_leaks: TRUE  30m 14s
 - ECC|RSA, None, reopen, SNoAA, anon|cert|pwd, no_switch, lt_leaks: TRUE  01m 35s
 - ECC|RSA, None, reopen, SSec, anon|cert, no_switch, lt_leaks: TRUE  08m 04s
 - ECC|RSA, None, reopen, SSec, pwd, no_switch, lt_leaks: TRUE  14m 25s
 - ECC|RSA, Encrypt|Sign, no_reopen, SNoAA, anon|cert, no_switch, no_leaks: TRUE  36m 48s
 - ECC|RSA, Encrypt|Sign, no_reopen, SNoAA, pwd, no_switch, no_leaks: TRUE  20m 51s
 - ECC|RSA, Sign, no_reopen, SNoAA|SSec, anon, no_switch, no_leaks: TRUE  20m 48s
 - ECC|RSA, Sign, no_reopen, SNoAA, anon|cert|pwd, no_switch, no_leaks: TRUE  24m 40s
 - ECC|RSA, Encrypt, no_reopen, SNoAA, anon|cert|pwd, no_switch, no_leaks: TRUE  20m 06s
 - ECC|RSA, Encrypt, no_reopen, SNoAA, anon|pwd, no_switch, lt_leaks: TRUE  39m 05s
 - ECC|RSA, Encrypt, no_reopen, SNoAA, anon|cert, no_switch, lt_leaks: TRUE  40m 53s
 - ECC|RSA, Encrypt, no_reopen, SNoAA, cert|pwd, no_switch, lt_leaks: TRUE  36m 31s
 - ECC|RSA, Encrypt, no_reopen, SSec, anon|pwd, no_switch, no_leaks: TRUE  28m 17s
 - ECC|RSA, Encrypt, no_reopen, SSec, pwd, no_switch, lt_leaks: TRUE  24m 20s
 - ECC|RSA, Encrypt, no_reopen, SSec, cert, no_switch, no_leaks: TRUE  36m 14s
 - RSA, Encrypt|None|Sign, no_reopen, SNoAA|SSec, anon, no_switch, lt_leaks: TRUE  02m 09s
 - RSA, Encrypt|None|Sign, no_reopen, SNoAA, anon|cert|pwd, no_switch, lt_leaks: TRUE  02m 45s
 - RSA, Encrypt|None|Sign, no_reopen, SSec, anon|pwd, no_switch, lt_leaks: TRUE  32m 38s
 - RSA, Encrypt|None|Sign, no_reopen, SSec, anon|cert, no_switch, lt_leaks: TRUE  12m 33s
 - RSA, Encrypt|None|Sign, reopen, SNoAA, anon|pwd, no_switch, no_leaks: TRUE  01m 43s
 - RSA, None|Sign, no_reopen, SNoAA|SSec, anon|cert, no_switch, lt_leaks: TRUE  35m 01s
 - RSA, None|Sign, reopen, SNoAA|SSec, anon|cert, no_switch, no_leaks: TRUE  42m 13s
 - RSA, None|Sign, reopen, SNoAA|SSec, anon, no_switch, lt_leaks: TRUE  01m 08s
 - RSA, None|Sign, reopen, SNoAA|SSec, cert, no_switch, lt_leaks: TRUE  14m 08s
 - RSA, None|Sign, reopen, SNoAA, anon|cert|pwd, no_switch, lt_leaks: TRUE  01m 58s
 - RSA, None|Sign, reopen, SSec, anon|pwd, no_switch, lt_leaks: TRUE  20m 00s
 - RSA, None|Sign, reopen, SSec, anon|cert, no_switch, lt_leaks: TRUE  05m 32s
 - RSA, None|Sign, reopen, SSec, cert|pwd, no_switch, lt_leaks: TRUE  36m 15s
 - RSA, Encrypt|None, no_reopen, SNoAA|SSec, pwd, no_switch, lt_leaks: TRUE  30m 19s
 - RSA, Encrypt|None, no_reopen, SNoAA|SSec, cert, no_switch, lt_leaks: TRUE  24m 32s
 - RSA, None, reopen, SNoAA|SSec, anon|cert|pwd, no_switch, lt_leaks: TRUE  20m 18s
 - RSA, Encrypt, no_reopen, SNoAA|SSec, anon|pwd, no_switch, lt_leaks: TRUE  06m 35s
 - RSA, Encrypt, no_reopen, SSec, anon|cert|pwd, no_switch, lt_leaks: TRUE  23m 43s
 - ECC, Encrypt|None|Sign, no_reopen, SNoAA, anon|pwd, no_switch, no_leaks: TRUE  32m 29s
 - ECC, Encrypt|None|Sign, no_reopen, SNoAA, anon|cert, no_switch, no_leaks: TRUE  18m 52s
 - ECC, Encrypt|None|Sign, no_reopen, SNoAA, anon, no_switch, lt_leaks: TRUE  29m 40s
 - ECC, Encrypt|None|Sign, no_reopen, SNoAA, cert|pwd, no_switch, no_leaks: TRUE  40m 14s
 - ECC, None|Sign, no_reopen, SNoAA|SSec, anon, no_switch, no_leaks: TRUE  19m 02s
 - ECC, None|Sign, no_reopen, SNoAA, anon|cert|pwd, no_switch, no_leaks: TRUE  27m 13s
 - ECC, None|Sign, no_reopen, SNoAA, anon|pwd, no_switch, lt_leaks: TRUE  41m 43s
 - ECC, Encrypt|None, no_reopen, SNoAA, anon|cert|pwd, no_switch, lt_leaks: TRUE  38m 53s
 - ECC, Encrypt|None, reopen, SNoAA, anon|pwd, no_switch, no_leaks: TRUE  20m 01s
 - ECC, Encrypt|Sign, no_reopen, SNoAA, anon|cert|pwd, no_switch, no_leaks: TRUE  32m 31s
 - ECC, Sign, no_reopen, SNoAA|SSec, anon, no_switch, lt_leaks: TRUE  39m 28s
 - ECC, Sign, no_reopen, SNoAA, cert|pwd, no_switch, lt_leaks: TRUE  34m 09s
 - ECC, Sign, no_reopen, SSec, anon|cert, no_switch, no_leaks: TRUE  34m 53s
 - ECC, Encrypt, no_reopen, SNoAA|SSec, anon, no_switch, no_leaks: TRUE  24m 11s
 - ECC, Encrypt, no_reopen, SNoAA|SSec, pwd, no_switch, no_leaks: TRUE  23m 28s

### 3.2

 - ECC|RSA, None|Sign, no_reopen, SNoAA, cert, no_switch, no_leaks: TRUE  18m 10s
 - ECC|RSA, None|Sign, no_reopen, SSec, cert, no_switch, no_leaks: TRUE  18m 15s
 - ECC|RSA, Encrypt|None, no_reopen, SNoAA, cert, no_switch, no_leaks: TRUE  20m 23s
 - ECC|RSA, Encrypt|None, no_reopen, SSec, pwd, no_switch, no_leaks: TRUE  11m 59s
 - ECC|RSA, Encrypt|None, no_reopen, SSec, cert, no_switch, no_leaks: TRUE  20m 27s
 - ECC|RSA, None, reopen, SNoAA|SSec, anon|pwd, no_switch, no_leaks: TRUE  21m 11s
 - ECC|RSA, None, reopen, SNoAA|SSec, anon|cert, switch, lt_leaks: TRUE  00m 41s
 - ECC|RSA, None, reopen, SNoAA|SSec, pwd, no_switch, lt_leaks: TRUE  13m 09s
 - ECC|RSA, None, reopen, SNoAA, anon|cert|pwd, switch, lt_leaks: TRUE  13m 12s
 - ECC|RSA, None, reopen, SSec, anon|cert|pwd, switch, lt_leaks: TRUE  17m 37s
 - ECC|RSA, Encrypt, no_reopen, SSec, pwd, no_switch, lt_leaks: TRUE  16m 05s
 - RSA, Encrypt|None|Sign, no_reopen, SNoAA|SSec, anon, no_switch, lt_leaks: TRUE  06m 24s
 - RSA, Encrypt|None|Sign, no_reopen, SNoAA|SSec, cert, no_switch, lt_leaks: TRUE  05m 46s
 - RSA, Encrypt|None|Sign, no_reopen, SNoAA, anon|pwd, no_switch, lt_leaks: TRUE  13m 44s
 - RSA, Encrypt|None|Sign, no_reopen, SNoAA, anon|cert, no_switch, lt_leaks: TRUE  03m 41s
 - RSA, Encrypt|None|Sign, no_reopen, SNoAA, cert|pwd, no_switch, lt_leaks: TRUE  07m 40s
 - RSA, Encrypt|None|Sign, no_reopen, SSec, anon|cert|pwd, no_switch, lt_leaks: TRUE  20m 39s
 - RSA, Encrypt|None|Sign, reopen, SNoAA, anon|pwd, no_switch, no_leaks: TRUE  16m 20s
 - RSA, Encrypt|None|Sign, reopen, SNoAA, anon, switch, no_leaks: TRUE  08m 54s
 - RSA, None|Sign, no_reopen, SNoAA|SSec, anon|cert, no_switch, lt_leaks: TRUE  06m 21s
 - RSA, None|Sign, no_reopen, SNoAA|SSec, anon, switch, lt_leaks: TRUE  14m 16s
 - RSA, None|Sign, no_reopen, SNoAA|SSec, cert, switch, lt_leaks: TRUE  15m 33s
 - RSA, None|Sign, no_reopen, SNoAA, anon|cert|pwd, no_switch, lt_leaks: TRUE  10m 06s
 - RSA, None|Sign, no_reopen, SNoAA, anon|cert, switch, lt_leaks: TRUE  13m 39s
 - RSA, None|Sign, no_reopen, SNoAA, pwd, switch, lt_leaks: TRUE  16m 41s
 - RSA, None|Sign, no_reopen, SSec, anon|cert, switch, lt_leaks: TRUE  13m 26s
 - RSA, None|Sign, no_reopen, SSec, pwd, switch, lt_leaks: TRUE  20m 10s
 - RSA, None|Sign, reopen, SNoAA|SSec, anon|cert, no_switch, no_leaks: TRUE  11m 21s
 - RSA, None|Sign, reopen, SNoAA|SSec, anon, switch, no_leaks: TRUE  18m 07s
 - RSA, None|Sign, reopen, SNoAA|SSec, cert, switch, no_leaks: TRUE  16m 55s
 - RSA, None|Sign, reopen, SNoAA, anon|cert|pwd, no_switch, no_leaks: TRUE  13m 09s
 - RSA, None|Sign, reopen, SNoAA, anon|cert, no_switch, lt_leaks: TRUE  13m 09s
 - RSA, None|Sign, reopen, SNoAA, anon, switch, lt_leaks: TRUE  07m 07s
 - RSA, None|Sign, reopen, SNoAA, pwd, no_switch, lt_leaks: TRUE  10m 04s
 - RSA, None|Sign, reopen, SNoAA, pwd, switch, no_leaks: TRUE  20m 08s
 - RSA, None|Sign, reopen, SSec, anon|cert|pwd, no_switch, no_leaks: TRUE  12m 34s
 - RSA, None|Sign, reopen, SSec, anon|cert, no_switch, lt_leaks: TRUE  13m 48s
 - RSA, None|Sign, reopen, SSec, anon|cert, switch, no_leaks: TRUE  17m 06s
 - RSA, None|Sign, reopen, SSec, pwd, no_switch, lt_leaks: TRUE  13m 15s
 - RSA, None|Sign, reopen, SSec, pwd, switch, no_leaks: TRUE  21m 01s
 - RSA, None|Sign, reopen, SSec, cert, switch, lt_leaks: TRUE  17m 55s
 - RSA, Encrypt|None, no_reopen, SNoAA|SSec, anon|cert|pwd, no_switch, lt_leaks: TRUE  19m 05s
 - RSA, Encrypt|None, no_reopen, SNoAA|SSec, cert, switch, no_leaks: TRUE  18m 48s
 - RSA, Encrypt|None, no_reopen, SSec, anon|cert, switch, no_leaks: TRUE  20m 00s
 - RSA, Encrypt|None, reopen, SNoAA|SSec, cert, no_switch, no_leaks: TRUE  02m 46s
 - RSA, Encrypt|None, reopen, SNoAA, anon|pwd, switch, no_leaks: TRUE  14m 43s
 - RSA, Encrypt|None, reopen, SNoAA, cert, switch, no_leaks: TRUE  04m 42s
 - RSA, Encrypt|None, reopen, SSec, anon|cert|pwd, no_switch, no_leaks: TRUE  04m 08s
 - RSA, Encrypt|None, reopen, SSec, anon|pwd, switch, no_leaks: TRUE  17m 45s
 - RSA, Encrypt|None, reopen, SSec, cert|pwd, switch, no_leaks: TRUE  10m 35s
 - RSA, None, reopen, SNoAA|SSec, anon|cert|pwd, switch, lt_leaks: TRUE  03m 14s
 - RSA, Encrypt, reopen, SSec, anon|cert, switch, no_leaks: TRUE  18m 35s
 - ECC, Encrypt|None|Sign, no_reopen, SNoAA, anon, no_switch, no_leaks: TRUE  05m 44s
 - ECC, Encrypt|None|Sign, no_reopen, SNoAA, cert, no_switch, no_leaks: TRUE  05m 44s
 - ECC, Encrypt|None|Sign, no_reopen, SSec, anon, no_switch, no_leaks: TRUE  09m 08s
 - ECC, Encrypt|None|Sign, no_reopen, SSec, cert, no_switch, no_leaks: TRUE  05m 23s
 - ECC, None|Sign, no_reopen, SNoAA|SSec, anon, no_switch, no_leaks: TRUE  07m 53s
 - ECC, None|Sign, no_reopen, SNoAA|SSec, cert, no_switch, no_leaks: TRUE  07m 03s
 - ECC, None|Sign, no_reopen, SNoAA, anon|cert, no_switch, lt_leaks: TRUE  09m 30s
 - ECC, None|Sign, no_reopen, SNoAA, anon, switch, lt_leaks: TRUE  11m 07s
 - ECC, None|Sign, no_reopen, SNoAA, cert, switch, no_leaks: TRUE  08m 54s
 - ECC, None|Sign, no_reopen, SSec, anon|cert, no_switch, lt_leaks: TRUE  10m 40s
 - ECC, None|Sign, no_reopen, SSec, anon, switch, no_leaks: TRUE  15m 55s
 - ECC, None|Sign, no_reopen, SSec, cert, switch, no_leaks: TRUE  10m 46s
 - ECC, Encrypt|None, no_reopen, SNoAA|SSec, anon, no_switch, no_leaks: TRUE  09m 38s
 - ECC, Encrypt|None, no_reopen, SNoAA|SSec, cert, no_switch, no_leaks: TRUE  10m 14s
 - ECC, Encrypt|None, no_reopen, SNoAA, anon|cert|pwd, no_switch, lt_leaks: TRUE  19m 12s
 - ECC, Encrypt|None, no_reopen, SNoAA, anon, switch, no_leaks: TRUE  10m 21s
 - ECC, Encrypt|None, no_reopen, SSec, anon|cert|pwd, no_switch, no_leaks: TRUE  15m 59s
 - ECC, Encrypt|None, no_reopen, SSec, anon|pwd, no_switch, lt_leaks: TRUE  10m 10s
 - ECC, Encrypt|None, no_reopen, SSec, anon|cert, no_switch, lt_leaks: TRUE  08m 34s
 - ECC, Encrypt|None, no_reopen, SSec, cert|pwd, no_switch, lt_leaks: TRUE  10m 20s
 - ECC, Encrypt|None, reopen, SNoAA, anon|pwd, no_switch, no_leaks: TRUE  14m 52s
 - ECC, Encrypt|None, reopen, SNoAA, pwd, switch, no_leaks: TRUE  20m 31s
 - ECC, None, reopen, SNoAA|SSec, anon|pwd, no_switch, lt_leaks: TRUE  17m 33s
 - ECC, None, reopen, SNoAA|SSec, cert|pwd, no_switch, lt_leaks: TRUE  17m 29s
 - ECC, Encrypt, no_reopen, SNoAA|SSec, cert|pwd, no_switch, no_leaks: TRUE  20m 03s
 - ECC, Encrypt, no_reopen, SSec, anon|cert|pwd, no_switch, lt_leaks: TRUE  11m 30s

# 3.2.axioms

 - ECC|RSA, Encrypt|None|Sign, no_reopen, SNoAA, anon|pwd, no_switch, lt_leaks: TRUE  04m 00s
 - ECC|RSA, Encrypt|None|Sign, no_reopen, SNoAA, anon|cert, no_switch, lt_leaks: TRUE  05m 54s
 - ECC|RSA, Encrypt|None|Sign, no_reopen, SNoAA, cert|pwd, no_switch, lt_leaks: TRUE  03m 57s
 - ECC|RSA, Encrypt|None|Sign, no_reopen, SNoAA, cert, switch, lt_leaks: TRUE  01m 53s
 - ECC|RSA, Encrypt|None|Sign, no_reopen, SSec, anon|cert|pwd, no_switch, lt_leaks: TRUE  08m 39s
 - ECC|RSA, Encrypt|None|Sign, no_reopen, SSec, anon|cert, switch, lt_leaks: TRUE  04m 14s
 - ECC|RSA, Encrypt|None|Sign, reopen, SNoAA, anon|cert|pwd, no_switch, no_leaks: TRUE  00m 35s
 - ECC|RSA, Encrypt|None|Sign, reopen, SNoAA, pwd, no_switch, lt_leaks: TRUE  09m 58s
 - ECC|RSA, Encrypt|None|Sign, reopen, SSec, anon|cert|pwd, no_switch, no_leaks: TRUE  00m 37s
 - ECC|RSA, Encrypt|None|Sign, reopen, SSec, anon, no_switch, lt_leaks: TRUE  06m 21s
 - ECC|RSA, Encrypt|None|Sign, reopen, SSec, pwd, no_switch, lt_leaks: TRUE  08m 00s
 - ECC|RSA, Encrypt|None|Sign, reopen, SSec, cert, no_switch, lt_leaks: TRUE  06m 13s
 - ECC|RSA, None|Sign, no_reopen, SNoAA, anon|cert|pwd, no_switch, lt_leaks: TRUE  01m 08s
 - ECC|RSA, None|Sign, reopen, SNoAA, anon|pwd, no_switch, lt_leaks: TRUE  03m 44s
 - ECC|RSA, None|Sign, reopen, SNoAA, anon|cert, no_switch, lt_leaks: TRUE  06m 28s
 - ECC|RSA, None|Sign, reopen, SNoAA, cert|pwd, no_switch, lt_leaks: TRUE  03m 56s
 - ECC|RSA, None|Sign, reopen, SNoAA, cert, switch, lt_leaks: TRUE  03m 58s
 - ECC|RSA, None|Sign, reopen, SSec, anon|cert|pwd, no_switch, lt_leaks: TRUE  08m 14s
 - ECC|RSA, Encrypt|None, no_reopen, SNoAA, anon|cert|pwd, switch, lt_leaks: TRUE  04m 07s
 - ECC|RSA, Encrypt|None, no_reopen, SSec, anon|cert|pwd, switch, lt_leaks: TRUE  01m 29s
 - ECC|RSA, Encrypt|None, reopen, SNoAA, anon|cert|pwd, switch, no_leaks: TRUE  00m 16s
 - ECC|RSA, Encrypt|None, reopen, SNoAA, anon|pwd, no_switch, lt_leaks: TRUE  04m 07s
 - ECC|RSA, Encrypt|None, reopen, SNoAA, anon|cert, no_switch, lt_leaks: TRUE  03m 59s
 - ECC|RSA, Encrypt|None, reopen, SNoAA, cert|pwd, no_switch, lt_leaks: TRUE  04m 05s
 - ECC|RSA, Encrypt|None, reopen, SNoAA, cert, switch, lt_leaks: TRUE  04m 49s
 - ECC|RSA, Encrypt|None, reopen, SSec, anon|cert|pwd, no_switch, lt_leaks: TRUE  08m 26s
 - ECC|RSA, Encrypt|None, reopen, SSec, anon|cert|pwd, switch, no_leaks: TRUE  00m 16s
 - ECC|RSA, Encrypt|None, reopen, SSec, anon|cert, switch, lt_leaks: TRUE  09m 52s
 - ECC|RSA, Encrypt|None, reopen, SSec, pwd, switch, lt_leaks: TRUE  05m 16s
 - ECC|RSA, None, reopen, SNoAA|SSec, anon|cert|pwd, switch, lt_leaks: TRUE  00m 09s
 - ECC|RSA, Encrypt|Sign, no_reopen, SNoAA, anon|cert|pwd, no_switch, lt_leaks: TRUE  09m 00s
 - ECC|RSA, Encrypt|Sign, no_reopen, SNoAA, anon, switch, lt_leaks: TRUE  07m 02s
 - ECC|RSA, Encrypt|Sign, no_reopen, SNoAA, cert|pwd, switch, lt_leaks: TRUE  04m 56s
 - ECC|RSA, Encrypt|Sign, no_reopen, SSec, anon|cert|pwd, switch, lt_leaks: TRUE  10m 32s
 - ECC|RSA, Encrypt|Sign, reopen, SNoAA, anon|cert|pwd, switch, no_leaks: TRUE  00m 39s
 - ECC|RSA, Encrypt|Sign, reopen, SNoAA, anon, no_switch, lt_leaks: TRUE  10m 32s
 - ECC|RSA, Encrypt|Sign, reopen, SNoAA, cert, no_switch, lt_leaks: TRUE  10m 30s
 - ECC|RSA, Encrypt|Sign, reopen, SSec, anon|cert|pwd, switch, no_leaks: TRUE  00m 38s
 - ECC|RSA, Sign, no_reopen, SNoAA, anon|cert|pwd, switch, lt_leaks: TRUE  02m 17s
 - ECC|RSA, Sign, reopen, SNoAA, anon|cert|pwd, no_switch, lt_leaks: TRUE  07m 47s
 - ECC|RSA, Sign, reopen, SNoAA, pwd, switch, lt_leaks: TRUE  09m 36s
 - ECC|RSA, Sign, reopen, SSec, anon|cert, switch, lt_leaks: TRUE  03m 36s
 - ECC|RSA, Sign, reopen, SSec, pwd, switch, lt_leaks: TRUE  09m 33s
 - ECC|RSA, Encrypt, reopen, SNoAA, anon|cert|pwd, no_switch, lt_leaks: TRUE  08m 20s
 - ECC|RSA, Encrypt, reopen, SSec, anon|pwd, switch, lt_leaks: TRUE  06m 29s
 - ECC|RSA, Encrypt, reopen, SSec, cert|pwd, switch, lt_leaks: TRUE  08m 31s
 - RSA, Encrypt|None|Sign, reopen, SNoAA, anon|cert|pwd, switch, lt_leaks: TRUE  01m 02s
 - RSA, Encrypt|None|Sign, reopen, SSec, anon|cert|pwd, switch, lt_leaks: TRUE  01m 02s
 - ECC, Encrypt|None|Sign, no_reopen, SNoAA, anon|cert|pwd, no_switch, lt_leaks: TRUE  09m 39s
 - ECC, None|Sign, reopen, SNoAA, anon|cert|pwd, no_switch, lt_leaks: TRUE  09m 07s
 - ECC, Encrypt|None, reopen, SNoAA, anon|cert|pwd, no_switch, lt_leaks: TRUE  10m 03s
 - ECC, Encrypt|None, reopen, SNoAA, pwd, switch, lt_leaks: TRUE  07m 10s
 - ECC, Encrypt|Sign, no_reopen, SNoAA, anon|pwd, switch, lt_leaks: TRUE  09m 30s
 - ECC, Encrypt|Sign, no_reopen, SNoAA, anon|cert, switch, lt_leaks: TRUE  09m 11s
 - ECC, Sign, reopen, SSec, anon|pwd, switch, lt_leaks: TRUE  10m 06s
 - ECC, Sign, reopen, SSec, cert|pwd, switch, lt_leaks: TRUE  10m 14s
 - ECC, Encrypt, reopen, SNoAA, cert|pwd, switch, lt_leaks: TRUE  05m 40s
 - ECC, Encrypt, reopen, SSec, anon|cert|pwd, switch, lt_leaks: TRUE  08m 59s
 

### 3.2.A

 - ECC|RSA, None, reopen, SNoAA, anon, switch, no_leaks: TRUE 00m 00s
 - ECC|RSA, Sign|None, no_reopen, SNoAA|SSec, pwd|cert|anon, switch, lt_leaks: TRUE  05m 28s
 - ECC, Encrypt, no_reopen, SNoAA|SSec, cert|anon|pwd, switch, lt_leaks: TRUE  00m 38s
 - ECC|RSA, Encrypt|Sign|None, reopen, SNoAA|SSec, pwd|cert|anon, no_switch, lt_leaks: TRUE  27m 26s
 - RSA, Encrypt|Sign|None, reopen, SNoAA|SSec, cert|anon|pwd, switch, lt_leaks: TRUE  00m 35s
 
