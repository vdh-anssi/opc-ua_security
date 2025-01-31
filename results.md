A Formal Security Analysis of OPC UA.
=====================================

See the file README.md for detailed instruction on how to use proverif.
We present here, for each security properties, some configurations for which we have proofs. Those configurations are maximal with respect to the timeout we used and explicitly indicate.


# Confidentiality Properties
In the paper (Section 5, Scope of the proofs), we make the following claims:
> Proofs for Conf[C] and Conf[S] (obtained in maximum 9 hours) are with respect to almost maximal configurations. Namely, we achieve the maximal configuration for RSA. Proofs are more challenging in ECC because they require PFS. We can nevertheless prove the maximal configuration (excluding None and SNoAA): (i) without Leak, as well as (ii) with Leak and either without Reopen, or without Switch.
> We proved Conf[Pwd] for the maximal configuration without Leak. With Leak, proofs were harder to obtain as we must choose between Reopen and Switch. We otherwise capture all configurations when considering in isolation SecurityPolicy and Mode.

The configurations we list here support those claims.

## For the property Conf[C]:
Maximal configurations (including "switch") when the Security Policy is RSA:
 - `$ python3 opcua.py -q "Conf[C]" -c "RSA, None|Sign|Encrypt, reopen, SNoAA|SSec, anon|pwd|cert, switch, lt_leaks"` (1m)
Maximal configurations (including "switch"), but no key leaks when the Security Policy is ECC:
 - `$ python3 opcua.py -q "Conf[C]" -c "ECC, None|Sign|Encrypt, reopen, SNoAA|SSec, anon|pwd|cert, switch, no_leaks"` (10s)
Maximal configurations except when "switch" is disabled:
 - `$ python3 opcua.py -q "Conf[C]" -c "RSA|ECC, None|Sign|Encrypt, reopen, SNoAA|SSec, anon|pwd|cert, no_switch, lt_leaks"` (9m)
Maximal configurations except when "reopen" (and "SNoAA") is disabled:
 - `$ python3 opcua.py -q "Conf[C]" -c "RSA|ECC, None|Sign|Encrypt, no_reopen, SSec, anon|pwd|cert, switch, lt_leaks"` (8m)

## For the property Conf[S]:
Maximal configurations (including "switch") when the Security Policy is RSA:
 - `$ python3 opcua.py -q "Conf[S]" -c "RSA, None|Sign|Encrypt, reopen, SNoAA|SSec, anon|pwd|cert, switch, lt_leaks"` (7m)
Maximal configurations (including "switch"), but no key leaks when the Security Policy is ECC:
 - `$ python3 opcua.py -q "Conf[S]" -c "ECC, Sign|Encrypt, reopen, SNoAA|SSec, anon|pwd|cert, switch, no_leaks"` (20s)
Maximal configurations except when "switch" is disabled:
 - `$ python3 opcua.py -q "Conf[S]" -c "RSA|ECC, None|Sign|Encrypt, reopen, SNoAA|SSec, anon|pwd|cert, no_switch, lt_leaks"` (40m)
Maximal configurations in ECC with "reopen", "switch" and key leaks:
 - `$ python3 opcua.py -q "Conf[S]" -c "ECC, Encrypt, reopen, SNoAA, pwd|cert, switch, lt_leaks"` (05h)
Maximal configurations except when "reopen" (and "SNoAA") is disabled:
 - `$ python3 opcua.py -q "Conf[S]" -c "ECC, Sign|Encrypt, no_reopen, SSec, anon|pwd|cert, switch, lt_leaks"` (9h)

## For the property Conf[Pwd]:
Configuration with long-term key leaks, but no channel leaks:
 - `$ python3 opcua.py -q "Conf[Pwd]" -c "ECC, Encrypt, no_reopen, SSec, pwd, no_switch, lt_leaks"` (1s)
Password confidentiality when no signature oracle is allowed (i.e., we enforce parsing of certificates even when SessionSecurity includes SNoAA):
 - `$ python3 opcua.py -q "Conf[Pwd]" -c "ECC, None, reopen, SNoAA|SSec, pwd, switch, lt_leaks"`: (1m)
 - `$ python3 opcua.py -q "Conf[Pwd]" -c "RSA|ECC, None|Sign|Encrypt, reopen, SNoAA|SSec, pwd, switch, no_leaks"` (2m)
In a subset of this configuration an attack was found using `--oracle`. The version 1.05.04 RC with our fix to the signature oracle attack is obtained without `--oracle` and can be proven secure with the command just above.
Maximal configurations in RSA except when "switch" (and "SSec") is disabled:
 - `$ python3 opcua.py -q "Conf[Pwd]" -c "RSA, None|Sign|Encrypt, reopen, SNoAA, pwd, no_switch, lt_leaks"` (8m)
Maximal configurations in RSA except when "reopen" (and "SSec") is disabled:
 - `$ python3 opcua.py -q "Conf[Pwd]" -c "RSA, None|Sign|Encrypt, no_reopen, SNoAA, pwd, switch, lt_leaks"` (1m)
Maximal configurations in ECC except when "reopen" and "switch" are disabled:
 - `$ python3 opcua.py -q "Conf[Pwd]" -c "ECC, None|Sign|Encrypt, no_reopen, SNoAA|SSec, pwd, no_switch, lt_leaks"` (1h)


# Agreement Properties
As mentioned in the paper, the agreement properties are much more complex to prove. They rely on more complex injective agreement properties but more importantly, we had to weaken them, which resulted in much more complicated queries with a lot of side-conditions to take into account the residual risks.

However, we make two claims:
 1. We can prove our fixes provably repair the protocol for the configuration in which we found the attacks
 2. We can establish proofs for a variety of configurations whose the union capture all configuration options.
We leave as future work the proof of the maximal configuration for the weakened agreement properties.

The claim 1. is supported by the results mentioned here and detailed in the README.md file:
 - for the weakened property Agr-[S->C],
 - for the weakened property Agr-[C->S],
 - for the property Conf[Pwd].

The claim 2. is supported by the results we obtained through lattice exploration campaigns results we report on below and that can be reproduced as explained in the README.md file.

##  Summary of results for the weakened property Agr-[S->C]

Property "3.1" refers to the weakened Agr-[S->C] (to tolerate the KCI attacks and race condition).
As explained in the paper, we use a series of lemmas and advanced techniques that depend on the set of sub-lemmas that need to be proven.
According to the file `dependencies.txt`, to prove the weakened property Agr-[S->C] we need to prove the following queries: "3.1.axioms", "3.1.axioms.1", "3.1.conf", "3.1.A", "3.1.B", "3.1.C", "3.1.D", "3.1.E", and finally "3.1" that relies on all of those other lemmas.
 - `$ python3 opcua.py -q "3.1.axioms"   -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (8s)
 - `$ python3 opcua.py -q "3.1.axioms.1" -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (1s)
 - `$ python3 opcua.py -q "3.1.conf"     -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (1s)
 - `$ python3 opcua.py -q "3.1.A"        -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (1m)
 - `$ python3 opcua.py -q "3.1.B"        -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (23h and > 30 GiB)
 - `$ python3 opcua.py -q "3.1.C"        -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (1s)
 - `$ python3 opcua.py -q "3.1.D"        -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (4s)
 - `$ python3 opcua.py -q "3.1.E"        -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (1m)
 - `$ python3 opcua.py -q "3.1"          -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (30s)

In particular this shows the absence of the impersonation attack that was found on configuration "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks".

Examples of configurations, where all lemmas and the property are proven (verification time is given for the longest query):
 - ECC|RSA, None,                 reopen, SNoAA,      anon,             switch, no_leaks (3.1.B 5s)
 - ECC|RSA, None|Sign|Encrypt,    reopen, SNoAA,      anon|pwd|cert, no_switch, no_leaks (3.1 4h)
 - ECC|RSA, None|Sign|Encrypt,    reopen,       SSec, anon|pwd|cert, no_switch, no_leaks (3.1 4h)
 - ECC|RSA,      Sign|Encrypt,    reopen,       SSec,          cert,    switch, no_leaks (3.1.axioms 17m)
 - ECC|RSA, None|     Encrypt, no_reopen, SNoAA,           pwd|cert,    switch, no_leaks (3.1.B 9m)
 - ECC|RSA, None|     Encrypt, no_reopen,       SSec, anon|pwd|cert,    switch, no_leaks (3.1.B 2h)
 -     RSA, None|Sign,         no_reopen,       SSec, anon|    cert, no_switch, lt_leaks (3.1.axioms 7m)
 - ECC,               Encrypt, no_reopen, SNoAA,               cert, no_switch, lt_leaks (3.1.B 23h)
 - ECC,               Encrypt, no_reopen,       SSec,          cert, no_switch, lt_leaks (3.1.B 22h)
 - ECC,          Sign,         no_reopen, SNoAA,               cert, no_switch, lt_leaks (3.1.B 09h)


##  Summary of results for the weakened property Agr-[C->S]

Similarly, property "3.2" refers to the weakened version of Agr-[C->S]. Its proof relies on "3.2.axioms", "3.2.A", but also on "3.1.A" and "3.1.C". When "ECC" is present in the configuration, we should also prove "3.1.axioms" (because "3.1.A" and "3.1.C" assume "3.1.axioms" in that case; see `dependencies.txt`).

Examples of configurations, where all lemmas and the property are proven:
 - ECC|RSA, None|Sign|Encrypt, no_reopen, SSec, anon|pwd|cert, no_switch, no_leaks (3.1.axioms 1m)
 - ECC|RSA, None|Sign|Encrypt,    reopen, SSec, anon|pwd|cert, no_switch, no_leaks (3.1.axioms 4h)
 - ECC|RSA, None,                 reopen, SSec, anon|pwd|cert,    switch,    lt_leaks (3.1.A 1h)
 -     RSA, None|Sign,            reopen, SSec, anon|pwd|cert,    switch,    lt_leaks (3.1.A 42m)
 - ECC|RSA,      Sign|Encrypt,    reopen, SSec,          cert,    switch, no_leaks (3.1.axioms 17m)
