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
`$ python3 opcua.py -q "Conf[C]" -c "RSA, None|Sign|Encrypt, reopen, SNoAA|SSec, anon|pwd|cert, switch, lt_leaks"` (30s)
Maximal configurations (including "switch"), but no key leaks when the Security Policy is ECC:
`$ python3 opcua.py -q "Conf[C]" -c "ECC, None|Sign|Encrypt, reopen, SNoAA|SSec, anon|pwd|cert, switch, no_leaks"` (10s)
Maximal configurations except when "switch" is disabled:
`$ python3 opcua.py -q "Conf[C]" -c "RSA|ECC, None|Sign|Encrypt, reopen, SNoAA|SSec, anon|pwd|cert, no_switch, lt_leaks"` (5m)

## For the property Conf[S]:
Maximal configurations (including "switch") when the Security Policy is RSA:
`$ python3 opcua.py -q "Conf[S]" -c "RSA, None|Sign|Encrypt, reopen, SNoAA|SSec, anon|pwd|cert, switch, lt_leaks"` (3m)
Maximal configurations (including "switch"), but no key leaks when the Security Policy is ECC:
`$ python3 opcua.py -q "Conf[S]" -c "ECC, Sign|Encrypt, reopen, SNoAA|SSec, anon|pwd|cert, switch, no_leaks"` (10s)
Maximal configurations except when "switch" is disabled:
`$ python3 opcua.py -q "Conf[S]" -c "RSA|ECC, None|Sign|Encrypt, reopen, SNoAA|SSec, anon|pwd|cert, no_switch, lt_leaks"` (25m)
In a subset of this configuration an attack was found using `--oracle`. The version 1.05.04 RC with our fix to the signature oracle attack is obtained without `--oracle` and can be proven secure with the command just above.

## For the property Conf[Pwd]:
Configuration with long-term key leaks, but no channel leaks:
`$ python3 opcua.py -q "Conf[Pwd]" -c "ECC, Encrypt, no_reopen, SSec, pwd, no_switch, lt_leaks"` (1s)
Password confidentiality when no signature oracle is allowed (i.e., we enforce parsing of certificates even when SessionSecurity includes SNoAA):
`$ python3 opcua.py -q "Conf[Pwd]" -c "ECC, None, reopen, SNoAA|SSec, pwd, switch, lt_leaks"`: (3s)
`$ python3 opcua.py -q "Conf[Pwd]" -c "RSA|ECC, Sign|Encrypt, reopen, SNoAA, pwd, switch, no_leaks"` (10s)

# Agreement Properties
As mentioned in the paper, the agreement properties are much more complex to prove. They rely on more complex injective agreement properties but more importantly, we had to weaken them, which resulted in much more complicated queries with a lot of side-conditions to take into account the residual risks.

However, we make two claims:
 1. We can prove our fixes provably repair the protocol for the configuration in which we found the attacks
 2. We can establish proofs for a variety of configurations whose the union capture all configuration options.
We leave as future work the proof of the maximal configuration for the weakened agreement properties.

The claim 1. is supported by the results mentioned in the README.md file:
Proofs for this property requires to first prove a number of lemmas that we assume (axioms) during the proof of the weakened Agr[S->C].
`$ python3 opcua.py --dev -q "3.1.axioms" -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (5s)
`$ python3 opcua.py --dev  -q "3.1.axioms.1" -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (5s)
`$ python3 opcua.py --dev  -q "3.1.A" -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (5s)
`$ python3 opcua.py --dev  -q "3.1.B" -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (1m)
`$ python3 opcua.py --dev  -q "3.1.C" -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (1s)
`$ python3 opcua.py --dev  -q "3.1.D" -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (5s)
`$ python3 opcua.py --dev  -q "3.1.E" -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (1m)
`$ python3 opcua.py --dev  -q "3.1"   -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (1m)
Similarly, the query "3.2" relies on "3.2.axioms", "3.2.A" and all "3.1.*" queries discussed above.
One should launch:
`$ python3 opcua.py --dev  -q "3.2.axioms" -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (5s)
`$ python3 opcua.py --dev  -q "3.2.A"   -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (5s)
`$ python3 opcua.py --dev  -q "3.2"   -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (2m)

The claim 2. is supported by the results we obtained through lattice exploration campaigns results we report on below and that can be reproduced as explained in the README.md file.

##  Campaign results for the weakened property Agr-[S->C]
TODO1: <insert here campaign results for 3.1, 3.1.B, 3.1.E, 3.1.axioms, 3.1.axioms.1
TODO2: Then we need to compute ourselves some configurations
capturing rich config tu support claim 2. for: 3.1.A, 3.1.C, 3.1.D, 3.1.

##  Campaign results for the weakened property Agr-[C->S]
TODO3: <insert here campaign results for 3.2, 3.2.A, 3.2.axioms

