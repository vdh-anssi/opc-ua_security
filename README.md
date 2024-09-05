A Formal Security Analysis of OPC-UA.
=====================================

This file gives detailed instructions on how to use ProVerif to:
 - find attacks and get detailed attack traces as PDF files
 - prove that our fixes provably repair the protocols for the configurations for which we found the attacks
 - prove the properties in the fixed variant for further configurations
 - launch lattice exploration campaigns.

# Installation

You need to build the development version of ProVerif, from the sources on branch "improved_scope_lemma" (this requires a working ocaml compiler):
 - `$ git clone https://gitlab.inria.fr/bblanche/proverif.git`
 - `$ cd proverif/proverif`
 - `$ git checkout improved_scope_lemma`
 - `$ ./build`
 - `$ ./proverif --help`

Results in this file have been obtained with Proverif development, branch improved_scope_lemma, commit 6a803aa13ccde13c0574912da93f029f86f63951. The branch improved_scope_lemma has been previously used in 
> Cheval, Vincent, Véronique Cortier, and Alexandre Debant. "Election Verifiability with ProVerif." 2023 IEEE 36th Computer Security Foundations Symposium (CSF). IEEE, 2023.

(Attacks can be found with the ProVerif version 2.05, available at https://bblanche.gitlabpages.inria.fr/proverif/, as well as the proofs for the confidentiality properties but the development version is required for proving the agreement properties. We thus recommend using the aforementioned development version.)

Make sure that the proverif executable is in your path and available from the command line.
You also need python 3.11 with Jinja2 (https://pypi.org/project/Jinja2/), to run the tool "opcua.py", that generates the input files and launch proverif.
 - `$ pip install jinja2`


# To reproduce the automatic attack finding described in the paper

These experiments have been conducted on a standard laptop. 

§5.2 Race condition for user contexts breaking Agr[S->C]:
 - `$ python3 opcua.py -q "3.1.0" -c "ECC, Encrypt, no_reopen, SSec, cert, no_switch, no_leaks" --html --not_fixed`
open the file `output/trace1.pdf`
The attack is found and reconstructed in less than 10s.
"3.1.0" is the initial Agr[S->C] property discussed in the paper.
`--not_fixed` indicates that the server's thumbprint is not included in ECC mode.
`-c` specifies the configuration.
See below how we can establish a security proof when our fix is used.

§5.2 Race condition for user contexts breaking Agr[C->S]:
 - `$ python3 opcua.py -q "3.2.0" -c "ECC, Encrypt, no_reopen, SSec, cert, no_switch, no_leaks" --html --not_fixed`
open the file `output/trace1.pdf`
The attack is found and reconstructed in less than 5s.
"3.2.0" is the initial Agr[C->S] property discussed in the paper.
See below how we can establish a security proof when our fix is used.


§5.3 ECC client impersonation attack and §5.4 KCI attack:
 - `$ python3 opcua.py -q "3.1" -u -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks" --html --not_fixed`
§5.2 KCI attack: open the file `output/trace1.pdf`
§5.3 ECC client impersonation attack: open the file `output/trace2.pdf`
"3.1" -u: checks both Agr[S->C] weakened to tolerate race conditions and KCI attacks
The attack is found and reconstructed in less than 20s.

§5.5 Downgrade of password secrecy:
 - `$ python3 opcua.py -q "Conf[Pwd]" -c "ECC, Encrypt, no_reopen, SSec, pwd, no_switch, ch_leaks" --html`
open the file `output/trace1.pdf`
The attack is found and reconstructed in less than 20s.

§5.6 Risk of Signature Oracle:
 - `$ python3 opcua.py -q "Conf[Pwd]" -c "ECC, None, no_reopen, SNoAA, pwd, no_switch, lt_leaks" --oracle --html`
open the file `output/trace1.pdf`
The attack is found and reconstructed in less than 32m.
`--oracle` indicates that the client certificate is not parsed (leading to the signature oracle), as tolerated by the OPC-UA specification for "No Application Authentication" in version 1.05.03.


# To reproduce the security proofs for our fixes

We illustrate here how to launch Proverif on some representative configurations proving the absence of attacks. For a complete description of our results, see the file `results.md`.

Verification times are indicative and may vary depending on your machine.

##  For the weakened property Agr-[S->C]
Property "3.1" refers to the weakened Agr-[S->C] (to tolerate the KCI attack and race condition.)
As explained in the paper, we use a series of lemmas and advanced techniques that depend on the set of sub-lemmas that need to be proven.
As a result, one need to prove the following queries: "3.1.axioms", "3.1.axioms.1", "3.1.A", "3.1.B", "3.1.D", "3.1.E", and finally "3.1" that relies on all of those other lemmas. (Note that "3.1.C" is a syntactic axiom.)

Proofs for this property requires to first prove a number of lemmas that we assume (axioms) during the proof of the weakened Agr[S->C].
 - `$ python3 opcua.py -q "3.1.axioms" -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (5s)
 - `$ python3 opcua.py -q "3.1.axioms.1" -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (5s)
 - `$ python3 opcua.py -q "3.1.A" -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (5s)
 - `$ python3 opcua.py -q "3.1.B" -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (1m)
 - `$ python3 opcua.py -q "3.1.D" -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (5s)
 - `$ python3 opcua.py -q "3.1.E" -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (1m)
 - `$ python3 opcua.py -q "3.1"   -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (1m)
As we are able to prove this main query "3.1" corresponding to Agr-[S->C], we show that our fixes resolve the attack that was found in the same configurations. Other configurations can be proven too (see `results.md`).

##  For the weakened property Agr-[C->S]
Similarly, the query "3.2" relies on "3.2.axioms", "3.2.A" and all "3.1.*" queries discussed above.
One should launch:
 - `$ python3 opcua.py -q "3.2.axioms" -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (5s)
 - `$ python3 opcua.py -q "3.2.A"   -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (5s)
 - `$ python3 opcua.py -q "3.2"   -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (2m)
As we are able to prove this main query "3.2" corresponding to Agr-[C->S], we show that our fixes resolve the attack that was found in the same configurations. Other configurations can be proven too (see `results.md`).

## For the property Conf[C]:
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

## For the property Conf[Pwd]:
Configuration with long-term key leaks, but no channel leaks:
 - `$ python3 opcua.py -q "Conf[Pwd]" -c "ECC, Encrypt, no_reopen, SSec, pwd, no_switch, lt_leaks"` (1s)
Password confidentiality when no signature oracle is allowed (i.e., we enforce parsing of certificates even when SessionSecurity includes SNoAA):
 - `$ python3 opcua.py -q "Conf[Pwd]" -c "ECC, None, reopen, SNoAA|SSec, pwd, switch, lt_leaks"`: (3s)
 - `$ python3 opcua.py -q "Conf[Pwd]" -c "RSA|ECC, None|Sign|Encrypt, reopen, SNoAA, pwd, switch, no_leaks"` (24s)
In a subset of this configuration an attack was found using `--oracle`. The version 1.05.04 RC with our fix to the signature oracle attack is obtained without `--oracle` and can be proven secure with the command just above.


# Instructions to launch lattice exploration campaigns

## To launch a new campaign:
Use the `prove.sh` script, for example:
 - `$ ./prove.sh "Conf[C]" "RSA, None|Sign|Encrypt, reopen, SNoAA|SSec, anon|pwd|cert, switch, lt_leaks"`
Note that by default prove.sh uses the "--git" option of prove.py to get the commit number. If you are not on Git, remove the "-g" options in prove.sh.

## To restart from a previous campaign:
Locate a **completed** log file produced by a previous campaign, for example `query_Conf[C]_2560.txt` (`2560` indicates the timeout used at this step) and use the `prove.sh` script as follows (`5120` the timeout for the first step of this campaign, here we just double the timeout):
 - `$ ./prove.sh "Conf[C]" "RSA, None|Sign|Encrypt, reopen, SNoAA|SSec, anon|pwd|cert, switch, lt_leaks" 5120 "query_Conf[C]_2560.txt"`