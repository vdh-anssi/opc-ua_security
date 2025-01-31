A Formal Security Analysis of OPC UA.
=====================================

This file describes the companion artifact of the USENIX Security 2025 paper of V. Diemunsch, L. Hirschi, and S. Kremer.
Full version of this paper on IACR eprint at https://eprint.iacr.org/2025/148.

It gives detailed instructions on how to use ProVerif to:
 - find attacks and get detailed attack traces as PDF files
 - prove that our fixes provably repair the protocols for the configurations for which we found the attacks
 - prove the properties in the fixed variant for further configurations
 - launch lattice exploration campaigns.


# License

GNU General Public License v3 (see file `LICENCE.md` and https://www.gnu.org/licenses/gpl-3.0.html).


# Installation

You need to build the development version of ProVerif, from the sources on branch "improved_scope_lemma" (this requires a working OCaml compiler, see https://ocaml.org/):
 - `$ git clone https://gitlab.inria.fr/bblanche/proverif.git`
 - `$ cd proverif/proverif`
 - `$ git checkout improved_scope_lemma`
 - `$ git checkout 6a803aa13ccde13c0574912da93f029f86f63951`
 - `$ ./build`
 - `$ ./proverif --help`

Results in this file have been obtained with Proverif development, branch improved_scope_lemma, commit 6a803aa13ccde13c0574912da93f029f86f63951. The branch improved_scope_lemma has been previously used in 
> Vincent Cheval, Véronique Cortier and Alexandre Debant. "Election Verifiability with ProVerif." IEEE 36th Computer Security Foundations Symposium (CSF). 2023.

Make sure that the proverif executable is in your path and available from the command line.
You also need Python 3.11 (or above) with Jinja2 (https://pypi.org/project/Jinja2/), to run the tool "opcua.py", that generates the input files and launch proverif.
 - `$ pip install jinja2`


# To reproduce the automatic attack finding described in the paper

These experiments have been conducted on a standard laptop with 15 GiB or RAM (except query 3.1.B that requires at least 30 GiB in ECC).

§5.1 Race condition for user contexts breaking Agr[S->C]:
 - `$ python3 opcua.py -q "3.1.race" -c "ECC, Encrypt, no_reopen, SSec, cert, no_switch, no_leaks" --html`
"3.1.race" is the initial Agr[S->C] property discussed in the paper.
`--not_fixed` indicates that the server's thumbprint is not included in ECC mode.
`-c` specifies the configuration.
The attack is found and reconstructed in less than 10s, and depicted in the file `output/trace1.pdf`.
This scenario is very close to the one described in the paper in §5.1 and illustrated in eprint Appendix §C.1, Figure 11.

§5.1 Race condition for user contexts breaking Agr[C->S]:
 - `$ python3 opcua.py -q "3.2.race" -c "ECC, Encrypt, no_reopen, SSec, cert, no_switch, no_leaks" --html`
"3.2.race" is the initial Agr[C->S] property discussed in the paper.
The attack is found and reconstructed in less than 10s, and depicted in the file `output/trace1.pdf`.
This scenario is mentioned in the eprint in Appendix §C.1 as an adaptation of the previous attack but on user responses.

§5.2 ECC client impersonation attack:
- `$ python3 opcua.py -q "3.1" -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks" --html --not_fixed`
"3.1" is Agr-[S->C], weakened to tolerate race conditions and KCI attacks.
The attack is found and reconstructed in less than 10s, and depicted in the file `output/trace1.pdf`.
This scenario is very close to the one described in the paper in §5.2 and illustrated in Figure 5 and in eprint Appendix §C.2, Figure 12.
See below how we can establish a security proof for Agr-[S->C] when our fix is used.

§5.3 KCI User Impersonation attack:
- `$ python3 opcua.py -q "3.1.KCI_UI" -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks" --html`
The attack is found and reconstructed in less than 5s, and depicted in the file `output/trace1.pdf`.
This scenario is very close to the one described in the paper in §5.3 and illustrated in Figure 6.

§5.4 Session hijack by reopening:
- `$ python3 opcua.py -q "3.1.reopen" -c "ECC, Sign, reopen, SSec, cert, no_switch, lt_leaks" --html`
The attack is found and reconstructed in less than 30m, and depicted in the file `output/trace1.pdf`.
(In RSA, it takes only 50s, and it is depicted in the file `output/trace2.pdf`).
This scenario is very close to the one described in the paper in §5.4 and illustrated in Figure 7.

§5.5 KCI session and user confusion:
- `$ python3 opcua.py -q "3.1.confusion" -c "RSA, Encrypt, reopen, SSec, cert, no_switch, lt_leaks" --html --no_reconstruction`
The attack is found in less than 03s, but Proverif cannot reconstruct it and terminates with "cannot be proved".
In the file `output/index.html`, a reachable goal shows that Proverif is able to construct a clause that contradicts the query:
 - the server has received a user request "C_val_4" in a session called "s_2" authenticated by "SAtoken_13", that is currently hold by user "usr_7"
 - the client has sent the same user request "C_val_4", but in a session called "id_131" also authenticated by "SAtoken_13", for a user called "usr_8"
The "Derivation" (file `output/derivation1.html`) shows that:
 - "SAtoken_13" was given by the client to the attacker, that impersonated the compromised server (thanks to the leak of the server secret key S_sk_3), through a legitimate activation request for a user "usr_9". (It could have been any request in fact).
 - "usr_8" is not known to the server and does not appear in any derivation of a server event.
This scenario is very close to the one described in the paper in §5.5 and illustrated in Figure 8.

§5.6 Downgrade of password secrecy:
 - `$ python3 opcua.py -q "Conf[Pwd]" -c "ECC, Encrypt, no_reopen, SSec, pwd, no_switch, ch_leaks" --html`
The attack is found and reconstructed in less than 25s, and depicted in the file `output/trace1.pdf`.
This scenario is mentioned in the paper in §5.6 in the eprint in Appendix §C.4.1.
Note that the property is true in mode "Sign" instead of "Encrypt".

§5.6 Risk of Signature Oracle:
 - `$ python3 opcua.py -q "Conf[Pwd]" -c "ECC, None, no_reopen, SNoAA, pwd, no_switch, lt_leaks" --oracle --html`
`--oracle` indicates that the client certificate is not parsed (leading to the signature oracle), as tolerated by the OPC UA specification for "No Application Authentication" in version 1.05.03.
The attack is found and reconstructed in less than 25m, and depicted in the file `output/trace1.pdf`.
It shows an attack against the user password that is made through the use of the Signature Oracle, when No Application Authentication (SNoAA) is used.
The Signature Oracle is mentioned in the paper in §5.6, described in eprint Appendix §B.6.2 and illustrated in Figure 14.
Note that the security property Conf[Pwd] is true when our fix is used, i.e. when no signature oracle is allowed (without `--oracle`).


# To reproduce the security proofs for our fixes

We illustrate here how to launch Proverif on some representative configurations proving the absence of attacks. For a complete description of our results, see the file `results.md`.

Verification times are indicative and may vary depending on your machine.

##  For the weakened property Agr-[S->C]
Property "3.1" refers to the weakened Agr-[S->C] (to tolerate the KCI attacks and race condition).
As explained in the paper, we use a series of lemmas and advanced techniques that depend on the set of sub-lemmas that need to be proven.
As mentioned in the file `dependencies.txt`, one needs to prove the following queries: "3.1.axioms", "3.1.axioms.1", "3.1.conf", "3.1.A", "3.1.B", "3.1.C", "3.1.D", "3.1.E", and finally "3.1" that relies on all of those other lemmas.

Proofs for this property requires to first prove a number of lemmas that we assume (axioms) during the proof of the weakened Agr[S->C].
 - `$ python3 opcua.py -q "3.1.axioms"   -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (8s)
 - `$ python3 opcua.py -q "3.1.axioms.1" -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (1s)
 - `$ python3 opcua.py -q "3.1.conf"     -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (1s)
 - `$ python3 opcua.py -q "3.1.A"        -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (1m)
 - `$ python3 opcua.py -q "3.1.B"        -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (23h and > 30 GiB)
 - `$ python3 opcua.py -q "3.1.C"        -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (1s)
 - `$ python3 opcua.py -q "3.1.D"        -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (4s)
 - `$ python3 opcua.py -q "3.1.E"        -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (1m)
 - `$ python3 opcua.py -q "3.1"          -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks"` (30s)
As we are able to prove this main query "3.1" corresponding to Agr-[S->C], we show that our fixes resolve the attack that was found in the same configurations (see above §5.2 ECC client impersonation attack with "--not_fixed"). Other configurations can be proven too (see `results.md`).

##  For the weakened property Agr-[C->S]
Similarly, the query "3.2" relies on "3.2.axioms", "3.2.A", but also on "3.1.A" and "3.1.C", two of the lemmas above.
One should launch:
 - `$ python3 opcua.py -q "3.1.A"      -c "ECC, Encrypt, no_reopen, SSec, cert, no_switch, lt_leaks"` (1m)
 - `$ python3 opcua.py -q "3.1.C"      -c "ECC, Encrypt, no_reopen, SSec, cert, no_switch, lt_leaks"` (1s)
 - `$ python3 opcua.py -q "3.2.axioms" -c "ECC, Encrypt, no_reopen, SSec, cert, no_switch, lt_leaks"` (2s)
 - `$ python3 opcua.py -q "3.2.A"      -c "ECC, Encrypt, no_reopen, SSec, cert, no_switch, lt_leaks"` (1s)
 - `$ python3 opcua.py -q "3.2"        -c "ECC, Encrypt, no_reopen, SSec, cert, no_switch, lt_leaks"` (8s)
As we are able to prove this main query "3.2" corresponding to Agr-[C->S]. Other configurations can be proven too (see `results.md`).

## For the property Conf[Pwd]:
Password confidentiality when no signature oracle is allowed (i.e., we enforce parsing of certificates even when SessionSecurity includes SNoAA):
 - `$ python3 opcua.py -q "Conf[Pwd]" -c "ECC, None, reopen, SNoAA|SSec, pwd, switch, lt_leaks"`: (1m)
 - `$ python3 opcua.py -q "Conf[Pwd]" -c "RSA|ECC, None|Sign|Encrypt, reopen, SNoAA|SSec, pwd, switch, no_leaks"` (2m)
In a subset of this configuration an attack was found using `--oracle` (see §5.6 Risk of Signature Oracle).
The version 1.05.04 RC with our fix to the signature oracle attack is obtained without `--oracle` and can be proved secure with the command just above.


# Instructions to launch lattice exploration campaigns

## To launch a new campaign:
Use the `prove.sh` script, for example:
 - `$ ./prove.sh "Conf[C]" "RSA, None|Sign|Encrypt, reopen, SNoAA|SSec, anon|pwd|cert, switch, lt_leaks"`
Note that by default prove.sh uses the "--git" option of prove.py to get the commit number. If you are not on Git, remove the "-g" options in prove.sh.

## To restart from a previous campaign:
Locate a **completed** log file produced by a previous campaign, for example `query_Conf[C]_2560.txt` (`2560` indicates the timeout used at this step) and use the `prove.sh` script as follows (`5120` the timeout for the first step of this campaign, here we just double the timeout):
 - `$ ./prove.sh "Conf[C]" "RSA, None|Sign|Encrypt, reopen, SNoAA|SSec, anon|pwd|cert, switch, lt_leaks" 5120 "query_Conf[C]_2560.txt"`