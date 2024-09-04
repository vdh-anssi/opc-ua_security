A Formal Security Analysis of OPC-UA.
=====================================

This file gives detailed instruction to:
 - find the attacks described in the paper with Proverif, and get detailed views as PDF files.
 - verify the maximal true configurations of the properties, well conditioned to circumvent the known weaknesses.


# To observe the attacks described in the paper: #
You need to install Proverif: https://bblanche.gitlabpages.inria.fr/proverif/ and make it available from the command line.
You also need python 3.11 with Jinja2 (https://pypi.org/project/Jinja2/), to run the tool "opcua.py", that will generate the input files and launch proverif.
`$ pip install jinja2`

The following tests where made with Proverif version 2.05, on a Linux 6.8 running on Intel(R) Core(TM) i7 CPU @ 1.8 GHz, with 16 GB of RAM.

`$ python3 opcua.py -q "Agr[S->C]" -u -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks" --not_fixed --html`
§5.2 KCI attack: open the file `output/trace1.pdf`
§5.3 ECC client impersonation attack: open the file `output/trace2.pdf`
The attacks are found and reconstructed in 46s.

`$ python3 opcua.py -q "Agr[S->C]" -c "ECC, Encrypt, no_reopen, SSec, cert, no_switch, no_leaks" --html`
§5.4 Race condition for user contexts: open the file `output/trace1.pdf`
The attack is found and reconstructed in 44s. It can also be found with the following configurations:
"RSA, Encrypt, no_reopen, SSec, cert, no_switch, no_leaks" (43s)
"RSA, Sign,    no_reopen, SSec, cert, no_switch, no_leaks" (32s)
"RSA, Sign,    no_reopen, SSec, pwd,  no_switch, no_leaks" (30s)
etc.

`$ python3 opcua.py -q "Conf[Pwd]" -c "ECC, Encrypt, no_reopen, SSec, pwd, no_switch, ch_leaks" --html`
§5.5 Downgrade of password secrecy: open the file `output/trace1.pdf`
The attack is found and reconstructed in 1m. It can also be found with the following configuration:
"ECC, Encrypt, no_reopen, SNoAA, pwd, no_switch, ch_leaks" (2m)
"RSA, Encrypt, no_reopen, SSec,  pwd, no_switch, ch_leaks" (18s)
"RSA, Encrypt, no_reopen, SNoAA, pwd, no_switch, ch_leaks" (12s)

`$ python3 opcua.py -q "Conf[Pwd]" -c "ECC, None, no_reopen, SNoAA, pwd, no_switch, lt_leaks" --oracle --html`
§5.6 Risk of Signature Oracle: open the file `output/trace1.pdf`
The attack is found and reconstructed in 40m.


# To prove the main properties: #
You need to build the development version of ProVerif, from the sources on branch "improved_scope_lemma":
`$ git clone https://gitlab.inria.fr/bblanche/proverif.git`
`$ cd proverif/proverif`
`$ git checkout improved_scope_lemma`
`$ ./build`
`$ ./proverif --help`

Now make the proverif executable directly available from the command line, and rename it as proverif-dev so that the tool opcua.py
can find it, when called with flag "--development" (or "-d"). For instance using:
`$ sudo cp proverif /usr/local/bin/proverif-dev`
or
`cp proverif ~/.local/bin/proverif-dev`
The tools prove.py and the script prove-dev.sh both call opcua.py with the flag "--development" set.

We present here some results to show how to launch Proverif on our model and that the main attacks are corrected. For a complete description of our results, see the file results.md.
The following tests where made with Proverif development, commit 6a803aa13ccde13c0574912da93f029f86f63951 of the 23rd of July 2024,
on a Linux 5.15 running on Intel(R) Xeon(R) CPU @ 3.1 GHz, with 400 GB of RAM.


## For property Conf[C]:
We have all configurations without "switch":
`$ python3 opcua.py -q "Conf[C]" -c "RSA|ECC, None|Sign|Encrypt, reopen, SNoAA|SSec, anon|pwd|cert, no_switch, lt_leaks" --dev` True 25m
For RSA, we also have "switch":
`$ python3 opcua.py -q "Conf[C]" -c "RSA, None|Sign|Encrypt, reopen, SNoAA|SSec, anon|pwd|cert, switch, lt_leaks" --dev` True 02m
For ECC, we have switch only without any leak:
`$ python3 opcua.py -q "Conf[C]" -c "ECC, None|Sign|Encrypt, reopen, SNoAA|SSec, anon|pwd|cert, switch, no_leaks" --dev` True 35s

## For property Conf[S]:
`$ python3 opcua.py -q "Conf[S]" -c "RSA|ECC, None|Sign|Encrypt, reopen, SNoAA|SSec, anon|pwd|cert, no_switch, lt_leaks" --dev` True 30m
For RSA, we also have "switch":
`$ python3 opcua.py -q "Conf[S]" -c "RSA, None|Sign|Encrypt, reopen, SNoAA|SSec, anon|pwd|cert, switch, lt_leaks" --dev` True 14m
For ECC, we have switch only without any leak:
`$ python3 opcua.py -q "Conf[S]" -c "ECC, Sign|Encrypt, reopen, SNoAA|SSec, anon|pwd|cert, switch, no_leaks" --dev` True 36s

## For property Conf[Pwd]:
If no leaks of channel keys:
`$ python3 opcua.py -q "Conf[Pwd]" -c "ECC, Encrypt, no_reopen, SSec, pwd, no_switch, lt_leaks"` True 3s.
If no signature oracle:
`$ python3 opcua.py -q "Conf[Pwd]" -c "ECC, None, reopen, SNoAA|SSec, pwd, switch, lt_leaks"`: True 10s
Mode None offers no security whatsoever to a session, so we may avoid it.
Option SSec offers strictly more checks on client certificates, so we may have more attacks on SNoAA.
`$ python3 opcua.py -q "Conf[Pwd]" -c "RSA|ECC, Sign|Encrypt, reopen, SNoAA, pwd, no_switch, lt_leaks" --dev`
`$ python3 opcua.py -q "Conf[Pwd]" -c "RSA|ECC, Sign|Encrypt, reopen, SNoAA, pwd, switch, no_leaks" --dev` True 8s

Property Agr[S->C] cannot be proved because it suffers from 2 weaknesses explained above: i.e.,
the race condition of user contexts and the KCI attack. Note that the ECC impersonation attack
has been fixed.
So we provide query 3.1 that circumvent these weaknesses and still gives strong
security guaranties, yet with a weaker threat model. See the file "opcua.pv" for details.
To prove it, one needs to first prove all required lemmas and then take them as axioms.
`$ python3 opcua.py -q "3.1.axioms" -c "RSA|ECC, None|Sign|Encrypt, reopen, SNoAA|SSec, anon|pwd|cert, no_switch, lt_leaks" --dev`
`$ python3 opcua.py -q "3.1.A" -c "RSA|ECC, None|Sign|Encrypt, reopen, SNoAA|SSec, anon|pwd|cert, no_switch, lt_leaks" --dev`
`$ python3 opcua.py -q "3.1.C" -c "RSA|ECC, None|Sign|Encrypt, reopen, SNoAA|SSec, anon|pwd|cert, no_switch, lt_leaks" --dev`
`$ python3 opcua.py -q "3.1.B" -c "RSA|ECC, None|Sign|Encrypt, reopen, SNoAA|SSec, anon|pwd|cert, no_switch, lt_leaks" --dev`
`$ python3 opcua.py -q "3.1.D" -c "RSA|ECC, None|Sign|Encrypt, reopen, SNoAA|SSec, anon|pwd|cert, no_switch, lt_leaks" --dev`
`$ python3 opcua.py -q "3.1.E" -c "RSA|ECC, None|Sign|Encrypt, reopen, SNoAA|SSec, anon|pwd|cert, no_switch, lt_leaks" --dev`
`$ python3 opcua.py -q "3.1"   -c "RSA|ECC, None|Sign|Encrypt, reopen, SNoAA|SSec, anon|pwd|cert, no_switch, lt_leaks" --dev`

Property Agr[C->S] cannot be proved because it suffers from weaknesses.
ECC impersonation attack. So we provide query 3.2 that circumvent these weaknesses, see the file "opcua.pv" for details.
`$ python3 opcua.py -q "3.2.axioms" -c "RSA|ECC, None|Sign|Encrypt, reopen, SNoAA|SSec, anon|pwd|cert, no_switch, lt_leaks" --dev`
`$ python3 opcua.py -q "3.2"   -c "RSA|ECC, None|Sign|Encrypt, reopen, SNoAA|SSec, anon|pwd|cert, no_switch, lt_leaks" --dev`

# To launch a new campaign:
`$ ./prove.sh "Conf[C]" "RSA, None|Sign|Encrypt, reopen, SNoAA|SSec, anon|pwd|cert, switch, lt_leaks"`
Note that by default prove.sh uses the "--git" option of prove.py to get the commit number. If you are not on Git, remove the "-g" options in prove.sh.

# To restart from a previous campaign:
`$ ./prove.sh "Conf[C]" "RSA, None|Sign|Encrypt, reopen, SNoAA|SSec, anon|pwd|cert, switch, lt_leaks" 5120 "query_Conf[C]_2560.txt"`
