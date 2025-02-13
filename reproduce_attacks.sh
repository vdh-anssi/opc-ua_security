#!/bin/sh
echo "Launching all attacks finding...................."

echo "Attack on Agr[S->C]: Race"
python3 opcua.py -q "3.1.race" -c "ECC, Encrypt, no_reopen, SSec, cert, no_switch, no_leaks" --html;
mv output "output_Agr[S->C].race";

echo "Attack on Agr[C->S]: Race"
python3 opcua.py -q "3.2.race" -c "ECC, Encrypt, no_reopen, SSec, cert, no_switch, no_leaks" --html;
mv output "output_Agr[C->S].race";

echo "Attack on Agr-[S->C]: client_impersonation"
python3 opcua.py -q "3.1" -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks" --html --not_fixed;
mv output "output_Agr-[S->C].client_impersonation";

echo "Attack on Agr-[S->C]: KCI_UI"
python3 opcua.py -q "3.1.KCI_UI" -c "ECC, Encrypt, no_reopen, SNoAA, cert, no_switch, lt_leaks" --html;
mv output "output_Agr-[S->C].KCI_UI";

echo "Attack on Agr-[S->C]: session_hijack_reopen"
python3 opcua.py -q "3.1.reopen" -c "RSA, Sign, reopen, SSec, cert, no_switch, lt_leaks" --html;
mv output "output_Agr-[S->C].session_hijack_reopen";

echo "Attack on Agr-[S->C]: session_hijack_switch"
python3 opcua.py -q "3.1.reopen" -c "RSA, Sign, no_reopen, SSec, cert, switch, lt_leaks" --html;
mv output "output_Agr-[S->C].session_hijack_switch";

echo "Attack on Agr-[S->C]: KCI_confusion"
python3 opcua.py -q "3.1.confusion" -c "RSA, Encrypt, reopen, SSec, cert, no_switch, lt_leaks" --html --no_reconstruction;
mv output "output_Agr-[S->C].KCI_confusion";

echo "Attack on Conf[Pwd]: downgrade"
python3 opcua.py -q "Conf[Pwd]" -c "ECC, Encrypt, no_reopen, SSec, pwd, no_switch, ch_leaks" --html;
mv output "output_Conf[Pwd].downgrade";

echo "Attack sig_oracle"
python3 opcua.py -q "Conf[Pwd]" -c "ECC, None, no_reopen, SNoAA, pwd, no_switch, lt_leaks" --oracle --html;
mv output "output_sig_oracle"

echo "---------------- END, inspect the 'output_<attack>' folders ---------------------------"