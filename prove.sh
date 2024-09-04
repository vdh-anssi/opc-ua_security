#!/bin/bash
# usage ./prove.sh query configuration [timeout file]

if [ -z $3 ] # if timeout is unset
then
   t=5 # seconds
   python3.11 prove.py -g -q "$1" -c "$2" -t "$t" -p 20 | tee "query_$1_$t.txt"
else
   t=$3
   python3.11 prove.py -g -q "$1" -c "$2" -t "$t" -s "$4" -p 20 | tee "query_$1_$t.txt"
fi

u=0
while (( t <= 43200 )); # 43200s = 12h, timeout <= 24h.
do
   (( u = t * 2 ))
   python3.11 prove.py -g -q "$1" -c "$2" -t "$u" -s "query_$1_$t.txt" --skip -p 20 | tee "query_$1_$u.txt"
   (( t = u))
done
