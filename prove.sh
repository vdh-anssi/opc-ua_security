#!/bin/bash
# usage ./prove.sh query configuration [timeout file]

if [ -z $3 ] # if timeout is unset
then
   t=5 # seconds
   python3 prove.py -g -q "$1" -c "$2" -t "$t" -p 20 | tee "query_$1_$t.txt"
else
   t=$3
   python3 prove.py -g -q "$1" -c "$2" -t "$t" -s "$4" -p 20 | tee "query_$1_$t.txt"
fi

u=0
while (( t <= 21600 )); # 43200s = 12h
do
   (( u = t * 2 ))
   python3 prove.py -g -q "$1" -c "$2" -t "$u" -s "query_$1_$t.txt" --skip -p 20 | tee "query_$1_$u.txt"
   (( t = u ))
done

# final run. May be very long, timeout <= 24h.
(( u = t * 2))
python3 prove.py -g -q "$1" -c "$2" -t "$u" -s "query_$1_$t.txt" --final -p 20 | tee "query_$1_$u.txt"
