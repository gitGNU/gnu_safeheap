#!/bin/sh
# Author: Ravi Sankar Guntur <ravi.g@samsung.com>
# Date: 8 th June 2010
echo "starting safeheap sanity test cases.."
echo "......."
COUNTER=1
while [  $COUNTER -lt 37 ]; do
#	echo Running test case id tcp$COUNTER
	run-with-safeheap.sh ./tcp$COUNTER
	if [ $? -eq 0 ] ; then
		echo tcp$COUNTER: pass
	else
		echo tcp$COUNTER: fail
		exit $?
	fi
        COUNTER=`expr $COUNTER + 1`
	sleep 1	
done
# execute ls
run-with-safeheap.sh ls
if [ $? -eq 0 ]; then 
	echo "ls command test: pass"
else
	echo "ls command test:  fail"
	exit $?
fi
sleep 1

# execute date
run-with-safeheap.sh date
if [ $? -eq 0 ]; then 
	echo "date command test: pass"
else
	echo "date command test:  fail"
	exit $?
fi
sleep 1

# execute clear
run-with-safeheap.sh clear
if [ $? -eq 0 ]; then 
	echo "clear command test: pass"
else
	echo "clear command test:  fail"
	exit $?
fi
sleep 1

# execute top. on H2 top returns 1 on success. On Aquila 0
run-with-safeheap.sh top -n 10
sleep 1
 
COUNTER=51
while [  $COUNTER -lt 85 ]; do
#	echo Running test case id tcp$COUNTER
	run-with-safeheap.sh ./tcp$COUNTER
	if [ $? -eq 0 ] ; then
		echo tcp$COUNTER: pass
	else
		echo tcp$COUNTER: fail
		exit $?
	fi
        COUNTER=`expr $COUNTER + 1`
	sleep 1	
done

echo "################## Sanity test cases result: pass ......"

echo "starting safeheap error test cases.."
COUNTER=1
while [  $COUNTER -lt 188 ]; do
	run-with-safeheap.sh ./tcc$COUNTER
	if [ $? -ne 0 ] ; then
		echo tcc$COUNTER: pass
	else
		echo tcc$COUNTER: fail
		exit $?
	fi
        COUNTER=`expr $COUNTER + 1`
	sleep 1	
done
COUNTER=200
while [  $COUNTER -lt 230 ]; do
	run-with-safeheap.sh ./tcc$COUNTER
	if [ $? -ne 0 ] ; then
		echo tcc$COUNTER: pass
	else
		echo tcc$COUNTER: fail
		exit $?
	fi
        COUNTER=`expr $COUNTER + 1`
	sleep 1	
done
echo "################# Error test cases result: pass ......"

echo "starting warning test cases.."
COUNTER=1
while [  $COUNTER -lt 2 ]; do
#       echo Running test case id tcp$COUNTER
        run-with-safeheap.sh ./tcw$COUNTER
        if [ $? -eq 0 ] ; then
                echo tcw$COUNTER: pass
        else
                echo tcw$COUNTER: fail
                exit $?
        fi
        COUNTER=`expr $COUNTER + 1`
        sleep 1
done

echo "################# safeheap test cases result: pass #####################"
exit $?


