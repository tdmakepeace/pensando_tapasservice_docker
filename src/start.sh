#!/bin/bash
#Created by Toby Makepeace - toby@pensando.io
#
DIR=/app/PenTapasaService
FILE=/app/PenTapasaService/variables.py
FILE2=/app/PenTapasaService/version.txt
FILE3=/app/src/version.txt
if [ -d "$DIR" ] 
    then
    if [ ! -f "$FILE" ]
        then
        service mysql start ; mysql < /app/src/db/PenTapasaService.sql 
        sleep 5s
        service mysql stop 
        mv /var/lib/mysql/TapAsAService /app/PenTapasaService
        ln -s /app/PenTapasaService/TapAsAService /var/lib/mysql/TapAsAService
	chmod 777 /app/PenTapasaService
        echo '[mysqld]' >> /etc/mysql/my.cnf
        echo 'bind-address = 0.0.0.0' >> /etc/mysql/my.cnf
        echo 'socket = /var/lib/mysql/mysql.sock' >> /etc/mysql/my.cnf
        sleep 5s
        service mysql start
	sleep 5s
	python3 /app/src/TapasaService.py > /app/PenTapasaService/debug.txt  2>&1
	mv /app/src/variables.py /app/PenTapasaService/variables.py
	ln -s /app/PenTapasaService/variables.py /app/src/variables.py
	sleep 5s
	cp $FILE3 $FILE2
	echo 'Fresh Install' > /app/PenTapasaService/debug.txt
	python3 /app/src/TapasaService.py >> /app/PenTapasaService/debug.txt  2>&1
    else
	if [ ! -f "$FILE2" ]
		then
			cp $FILE3 $FILE2
			service mysql start ; mysql < /app/src/db/PenTapasaService.sql 
			sleep 5s
			service mysql stop 
			sleep 5s
			rm -R /var/lib/mysql/TapAsAService
			sleep 5s
			ln -s /app/PenTapasaService/TapAsAService /var/lib/mysql/TapAsAService
			ln -s /app/PenTapasaService/variables.py /app/src/variables.py
			chmod 777 /app/PenTapasaService
			echo '[mysqld]' >> /etc/mysql/my.cnf
			echo 'bind-address = 0.0.0.0' >> /etc/mysql/my.cnf
			echo 'socket = /var/lib/mysql/mysql.sock' >> /etc/mysql/my.cnf
			sleep 5s
			service mysql start
			sleep 15s
			echo 'Forced Upgrade' > /app/PenTapasaService/debug.txt
			python3 /app/src/TapasaService.py >> /app/PenTapasaService/debug.txt  2>&1
	else
			OUT2=$(awk '{ print $1 }' $FILE2)
			OUT3=$(awk '{ print $1 }' $FILE3)
			if [ $OUT3 -gt $OUT2 ]
				then
					cp $FILE3 $FILE2
					service mysql start ; mysql < /app/src/db/PenTapasaService.sql 
					sleep 5s
					service mysql stop 
					sleep 5s
					rm -R /var/lib/mysql/TapAsAService
					sleep 5s
					ln -s /app/PenTapasaService/TapAsAService /var/lib/mysql/TapAsAService
					ln -s /app/PenTapasaService/variables.py /app/src/variables.py
					chmod 777 /app/PenTapasaService
					echo '[mysqld]' >> /etc/mysql/my.cnf
					echo 'bind-address = 0.0.0.0' >> /etc/mysql/my.cnf
					echo 'socket = /var/lib/mysql/mysql.sock' >> /etc/mysql/my.cnf
					sleep 15s
					service mysql start
					sleep 15s
					echo 'Planned Upgrade' > /app/PenTapasaService/debug.txt
					python3 /app/src/TapasaService.py >> /app/PenTapasaService/debug.txt  2>&1
			else
					service mysql start
					sleep 15s
					echo 'Restart' > /app/PenTapasaService/debug.txt
					python3 /app/src/TapasaService.py >> /app/PenTapasaService/debug.txt  2>&1
			fi
	fi
    fi

    # python3 /app/src/TapasaService.py > /dev/null  2>&1
fi





