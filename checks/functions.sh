#!/bin/sh

LOCKDIR="/tmp"
CACHEDIR=$LOCKDIR

getFromCache()
{
	CACHEFILE="$CACHEDIR/$1.cache"
	TIMEOUT="$2"
	CURRENTTIME="`date +%s`"
	if [ -s ${CACHEFILE} ]; then
		CACHEDATA=`cat ${CACHEFILE}`
		OLDDATATIME=${CACHEDATA%%,*}
		OLDDATA=${CACHEDATA#*,}

		if [ $OLDDATATIME -gt $((CURRENTTIME-TIMEOUT)) ]; then
			echo "$OLDDATA"
			return 0
		else
			return 1
		fi
	fi	
}

writeToCache()
{
	CACHEFILE="$CACHEDIR/$1.cache"
	DATA="$2"
	CURRENTTIME="`date +%s`"
	echo "$CURRENTTIME,$DATA" > "$CACHEFILE"
	[ "`id -u -n`" = "zabbix" ] || chown zabbix "$CACHEFILE"
	return 0
}

lockf()
{
	LOCKFILE="$LOCKDIR/$1.lock"
	if [ -n "$2" ]; then
		RETRY=$2
	else
		RETRY=1
	fi
	while [ $RETRY -gt 0 ]; do
		RETRY=`expr $RETRY - 1`
		if (set -o noclobber; echo "$$" > "$LOCKFILE") 2> /dev/null; then
			trap 'rm -f "$LOCKFILE"; exit $?' INT TERM EXIT
			return 0
		fi
		if [ -f "$LOCKFILE" ]; then
			kill -0 `cat "$LOCKFILE"` 1>/dev/null 2>&1
			if [ $? -ne 0 ]; then
				rm -f "$LOCKFILE" 
				if [ $? -ne 0 ]; then 
					echo "unable to remove lock"
					return 1
				fi
			fi
		fi
		sleep 1
	done
	echo "Locking failed. Held by $(cat $LOCKFILE)"
	return 1
}

unlockf()
{
	LOCKFILE="$LOCKDIR/$1.lock"
	rm -f "$LOCKFILE"
	trap - INT TERM EXIT
	return 0
}
