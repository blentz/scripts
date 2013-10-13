#!/bin/sh
# check SMART of all disks in system
BASENAME=$(dirname $0)
. ${BASENAME}/functions.sh
PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin:/home/zabbix/bin
RES=""
ME="disksmart_check"
TIMEOUT=600
ERRLOG_COUNT_THRESHOLD=100
if [ `which smartctl >/dev/null; echo $?` -ne 0 ]; then
	echo "no smartctl"
	exit 1
fi

checkSmartExitStatus()
{
	STATUS=$1
#if [ $(($STATUS & 1<<0)) -gt 0 ]; then echo "Command line did not parse"; fi
#	if [ $(($STATUS & 1<<1)) -gt 0 ]; then echo "Device open failed"; fi
	if [ $(($STATUS & 1<<2)) -gt 0 ]; then echo "Some command to the disk failed, or there was a checksum error in a SMART data structure"; fi
	if [ $(($STATUS & 1<<3)) -gt 0 ]; then echo "DISK FAILING"; fi
	if [ $(($STATUS & 1<<4)) -gt 0 ]; then echo "found prefail Attr <= threshold"; fi
#	if [ $(($STATUS & 1<<5)) -gt 0 ]; then echo "Some attributes have been <= threshold at some time in the past"; fi
	if [ $(($STATUS & 1<<7)) -gt 0 ]; then echo "self-test log contains records of errors"; fi
}


CACHE=`getFromCache "$ME" $TIMEOUT`
if [ -z "$CACHE" ]; then
	
	lockf ${ME} 15
	[ $? -eq 0 ] || exit  # unable to get lockfile
	DISKS="`sudo smartctl --scan-open`"
	if [ $? -ne 0 ]; then  # old smartctl
		if [ `uname` = "Linux" ]; then
			DISKS="`ls -1 /dev/ | grep -E '^sd[a-z]$' 2>/dev/null | sed 's|^|/dev/|' | sed 's|$|,|'`"
		elif [ `uname` = "FreeBSD" ]; then
			DISKS="`ls -1 /dev/ | grep -E '^(ad[0-9]+|da[0-9]+|ada[0-9]+)$' 2>/dev/null | sed 's|^|/dev/|' | sed 's|$|,|'`"
		fi
	else
		DISKS="`echo \"$DISKS\" | sed 's|\ [\#\[].*|,|'`"
	fi
	OIFS="${IFS}"
	NIFS=$","
	 
	IFS="${NIFS}"

	for DISK in ${DISKS}; do
		IFS='${OIFS}'
		if [ -z "$DISK" ]; then 
			continue
		fi
		DISK=${DISK%%\#*}
		DISK=${DISK%-*}
		DISK=`echo $DISK| xargs`
		sudo smartctl -q silent -a $DISK 2>/dev/null
		SMARTSTATUS=$?
		ERRLOG_COUNT=0
		if [ $SMARTSTATUS -ne 0 ]; then
			SMARTSTR=`checkSmartExitStatus \$SMARTSTATUS`
			if [ $((${SMARTSTATUS} & 1<<2)) -gt 0 ]; then
				sudo smartctl -a $DISK 2>/dev/null | grep -qE '(Vendor.*VMware|Vendor.*SUPER|Device.*DELL|device.*CD/DVD|Device.*processor|Device.*enclosure|Product.*Array|Virtual.*disk)'
				if [ $? -eq 0 ]; then
					continue
				fi
				sudo smartctl -i -A -l error -l selftest $DISK 2>/dev/null 1>/dev/null  # try without health check
				if [ $? -eq 0 ]; then
					continue
				fi
			fi
			if [ $((${SMARTSTATUS} & 1<<6)) -gt 0 ]; then
				SMARTSTR="ton of errors in log"
				ERRLOG_COUNT="`sudo smartctl -l error $DISK 2>/dev/null | grep Error\ Count`"
				ERRLOG_COUNT=${ERRLOG_COUNT##*: }
				ERRLOG_COUNT=${ERRLOG_COUNT%% *}
			fi
			if [ -n "${SMARTSTR}" -o \( ${ERRLOG_COUNT} -gt ${ERRLOG_COUNT_THRESHOLD} \) ]; then
				RES="${RES}${DISK} ${SMARTSTR}
"			
			fi
		fi
		IFS="${NIFS}"
	done
	IFS="${OIFS}"
	if [ -z "$RES" ]; then
		RES="OK"
	fi

	writeToCache "$ME" "$RES" 
	unlockf $ME
else
	RES=${CACHE}
fi

echo "$RES" | tr -s "\n\n" "\n"
