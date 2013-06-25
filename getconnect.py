#!/usr/bin/env python

#############
# LIBRARIES #
#############

import subprocess
import os
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import sqlite3 as lite
import time


from subprocess import call
from sys import argv          # Command-line arguments
from sys import stdout, stdin # Flushing
#from scapy.all import *

###########################
#     VARS AND INIT       #
###########################

debug = 0
version = 0.1


DN = open(os.devnull, 'w')
ap_list = []
 

###########################
#     DB CONNECTION       #
###########################
try:
    con = lite.connect('accesspoints.db')
    
    cur = con.cursor()    
               
    
except lite.Error, e:
    
    print "Error %s:" % e.args[0]
    sys.exit(1)


###########################
# WIRELESS CARD FUNCTIONS #
###########################


def enable_monitor_mode(iface):
        call(['airmon-ng', 'start', iface], stdout=DN, stderr=DN)


def disable_monitor_mode():
        call(['airmon-ng', 'stop', 'mon0'], stdout=DN, stderr=DN)


def PacketHandler(pkt) :
	if pkt.haslayer(Dot11) :
		if pkt.type == 0 and pkt.subtype == 8 :
			if pkt.addr2 not in ap_list :
				ap_list.append(pkt)
				if debug: print "AP MAC: %s with SSID: %s " %(pkt.addr2, pkt.info)


def ping(host):
    result = subprocess.call(["ping","-c","1",host],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    if result == 0:
        return True
    else:
	return False

def connectAP(ssid,key):
	call(['uci set wireless.@wifi-iface[0].encryption=psk2'], stdout=DN, stderr=DN)
	call(['uci set wireless.@wifi-iface[0].ssid='+ssid], stdout=DN, stderr=DN)
	call(['uci set wireless.@wifi-iface[0].key='+key], stdout=DN, stderr=DN)
	call(['uci commit wireless'])
	call(['wifi'])


def parseAP(aplist):
    return aplist

def printDB_AP():
    with con:
        con.row_factory = lite.Row

        cur = con.cursor() 
        cur.execute("SELECT * FROM accesspoints")
        rows = cur.fetchall()

        for row in rows:
            print "%s MAC=%s KEY=%s" % (row["SSID"], row["MAC"], row["KEY"])

def getSQLVersion():
    cur.execute('SELECT SQLITE_VERSION()')
    data = cur.fetchone()
    return data 

###########################
#      MAIN PROGRAM       #
###########################



print "Script version: %s" % version
print "SQLite version: %s" % getSQLVersion()

#enable_monitor_mode('eth1')
#sniff(iface="mon0", prn = PacketHandler)

#wait for aps
time.sleep(10)
print('APs found: %d' %len(ap_list))

#printDB_AP()




#print ping("www.google.dssdefe")



