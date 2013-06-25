#!/usr/bin/env python
import subprocess

def ping(host):
    result = subprocess.call(["ping","-c","1",host],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    if result == 0:
        return True
    else:
	return False


print ping("www.google.dssdefe")
