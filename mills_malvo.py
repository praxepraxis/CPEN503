#!/usr/bin/env python
# ------------------------------------------
# 0713 MMXVI Gregorian AST UTC-0400
# ------------------------------------------
# Atelier-Velvet Corporation et alia
# Monserrate-Mills-Malvo 1.7 Attack 0.1
#
# Carro Cruz, Manuel Alberto
# Copyright 2016 Atelier-Velvet Corporation.
# -------------------------------------------
# Escuela de Ingenieria Jose Domingo Perez
# Sistema Universitario Ana G Mendez
# Universidad del Turabo
# CPEN 503: Computer and Network Security
# Term Project Monserrate-Mills Crypto
# Prof. Almodovar J, PhD, PE
# -------------------------------------------

import os, sys

from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
from Crypto import Random


def mills_malvo():
    print "Monserrate-Mills-Malvo 1.7 Attack 0.1 CPEN 503 Final Project Crypto"
    print "Copyright 2016 Atelier-Velvet Corporation."

    # IMPORTATION OF THE KEYS
    
    privateA = RSA.importKey(open('KA.der').read())
    kpublicA = RSA.importKey(open('KA.der.pub').read())
    privateB = RSA.importKey(open('KB.der').read())
    kpublicB = RSA.importKey(open('KB.der.pub').read())

    privattA = RSA.importKey(open('KAattack.der').read())
    kpubattA = RSA.importKey(open('KAattack.der.pub').read())
    privattB = RSA.importKey(open('KBattack.der').read())
    kpubattB = RSA.importKey(open('KBattack.der.pub').read())

    # REDEFINITION OF THE RSA KEYS SO THAT THEY MATCH THE CORRECT LENGTH AND ORDER (INTERNAL RSA KEY MUST BE SHORTER IN LENGTH THAN EXTERNAL RSA KEY) 
    
    KAPRI = kpublicB
    KAPUB = privateB

    KBPRI = privateA
    KBPUB = kpublicA

    KAMPRI = kpubattB
    KAMPUB = privattB

    KBMPRI = privattA
    KBMPUB = kpubattA
    
    # ATTACK ON THE "SECURE" SCHEMA POSTULATED BY THE BOOK: RSA[KBPUB, RSA[KAPRI, K]]--->ARCRSA[KBPRI, ARCRSA[KAPUB, RSA[KBPUB, RSA[KAPRI, K]]]]

    print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
    print "ATTACK ON THE ``SECURE'' SCHEMA POSTULATED BY THE BOOK: RSA[KBPUB, RSA[KAPRI, K]]--->ARCRSA[KBPRI, ARCRSA[KAPUB, RSA[KBPUB, RSA[KAPRI, K]]]]:"
    print " "
    print "Order of Events:"

    print " "
    print "INTERCEPTION OF THE PUBLIC KEYS:"
    print " "
    
    print "[TRANSMISSION FROM ALICE INTENDED TO BOB]: Alice sends Bob her public key, KAPUB."
    print "[TRANSMISSION FROM ALICE TO BOB INTERCEPTED BY MALVO]: Malvo swaps Alice's public key, KAPUB, with a public key from the pairs of his own, KAMPUB."
    print "[TRANSMISSION FROM MALVO TO BOB]: Malvo sends Bob the swap of Alice's public key, KAMPUB, and stores Alice's public key, KAPUB, in his key repository."
    print "[TRANSMISSION FROM BOB INTENDED TO ALICE]: Bob sends Alice his public key, KBPUB."
    print "[TRANSMISSION FROM BOB TO ALICE INTERCEPTED BY MALVO]: Malvo swaps Bob's public key, KBPUB, with another public key from the pairs of  his own, KBMPUB."
    print "[TRANSMISSION FROM MALVO TO ALICE]: Malvo sends Alice the swap of Bob's public key, KBMPUB, and stores Bob's public key, KBPUB, in his key repository."

    print " "
    print "EXTRACTION OF THE SYMMETRIC KEY:"
    print " "

    print "[GENERATION OF THE 16 BYTE SYMMETRIC KEY BY ALICE]:"
    K = raw_input("Alice, enter the symmetric key and press enter to send to Bob: ")
    print "Allice entered: ", K
    print " "
    print "[DOUBLE RSA ENCRYPTION AND TRANSMITTAL OF SYMMETRIC KEY USING ALICE'S PRIVATE KEY, THEN MALVO'S BOB COMPROMISED PUBLIC KEY]:"
    print " "
    
    cipher = PKCS1_OAEP.new(KAPRI)
    ciphertextAM0 = cipher.encrypt(K)
    cipher = PKCS1_OAEP.new(KBMPUB)
    ciphertextAM1 = cipher.encrypt(ciphertextAM0)

    print "[MALVO'S DOUBLE RSA DECRYPTION OF ALICE'S CIPHERTEXT TO BOB USING ALICE'S PUBLIC KEY AND MALVO'S BOB PRIVATE KEY, KBMPRI]:"

    cipher = PKCS1_OAEP.new(KBMPRI)
    ciphertextMA1 = cipher.decrypt(ciphertextAM1)
    cipher = PKCS1_OAEP.new(KAPUB)
    plaintextAM0 = cipher.decrypt(ciphertextMA1)

    print "[MALVO'S EXTRACTED SYMMETRIC KEY PAR INTERCEPTION FROM ALICE TO BOB IS]: ", plaintextAM0
    print " "

    print "[GENERATION OF COMPROMISED SYMMETRIC KEY FOR MALVO TO SEND BOB AS IF WERE COMMING FROM ALICE]"
    K_hat = raw_input("Enter the compromised symmetric key to send to Bob in the name of Alice, Malvoo .... : ")
    print "Malvo entered: ", K_hat
    print " "
    print "[DOUBLE RSA ENCRYPTION AND TRANSMITTAL OF COMPROMISED SYMMETRIC KEY USING MALVO'S ALICE PRIVATE KEY, THEN BOB'S PUBLIC KEY]:"

    cipher = PKCS1_OAEP.new(KAMPRI)
    ciphertextMB0 = cipher.encrypt(K_hat)
    cipher = PKCS1_OAEP.new(KBPUB)
    ciphertextMB1 = cipher.encrypt(ciphertextMB0)

    print " "
    print "[BOB'S DOUBLE RSA DECRYPTION OF MALVO'S COMPROMISED CIPHERTEXT USING BOB'S PRIVATE KEY AND MALVO'S ALICE PUBLIC KEY, KAMPUB]:"

    cipher = PKCS1_OAEP.new(KBPRI)
    ciphertextBM1 = cipher.decrypt(ciphertextMB1)
    cipher = PKCS1_OAEP.new(KAMPUB)
    plaintextBM0 = cipher.decrypt(ciphertextBM1)

    print "[BOB RECEIVES COMPROMISED SYMMETRIC KEY]: ", plaintextBM0
    print " "

    print "[ALICE AND BOB NOW THINK THEY SHARE THE SAME SYMMETRIC KEY ... MALVO KNOWS THEY'LL BE USING AES TO TRANSMIT ACROSS THE CHANNEL ....]"
    print " "
    print "[ALICE ---> BOB]: ALICE AES ENCRYPTS MESSAGE MA ON THE BLOCKSIZE (16 BYTES) WITH KEY K (16, 24, OR 32 BITES) AND SENDS IT TO BOB"
    print " "

    BLOCK_SIZE = 16
    
    MA = raw_input("Alice, enter your message to bob ... It's secure !: ")
    print "Alice's message MA was: ", MA

    key = plaintextAM0
    
    iv = Random.new().read(BLOCK_SIZE)
    cipher = AES.new(key.encode(), AES.MODE_CFB, iv)
    aciphertextAM = iv + cipher.encrypt(MA.encode())

    print " "
    print "[MALVO INTERCEPTS ALICE'S AES ENCRYPTED CIPHERTEXT TO BOB AND DECRYPS IT USING ALICE'S EXTRACTED SYMMETRIC KEY]" 

    AM = cipher.decrypt(aciphertextAM)

    print "[MALVO RECOVERS AND READS ALICE'S MESSAGE TO BOB ...]: ", AM
    print " "
    print "[MALVO NOW RE AES ENCRYPTS ALICE'S MESSAGE TO BOB BUT USING THE COMPROMISED SYMMETRIC KEY, K HAT]:"

    key_hat = K_hat
    
    iv = Random.new().read(BLOCK_SIZE)
    cipher = AES.new(key_hat.encode(), AES.MODE_CFB, iv)
    aciphertextMB = iv + cipher.encrypt(AM)

    print " "
    print "[BOB DECRYPTS THE COMPROMISED AES CIPHERTEXT USING THE COMPROMISED SYMMETRIC KEY, K HAT]:"

    BM = cipher.decrypt(aciphertextMB)
    print "Here it is Bob, the message so securely sent by Alice ;): ", BM

    
if __name__ == '__main__':
    mills_malvo()

    
