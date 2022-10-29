#-------------------------------------------------------------------------------
# Name: mpgp.py
# Purpose: To provide GP 2.2.1 implementation

# Author:      Mu Hongyu Andy
#
# Created:     15-10-2012
# Copyright:   (c) hmu 2012
# Licence:     <your licence>
#-------------------------------------------------------------------------------

#! /usr/bin/env python

import sys
import re
import binascii
import struct

from mplogger import *
from mphelper import *


class GPImpl():
    def __init__(self, scmgr, CARD_PROFILE = None):

        # Instance of Smart Card Reader Management
        self.mgr = scmgr

        self.logger = MPLogger(LOGLEVEL_INFO)

        # returned by Initial Update
        self.key_info = None
        self.seq_counter = None
        self.card_challenge = None
        self.card_cryptogram = None

        # C-MAC length
        self.CMAC_LEN = 8

        # Initial chaining vector
        self.hostMAC = '00' * DES_BLOCK_SIZE

        if not self.mgr.is_reader_opened():
            raise Exception('Reader not connected!')

        # Terminal configuration
        if CARD_PROFILE is None:
            self.KMC = '404142434445464748494A4B4C4D4E4F'
            self.KV = '20'
            self.SL = '00'
            self.CPG = 0
            self.SCP = 2
            self.SCP_i = 15
            self.scp_ks = [self.KMC, self.KMC, self.KMC]
        else:
            self.KMC = CARD_PROFILE['KMC']
            self.KV = CARD_PROFILE['KEY_VERSION']
            self.SL = CARD_PROFILE['SECURITY_LEVEL']
            self.CPG = CARD_PROFILE['CPG']
            self.SCP = CARD_PROFILE['SCP']
            self.SCP_i = CARD_PROFILE['SCP_i']
            self.scp_ks = CARD_PROFILE['SCP02']
            
    def diversify_kmc(self, cpg, kmc, aid_last2, csn, ic_batch_id):
        #set default enc/mac/kek as base key.
        KDCenc = kmc
        KDCmac = kmc
        KDCkek = kmc
        
        # Derive KMC
        if cpg == 0:
            self.logger.debug('KMC Diversification:NO')
            # since no diversification of KMC, use pre-defined keyset instead.
            
        elif cpg == 202:
            self.logger.debug('KMC Diversification:CPG202 (Open Platform v2.02)')
            aid_last2_csn = aid_last2 + csn
            diversifier_enc = aid_last2_csn + 'F001' + aid_last2_csn + '0F01'
            diversifier_mac = aid_last2_csn + 'F002' + aid_last2_csn + '0F02'
            diversifier_kek = aid_last2_csn + 'F003' + aid_last2_csn + '0F03'

            KDCenc = DES3_CBC_ENC(kmc, '00' * DES_BLOCK_SIZE, diversifier_enc)
            KDCmac = DES3_CBC_ENC(kmc, '00' * DES_BLOCK_SIZE, diversifier_mac)
            KDCkek = DES3_CBC_ENC(kmc, '00' * DES_BLOCK_SIZE, diversifier_kek)

            self.logger.debug('Factor:' + diversifier_enc)
            self.logger.debug('KDCenc:' + KDCenc)

            self.logger.debug('Factor:' + diversifier_mac)
            self.logger.debug('KDCmac:' + KDCmac)

            self.logger.debug('Factor:' + diversifier_kek)
            self.logger.debug('KDCkek:' + KDCkek)

        elif cpg == 212:
            self.logger.debug('KMC Diversification:CPG212 (Visa GlobalPlatform 2.1.1)')
            csn_ic_batch_id = csn + ic_batch_id
            diversifier_enc = csn_ic_batch_id + 'F001' + csn_ic_batch_id + '0F01'
            diversifier_mac = csn_ic_batch_id + 'F002' + csn_ic_batch_id + '0F02'
            diversifier_kek = csn_ic_batch_id + 'F003' + csn_ic_batch_id + '0F03'

            KDCenc = DES3_CBC_ENC(kmc, '00' * DES_BLOCK_SIZE, diversifier_enc)
            KDCmac = DES3_CBC_ENC(kmc, '00' * DES_BLOCK_SIZE, diversifier_mac)
            KDCkek = DES3_CBC_ENC(kmc, '00' * DES_BLOCK_SIZE, diversifier_kek)

            self.logger.debug('Factor:' + diversifier_enc)
            self.logger.debug('KDCenc:' + KDCenc)

            self.logger.debug('Factor:' + diversifier_mac)
            self.logger.debug('KDCmac:' + KDCmac)

            self.logger.debug('Factor:' + diversifier_kek)
            self.logger.debug('KDCkek:' + KDCkek)
        else:
            raise Exception('Invalid KMC diverfication mode')
            
        return (KDCenc, KDCmac, KDCkek)
        
    def diversify_scp_key(self, scp, kdc_keyset, card_challenge, host_challenge, secure_counter):
        KDCenc = kdc_keyset[0]
        KDCmac = kdc_keyset[1]
        KDCkek = kdc_keyset[2]
            
        # Gnerate secure channel session key
        if scp == 2:
            diversifier_enc = '0182' + secure_counter + '00' * 12
            diversifier_mac = '0101' + secure_counter + '00' * 12
            diversifier_dek = '0181' + secure_counter + '00' * 12

            sk_enc = DES3_CBC_ENC(KDCenc, '00' * DES_BLOCK_SIZE, diversifier_enc)
            self.logger.debug('KDCenc=' + KDCenc)
            self.logger.debug('Factor=' + diversifier_enc)
            self.logger.debug('S-ENC =' + sk_enc)

            sk_mac = DES3_CBC_ENC(KDCmac, '00' * DES_BLOCK_SIZE, diversifier_mac)
            self.logger.debug('KDCmac=' + KDCmac)
            self.logger.debug('Factor=' + diversifier_mac)
            self.logger.debug('S-MAC =' + sk_mac)

            sk_dek = DES3_CBC_ENC(KDCkek, '00' * DES_BLOCK_SIZE, diversifier_dek)
            self.logger.debug('KDCkek:' + KDCkek)
            self.logger.debug('Factor:' + diversifier_dek)
            self.logger.debug('DEK :' + sk_dek)

        elif scp == 1:
            diversifier_enc = card_challenge + host_challenge
            diversifier_mac = card_challenge + host_challenge
            diversifier_dek = None

            sk_enc = DES3_CBC_ENC(KDCenc, '00' * DES_BLOCK_SIZE, diversifier_enc)
            self.logger.debug('KDCenc=' + KDCenc)
            self.logger.debug('Factor=' + diversifier_enc)
            self.logger.debug('S-ENC =' + sk_enc)

            sk_mac = DES3_CBC_ENC(KDCmac, '00' * DES_BLOCK_SIZE, diversifier_mac)
            self.logger.debug('KDCmac=' + KDCmac)
            self.logger.debug('Factor=' + diversifier_mac)
            self.logger.debug('S-MAC =' + sk_mac)

            sk_dek = KDCkek
            self.logger.debug('KDCkek:' + KDCkek)
            self.logger.debug('Factor:' + diversifier_dek)
            self.logger.debug('DEK :' + sk_dek)
        else:
            self.logger.debug('SCP %d not supported' % SCP)
            
        return (sk_enc, sk_mac, sk_dek)
        
    
        
    def diversify_key(self, kmc=None, scp_keyset=None, init_update_resp=None, CPG = 0, SCP = 2, i=15):
        
        if kmc is None:
            base_key = self.KMC
        
        if scp_keyset is None:
            scpks = self.scp_ks
            
        if init_update_resp is None:
            key_div_fct = self.key_divers
            seq_cntr = self.seq_counter            
        else:
            key_div_fct = init_update_resp[8:20]
            seq_cntr = init_update_resp[24:28]
        
        csn_ic_batchid = binascii.unhexlify(key_div_fct)

        self.logger.debug('----------------------------------------------------------------')
        self.logger.debug('KMC: ' + base_key)

        #set default enc/mac/kek as base key.
        KDCenc = base_key
        KDCmac = base_key
        KDCkek = base_key
        
        # Derive KMC
        if CPG == 0:
            self.logger.debug('Key Diversification:NO')
            # since no diversification of KMC, use pre-defined keyset instead.
            KDCenc = scpks[0]
            KDCmac = scpks[1]
            KDCkek = scpks[2]
            
        elif CPG == 202:
            self.logger.debug('Key Diversification:CPG202\n')
            raise Exception('CPG202 not supported temporarily')

        elif CPG == 212:
            self.logger.debug('Key Diversification:CPG212\n')
            cpg212DiversEncDi = key_div_fct + 'F001' + key_div_fct + '0F01'
            cpg212DiversMACDi = key_div_fct + 'F002' + key_div_fct + '0F02'
            cpg212DiversKekDi = key_div_fct + 'F003' + key_div_fct + '0F03'

            KDCenc = DES3_CBC_ENC(base_key, '00' * 8, cpg212DiversEncDi)
            KDCmac = DES3_CBC_ENC(base_key, '00' * 8, cpg212DiversMACDi)
            KDCkek = DES3_CBC_ENC(base_key, '00' * 8, cpg212DiversKekDi)

            self.logger.debug('\tFactor:' + cpg212DiversEncDi)
            self.logger.debug('\tKDCenc:' + KDCenc)

            self.logger.debug('------------------------------------------------------------')
            self.logger.debug('\tFactor:' + cpg212DiversMACDi)
            self.logger.debug('\tKDCmac:' + KDCmac)

            self.logger.debug('------------------------------------------------------------')
            self.logger.debug('\tFactor:' + cpg212DiversKekDi)
            self.logger.debug('\tKDCkek:' + KDCkek)


        self.logger.debug('SCP%02X i=%d\n' % (SCP, i))

        # Generate secure channel session key
        if SCP == 2:
            scp02DiversENCDi = '0182' + seq_cntr + '00' * 12
            scp02DiversMACDi = '0101' + seq_cntr + '00' * 12
            scp02DiversDEKDi = '0181' + seq_cntr + '00' * 12

            sk_enc = DES3_CBC_ENC(KDCenc, '00' * DES_BLOCK_SIZE, scp02DiversENCDi)
            self.logger.debug('\tKDCenc:' + KDCenc)
            self.logger.debug('\tFactor:' + scp02DiversENCDi)
            self.logger.debug('\tS-ENC :' + sk_enc)

            sk_mac = DES3_CBC_ENC(KDCmac, '00' * DES_BLOCK_SIZE, scp02DiversMACDi)
            self.logger.debug('\tKDCmac:' + KDCmac)
            self.logger.debug('\tFactor:' + scp02DiversMACDi)
            self.logger.debug('\tS-MAC :' + sk_mac)

            sk_dek = DES3_CBC_ENC(KDCkek, '00' * DES_BLOCK_SIZE, scp02DiversDEKDi)
            self.logger.debug('\tKDCkek:' + KDCkek)
            self.logger.debug('\tFactor:' + scp02DiversDEKDi)
            self.logger.debug('\tDEK :' + sk_dek)

        elif SCP == 1:
            self.logger.debug('SCP 01 not supported')
        else:
            self.logger.debug('SCP %d not supported' % SCP)

        self.logger.debug('\tSecurity Level: ' + self.SL)

        self.logger.debug('---------------------------------------------------------------')

        # check card cryptogram
        return (sk_enc, sk_mac, sk_dek)

    def _initial_update(self, host_challenge):
        
        INIT_UPD = '8050' + self.KV + '00' + ('%02X' % (len(host_challenge)/2)) + host_challenge

        resp_tup = self.mgr.transmit_apdu(INIT_UPD)

        resp = resp_tup[0]
        self.key_info = resp[20:24]
        self.seq_counter = resp[24:28]
        self.card_challenge = resp[28:40]
        self.card_cryptogram = resp[40:56]

        self.key_divers = resp[8:20]
        
        # print resp
        # print self.key_info
        # print self.seq_counter
        # print self.card_challenge
        # print self.card_cryptogram
        # print self.key_divers
        
        return resp
        #return '0000C07460598C0D3800200200A17D64616ED6B4779E05773DBCEF0E'

    def open_secure_channel(self, sd_aid, host_challenge=None):

        # first select secure domain to be authd
        self.select(sd_aid)

        if host_challenge is None:
            #host_challenge = '1111111122222222'
            host_challenge = '1A924EC499BF53AC'

        self.logger.info('---OPEN SECURE CHANNEL-------------------------------')
        rsp_initupd = self._initial_update(host_challenge)
        
        if self.SCP == 1:        
            rsp_initupd_fmt = '4s 4x 8s 4s 2s 2s 16s 16x'
            (aid_last2, csn, ic_batch_id, kv, scp_id, card_challenge) = struct.unpack(rsp_initupd_fmt, rsp_initupd)
        else:
            rsp_initupd_fmt = '4s 4x 8s 4s 2s 2s 4s 12s 16x'
            (aid_last2, csn, ic_batch_id, kv, scp_id, secure_counter, card_challenge) = struct.unpack(rsp_initupd_fmt, rsp_initupd)

        kdc_ks = self.diversify_kmc(self.CPG, self.KMC, aid_last2, csn, ic_batch_id)
        
        self.S_ENC, self.S_MAC, self.DEK = self.diversify_scp_key(self.SCP, kdc_ks, card_challenge, host_challenge, secure_counter)
        #self.S_ENC, self.S_MAC, self.DEK = self.diversify_key(init_update_resp = None, CPG = self.CPG, SCP = self.SCP, i = self.SCP_i)

        if self.SCP == 1:
            diversifier_host_cryptogram = card_challenge + host_challenge
        else:
            diversifier_host_cryptogram = secure_counter + card_challenge + host_challenge

        hostCryptogramDivers = PADDING80(diversifier_host_cryptogram, DES_BLOCK_SIZE)


        self.logger.debug('Host Cryptogram Di:' + hostCryptogramDivers)
        self.logger.debug('S-ENC:' + self.S_ENC)

        hostCryptogram = DES3_CBC_ENC(self.S_ENC, '00' * DES_BLOCK_SIZE, hostCryptogramDivers)

        hostCryptogram = hostCryptogram[-16:]

        self.logger.debug('Host Crytogram:' + hostCryptogram)

        APDU_AUTHD = '8482' + self.SL + '0010' + hostCryptogram

        apdu1 = PADDING80(APDU_AUTHD, DES_BLOCK_SIZE)

        self.hostMAC = DES_3DES_CBC_MAC(self.S_MAC, '00' * 8, apdu1)

        resp = self.mgr.transmit_apdu(APDU_AUTHD + self.hostMAC)

        return resp[0]

    def encryptKey(self, key):
        return DES3_ECB_ENC(self.DEK, key)

    def rawAPDU(self, apdu):
        return self.mgr.transmit_apdu(apdu)

    def secureAPDU(self, apdu):
        apdu_dec = binascii.unhexlify(apdu)

        if self.SL == '01' or self.SL == '03':
            # CLA | 0x04
            cla = ord(apdu_dec[0])
            cla |= 0x04

            # LC + 0x08
            lc = ord(apdu_dec[4])
            lc += 0x08

            apdu_dec_sm = struct.pack('B', cla) + apdu_dec[1:4] + struct.pack('B', lc) + apdu_dec[5:]
            apdu_sm = binascii.hexlify(apdu_dec_sm)

            # ICV
            icv = DES_ECB_ENC(self.S_MAC[:16], self.hostMAC)

            # Padding 800000...
            apdu1 = PADDING80(apdu_sm, DES_BLOCK_SIZE)

            # C-MAC
            self.hostMAC = DES_3DES_CBC_MAC(self.S_MAC, icv, apdu1)

            apdu_str = ''

            # encrypt data field
            if self.SL == '03' and ord(apdu_dec[4]) > self.CMAC_LEN:
                di = PADDING80(apdu_sm[10:], DES_BLOCK_SIZE)
                iv = '0000000000000000'
                do = DES3_CBC_ENC(self.S_ENC, iv, di)
                apdu_str += (apdu_sm[:8] + '%02X' % (len(do)/2 + self.CMAC_LEN) + do)
            else:
                apdu_str += apdu_sm

            apdu_str += self.hostMAC

            return self.mgr.transmit_apdu(apdu_str)
        else:
            if apdu_dec[4] == '\x00':
                apdu_cmd = apdu[:-2]
            else:
                apdu_cmd = apdu

            return self.mgr.transmit_apdu(apdu_cmd)

    def select(self, aid):
        self.logger.info('---SELECT-------------------------------------------')
        SEL_SSD = '00A40400' + ('%02X' % (len(aid)/2)) + aid

        self.mgr.transmit_apdu(SEL_SSD)

    def getSessionKeySet(self):
        return (self.S_ENC, self.S_MAC, self.DEK)