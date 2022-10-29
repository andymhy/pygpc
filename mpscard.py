#coding=utf-8

#-------------------------------------------------------------------------------
# Name:        mpscard.py
# Purpose: wrapper of parts of pyscard
#
# Author:      Mu Hongyu
#
# Created:     31-10-2012
# Copyright:   (c) MU Hongyu 2012
# Licence:     <your licence>
#-------------------------------------------------------------------------------

import time
import logging
import smartcard.util


from smartcard.scard import *
from mplogger import *

################################################################################
## Smart Card Mangement: Rreader Management, Smart Card APDU level management
################################################################################
class SCManager():

    def __init__(self, check_sw=True):
        self.context = None
        self.card = None
        self.protocol = None
        self.reader = None
        self.is_connected = False

        self.continuous = not check_sw

        self.logger = MPLogger(LOGLEVEL_INFO)

    def get_context(self):
        return self.context

    def get_card_handle(self):
        return self.card

    def get_active_protocol(self):
        return self.protocol

    def get_current_reader(self):
        return self.reader

    def is_reader_opened(self):
        return self.isRdrConnected

    def get_halt_mode(self):
        return self.continuous

    def set_halt_mode(self, continuous=True):
        self.continuous = continuous

    def establish_context(self):

        try:
            res, ctx = SCardEstablishContext(SCARD_SCOPE_USER)
            if res != SCARD_S_SUCCESS:
                raise Exception('Failed to establish context : ' + SCardGetErrorMessage(res))
            self.logger.info('[SCard] => ' + 'SCardContext established!')

        except Exception, message:
            self.logger.error(message)
            exit()

        self.context = ctx
        return ctx

    def release_context(self):

        try:
            ctx = self.context

            # if reader is not disconnected, disconnected it first
            if self.card is not None:
                self.closeReader(self.card)

            res = SCardReleaseContext(ctx)
            if res != SCARD_S_SUCCESS:
                self.context = None
                raise Exception('Failed to release context: ' + SCardGetErrorMessage(res))

            self.logger.info('[SCard] => ' + 'SCardContext released!')

        except Exception, message:
            self.logger.error(message)
            exit()

    def list_readers(self, ctx=None):

        rdrs = []
        try:
            if ctx is None:
                ctx = self.context

            res, rdrs = SCardListReaders(ctx, [])
            if res != SCARD_S_SUCCESS:
                raise Exception('Failed to list readers: ' + SCardGetErrorMessage(res))

            if len(rdrs) < 1:
                raise Exception('No smart card reader found')

            self.reader = rdrs[0]

        except Exception, message:
            self.logger.error(message)
            exit()

        return rdrs

    def open_reader(self, rdr=None):

        try:
            if rdr is None:
                rdr = self.reader

            self.logger.info('[SCard] => ' + 'To connect { ' + rdr + ' } ...')

            res, crd, ptl = SCardConnect(self.context, rdr,
                SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1)
            if res != SCARD_S_SUCCESS:
                raise Exception('[SCard] => Unable to connect: ' + SCardGetErrorMessage(res))
            self.logger.info('[SCard] => { '+ rdr + ' } connected [T' + str(ptl) + ']')

        except Exception, message:
            self.logger.error(message)
            exit()

        self.card = crd
        self.protocol = ptl
        self.isRdrConnected = True

        return (crd, ptl)

    def close_reader(self):

        try:
            res = SCardDisconnect(self.card, SCARD_UNPOWER_CARD)
            if res != SCARD_S_SUCCESS:
                raise Exception('[SCard]=> SCardDisconnect failed= ' + SCardGetErrorMessage(res))

            self.isRdrConnected = False
            self.card = None

            self.logger.info('[SCard]=> SCardDisconnect { ' + self.reader + ' } disconnected!')

        except Exception, message:
            self.logger.error(message)
            exit()
            
    def reset_card(self, warm_reset=False):
        try:
            if warm_reset:
                reset_mode = SCARD_RESET_CARD
            else:
                reset_mode = SCARD_UNPOWER_CARD
                
            res, ptl = SCardReconnect(self.card, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, reset_mode)
            if res != SCARD_S_SUCCESS:
                raise Exception('[SCard]=> SCardReconnect failed= ' + SCardGetErrorMessage(res))

            self.protocol = ptl
            self.logger.info('[SCard]=> SCardReconnect { ' + self.reader + ' } OK!')
            
        except Exception, message:
            self.logger.error(message)
            exit()
            
    def get_atr(self, crd=None):
        if crd is None:
            hresult, reader, state, protocol, atr = SCardStatus(self.card)
        else:
            hresult, reader, state, protocol, atr = SCardStatus(crd)

        return smartcard.util.toHexString(atr)

    def transmit_apdu(self, cmd, crd=None, ptl=None):
        '''
            cmd = '00A4040008A000000003000000'
            spaces are allowed
        '''

        resp_str = None

        try:

            if crd is None:
                crd = self.card
            if ptl is None:
                ptl = self.protocol

            self.logger.info('[APDU]-> ' + cmd.upper())

            cmd_lst = smartcard.util.toBytes(cmd)

            res, resp = SCardTransmit(crd, ptl, cmd_lst)
            
            if res != SCARD_S_SUCCESS:
                raise Exception('SCardTransmit failed: ' + SCardGetErrorMessage(res))

            if len(resp) < 2:
                raise Exception('SCardTransmit failed: len of response < 2')

            # SW = 61xx or 6Cxx
            if resp[-2] == 0x61:
                get_resp_cmd = [0x00, 0xC0, 0x00, 0x00, resp[1]]
                res, resp = SCardTransmit(crd, ptl, get_resp_cmd)
                if res != SCARD_S_SUCCESS:
                    raise Exception('Get Response failed: ' + SCardGetErrorMessage(res))

            if resp[-2] == 0x6C:
                cmd_lst.append(resp[1])
                res, resp = SCardTransmit(crd, ptl, cmd_lst)
                if res != SCARD_S_SUCCESS:
                    raise Exception('APDU with given len resending failed:' + SCardGetErrorMessage(res))

            resp_str =  smartcard.util.toHexString(resp, smartcard.util.PACK)
            
            self.logger.info('[APDU]<- ' + resp_str)

            sw = int(resp_str[-4:], 16)

            if resp[-2] != 0x90 and resp[-2] != 0x62 and resp[-2] != 0x63:
                if not self.continuous:
                    self.close_reader()
                    self.release_context()
                    exit()

        except Exception, message:            
            self.logger.error(message)
            exit()

        return  (resp_str[:-4], sw)

def main():

    sc = SCManager()

    sc.establish_context()
    rdrs = sc.list_readers()
    print rdrs

    sc.open_reader(rdrs[1])


    sc.transmit_apdu('00A4040008A000000003000000')

    sc.close_reader()

    sc.release_context()

if __name__ == '__main__':
    main()
