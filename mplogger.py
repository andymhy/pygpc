#coding=utf-8
import logging
import os

LOGCHANNEL_CONSOLE          = 1
LOGCHANNEL_FILE             = 2
LOGCHANNEL_FILE_CONSOLE     = 3

LOGLEVEL_DEBUG              = logging.DEBUG
LOGLEVEL_INFO               = logging.INFO
LOGLEVEL_WARNING            = logging.WARNING
LOGLEVEL_ERROR              = logging.ERROR
LOGLEVEL_CRITICAL           = logging.CRITICAL

class MPLogger():

    def __init__(self, level=LOGLEVEL_INFO, ch=LOGCHANNEL_CONSOLE, fn=None):

        self.logger = logging.getLogger('CUPTSM')
        
        self.logger.setLevel(level)
        
        self.ch_list = []
        
        # create formatter
        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s : %(message)s")
        
        if ch > LOGCHANNEL_CONSOLE:
            pwd = os.path.abspath(os.path.dirname(__file__))     
            folder = 'log'
            dir = os.path.join(pwd, folder)
            if not os.path.exists(dir):
                os.mkdir(dir)
                
            ch_file = logging.FileHandler(dir + '/debug.txt')
            # add formatter to ch
            ch_file.setFormatter(formatter)
            self.ch_list.append(self.ch_file)
        
        if ch != LOGCHANNEL_FILE:
            ch_console = logging.StreamHandler()
            # add formatter to ch
            ch_console.setFormatter(formatter)
            self.ch_list.append(ch_console)
     
        

    def info(self, msg):
        for ch in self.ch_list:
            self.logger.addHandler(ch)
            
        self.logger.info(msg)
        
        for ch in self.ch_list:
            self.logger.removeHandler(ch)    
     
    def debug(self, msg):
        for ch in self.ch_list:
            self.logger.addHandler(ch)
            
        self.logger.debug(msg)
        
        for ch in self.ch_list:
            self.logger.removeHandler(ch)
        
     
    def error(self, msg):
        for ch in self.ch_list:
            self.logger.addHandler(ch)
            
        self.logger.error(msg)
        
        for ch in self.ch_list:
            self.logger.removeHandler(ch)
            
    def warning(self, msg):
        for ch in self.ch_list:
            self.logger.addHandler(ch)
            
        self.logger.warning(msg)
        
        for ch in self.ch_list:
            self.logger.removeHandler(ch)
def main():

    lg = MPLogger(LOGLEVEL_DEBUG)

    for i in range(100):
        if i % 2 == 0:
            lg.debug(str(i))
        else:
            lg.error(str(i))

if __name__ == '__main__':
    main()
