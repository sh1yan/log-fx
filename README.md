# log-日志分析

# coding:utf-8

import re
import time
logo = '''
          _         _      _  _                  
   ___   | |_      (_)    | || |  __ _    _ _    
  (_-<   | ' \     | |     \_, | / _` |  | ' \   
  /__/_  |_||_|   _|_|_   _|__/  \__,_|  |_||_|  
_|"""""|_|"""""|_|"""""|_| """"|_|"""""|_|"""""| 
"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-' 

   Code By shiyan     Blog: sh1yan.top
   
'''
class Log_analysis(object):

    def __init__(self,Route,Features):
        self.Route = Route
        self.Features = Features

    def file(self):
        global du_log
        log = open(self.Route,'r')
        du_log = log.readlines()
        log.close()

    def state200(self):
        global state_two
        state_two = []
        for i in du_log:
            zz200 = r'HTTP/1.1" 200'
            cz200 = re.findall(zz200,i)
            if cz200:
                state_two.append(i)
            else:
                pass

    def for_xh(self,xh):
        for i in xh:
            return i

    def analysis(self):
        IP = r'(\d*.\d*.\d*.\d*) -'
        times = r'- \[(.*)\] "'
        gjurl = r'"GET(.*)HTTP/1.1"'
        for i in state_two:
            log_gj = re.findall(self.Features, i, re.I)
            if log_gj:
                gj_IP = re.findall(IP, i)
                gj_time = re.findall(times, i)
                gj_url = re.findall(gjurl, i)
                time.sleep(1)
                print '- - - - - - - - - - - - - - - - - - - - - - - - - -'
                print u'攻击者IP：  ', self.for_xh(gj_IP)
                print u'攻击时间：  ', self.for_xh(gj_time)
                print u'攻击特征： ', self.for_xh(gj_url)
                # print '- - - - - - - - - - - - - - - - - - - - - - - - - -'
            else:
                pass

sql = r'select'
xss = r'script'

if __name__ == '__main__':

    print logo
    rzfx = Log_analysis('G://1.log',sql)
    rzfx.file()
    rzfx.state200()
    rzfx.analysis()

