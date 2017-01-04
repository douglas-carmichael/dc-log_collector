#!/usr/bin/python
# -*- coding: utf-8 -*-

# Tiny Syslog Server in Python.
##
# This is a tiny syslog server that is able to receive UDP based syslog
# entries on a specified port and save them to a file.
# That's it... it does nothing else...
# There are a few configuration parameters.

(HOST, PORT) = ('192.168.1.3', 514)

#
# NO USER SERVICEABLE PARTS BELOW HERE...
#

import logging
import SocketServer
import re
import pprint
import macoslog

# local3: EX2200
# local2: SRX110
# local5: ZyXEL

LOG_FACILITY = {
    0: 'kernel messages',
    1: 'user-level messages',
    2: 'mail system',
    3: 'system daemons',
    4: 'security/authorization messages',
    5: 'messages generated internally by syslogd',
    6: 'line printer subsystem',
    7: 'network news subsystem',
    8: 'UUCP subsystem',
    9: 'clock daemon',
    10: 'security/authorization messages',
    11: 'FTP daemon',
    12: 'NTP subsystem',
    13: 'log audit',
    14: 'log alert',
    15: 'clock daemon',
    16: 'local0',
    17: 'local1',
    18: 'local2',
    19: 'local3',
    20: 'local4',
    21: 'local5',
    22: 'local6',
    23: 'local7',
    }

LOG_LEVEL = {
    0: 'Emergency',
    1: 'Alert',
    2: 'Critical',
    3: 'Error',
    4: 'Warning',
    5: 'Notice',
    6: 'Informational',
    7: 'Debug',
    }


class SyslogUDPHandler(SocketServer.BaseRequestHandler):

    def handle(self):
        data = bytes.decode(self.request[0].strip())
        socket = self.request[1]
        syslog_message = str(data)
        (priority, text) = \
            self.split_priority_from_message(syslog_message)
        facility = self.get_facility_from_priority(priority)
        lvl = self.get_level_from_priority(priority)

        subsystem_root = 'net.dcarmichael.log_collector'

        data = dict()
        data['Raw'] = syslog_message
        data['Client'] = self.client_address[0]
        data['log Level'] = LOG_LEVEL[lvl]
        data['log Facility'] = LOG_FACILITY[facility]
        data['Text'] = text
        if facility == 21:
            macoslog.write_log(subsystem_root, 'nwa3560n', text)
        elif facility == 18:
            # SRX110
            self.handle_bsd_message(subsystem_root, 'srx110', text)
        elif facility == 19:
            # EX2200C
            self.handle_bsd_message(subsystem_root, 'ex2200', text)

    def handle_bsd_message(self, subsystem_root, device, msg):


        # Check to see if this is a BSD-standard syslog message

        bsd_test_m = re.search('\\b(\\w*)\\[\\d*\\]', msg, re.S)
        if bsd_test_m:
        	msg_split = msg.split(" ")
        	msg_subsystem = subsystem_root + "." + device 
        	msg_category = msg_split[4].split("[")[0]
        	msg_body = ""
        	for split_point in range(5, len(msg_split)):
        		msg_body += msg_split[split_point] + " "
        	macoslog.write_log(msg_subsystem, msg_category, msg_body)
        return ''

    def split_priority_from_message(self, msg):
        '''
        https://www.fir3net.com/UNIX/Linux/how-to-determine-the-syslog-facility-
        using-tcpdump.html
        Each Syslog message contains a priority value. The priority value is
        enclosed within the characters < >. The priority value can be
        between 0 and 191 and consists of a Facility value and a Level value.
        Facility being the type of message, such as a kernel or mail message.
        And level being a severity level of the message.

        To calculate the priority value the following formula is used :
        Priority = Facility * 8 + Level

        So to determine the facility value of a syslog message we divide the
        priority value by 8. The remainder is the level value.
        '''

        match = re.search(r"\b(?=\w)(\d*)\b(?!\w)>(.*)", msg,
                          re.MULTILINE)
        if match:
            result = match.group(1)
            return (int(result), str(match.group(2)))
        else:
            raise

    def get_facility_from_priority(self, priority):
        return priority / 8

    def get_level_from_priority(self, priority):
        return priority % 8


if __name__ == '__main__':
    try:
        server = SocketServer.UDPServer((HOST, PORT), SyslogUDPHandler)
        server.serve_forever(poll_interval=0.1)
    except (IOError, SystemExit):
        raise
    except KeyboardInterrupt:
        print 'Ctrl+C Pressed. Shutting down.'

			