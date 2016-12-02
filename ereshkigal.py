#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Ereshkigal is an AutoSSH tunnel monitor
# It gives a curses user interface to monitor existing SSH tunnel that are managed with autossh.
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Author : nojhan <nojhan@nojhan.net>
#

#################################################################################################
# CORE
#################################################################################################

import os
import subprocess
import logging

# fort sorting dictionaries easily
from operator import itemgetter

class SSHTunnel(dict):
    """A dictionary that stores an SSH connection related to a tunnel"""

    def __init__(self, local_address = '1.1.1.1', local_port = 0, foreign_address = '1.1.1.1', foreign_port = 0, target_host = "Unknown", status = 'UNKNOWN', ssh_pid = 0, autossh_pid = 0 ):

        # informations available with netstat
        self['local_address'] = local_address
        self['local_port'] = local_port
        self['foreign_address'] = foreign_address
        self['foreign_port'] = foreign_port
        self['target_host'] = target_host
        self['status'] = status
        self['ssh_pid'] = ssh_pid
        self['autossh_pid'] = autossh_pid

        # would be nice to have an estimation of the connections latency
        #self.latency = 0


    def __repr__(self):
        # do not print all the informations by default
        return "%i\t%i\t%s\t%s" % (
            self['autossh_pid'],
            self['local_port'], 
            self['target_host'], 
            self['status']
            )


class AutoSSHprocess(dict):
    """A dictionary that stores an autossh process"""

    def __init__(self, pid = 0, local_port = 0, via_host="Unknown", target_host = "Unknown",foreign_port = 0):

        # some informations available on /proc
        self['pid'] = pid
        self['local_port'] = local_port
        self['via_host'] = via_host
        self['target_host'] = target_host
        self['foreign_port'] = foreign_port
        self['tunnels'] = []

    def __repr__(self):
        # single informations
        repr = "%i\t%i\t%s\t%s\t%i" % ( 
            self['pid'],
            self['local_port'],
            self['via_host'],
            self['target_host'],
            self['foreign_port'])

        # list of tunnels linked to this process
        for t in self['tunnels']:
            repr += "\n\t↳ %s" % t

        return repr


class AutoSSHTunnelMonitor(list):
    """List of existing autossh processes and ssh connections"""

    def __init__(self):
        """Warning: the initialization does not gather tunnels informations, use update() to do so"""
        # command that display network connections
        self.network_cmd = "netstat -ntp"

         # command that display processes
        self.ps_cmd = "ps ax"

        # do not perform update by default
        # this is necessary because one may want
        # only a list of connections OR autossh processes
        #self.update()


    def update(self):
        """Gather and parse informations from the operating system"""
        # autossh processes
        autosshs = self.get_autossh_instances()
        if autosshs:
            logging.debug("Autossh processes: %s" % autosshs)

        # ssh connections related to a tunnel
        connections = self.get_connections()
        if connections:
            logging.debug("SSH connections related to a tunnel: %s" % connections)

        # Bind existing connections to autossh processes.
        # Thus the instance is a list of AutoSSHinstance instances,
        # each of those instances having a 'tunnels' key,
        # hosting the corresponding list of tunnel connections.
        self[:] = self.bind_tunnels(autosshs, connections)

        # sort on a given key
        self.sort_on( 'local_port')


    def __repr__(self):
        repr = "PID\tINPORT\tVIA\tHOST\tOUTPORT"

        # only root can see tunnels connections
        if os.geteuid() == 0:
            repr += "\tTUNNELS"

        repr += '\n'

        # print each item in the list
        for t in self:
            repr += "%s\n" % t

        return repr


    def sort_on(self, key = 'autossh_pid' ):
        """Sort items on a given key"""
        # use the operator module
        self[:] = sorted( self, key=itemgetter( key ) )


    def get_autossh_instances(self):
        """Gather and parse autossh processes"""

        # call the command
        #status = os.popen3( self.ps_cmd )

        p = subprocess.Popen( self.ps_cmd, shell=True,
              stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)

        status = (p.stdin, p.stdout, p.stderr)


        # list of processes with the "autossh" string
        status_list = [ps for ps in status[1].readlines() if b"autossh" in ps]
        if status_list:
            logging.debug("Processes containing 'autossh': %s" % status_list)

        # split the process line if it contains a "-L"
        cmds = [i.split() for i in status_list if '-L' in i.decode()]

        autosshs = []

        for cmd in cmds:
            logging.debug("Parse command: %s" % cmd)

            # split the command in order to obtain arguments to the -L option
            args = [i.strip(b'L-') for i in cmd if '-L' in i.decode()][0].split(b':')
            logging.debug("Split around -L: %s" % args)

            pid = int(cmd[0])
            local_port = int(args[0])
            target_host = args[1].decode()
            foreign_port = int(args[2])

            # find the hostname where the tunnel goes
            via_host = "unknown"
            for i in range( len(cmd)-1,0,-1 ):
                if chr(cmd[i][0]) != '-':
                    via_host = cmd[i].decode()
                    logging.debug("Via host: %s" % via_host)
                    break


            auto = AutoSSHprocess( pid, local_port, via_host, target_host, foreign_port )
            logging.debug("Add AutoSSHprocess: %s" % auto)

            autosshs.append( auto )

        return autosshs

    def parse_addr_port(self, addr_port):
        if len(addr_port) == 2: # ipv4
            addr = addr_port[0].decode()
            logging.debug("IPv4 address: %s" % addr)
            port = int(addr_port[1])
            logging.debug("IPv4 port: %s" % port)
        else: # ipv6
            addr = b":".join(addr_port[:-1]).decode()
            logging.debug("IPv6 address: %s" % addr)
            port = int(addr_port[-1])
            logging.debug("IPv6 port: %s" % port)
        return addr,port


    def get_connections(self):
        """Gather and parse ssh connections related to a tunnel"""

        #status = os.popen3( self.network_cmd )

        p = subprocess.Popen( self.network_cmd, shell=True,
              stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)

        status = (p.stdin, p.stdout, p.stderr)

        status_list = status[1].readlines()
        # logging.debug("%i active connections" % len(status_list))

        cons = [i.split() for i in status_list if b'ssh' in i]

        tunnels = []

        for con in cons:
            logging.debug("Candidate connection: %s" % con)
            # netstat format:
            # Proto Recv-Q Send-Q Adresse locale          Adresse distante        Etat       PID/Program name

            # local infos
            local = con[3].split(b':')
            logging.debug("local infos: %s" % local)
            local_addr, local_port = self.parse_addr_port(local)

            # foreign infos
            foreign = con[4].split(b':')
            foreign_addr, foreign_port = self.parse_addr_port(foreign)

            status = con[5]
            logging.debug("Connection status: %s" % status)

            sshpid = int( con[6].split(b'/')[0] )
            logging.debug("SSH PID: %s" % sshpid)

            # ssh cmd line, got from /proc
            f = open( '/proc/' + str(sshpid) + '/cmdline' )
            cmd = f.readlines()[0]
            f.close()
            logging.debug("SSH command: %s" % cmd)

            # if not an ssh tunnel command
            if ('-L' not in cmd) or (':' not in cmd):
                # do not list it
                logging.debug("Not a tunnel command")
                continue

            logging.debug("Is a tunnel command")

            # autossh parent process
            ppidf = '/proc/' + str(sshpid) + '/status'
            logging.debug("Parse %s" % ppidf)
            f = open( ppidf )

            # filter the parent pid
            lpid = [i for i in f.readlines() if 'PPid' in str(i)]
            f.close()
            logging.debug("PPid: %s" % lpid)

            # parsing
            ppid = int(lpid[0].split(':')[1].strip())
            logging.debug("Parsed PPid: %s" % ppid)

            # command line of the parent process
            pcmdf = '/proc/' + str(ppid) + '/cmdline' 
            logging.debug("Parse %s" % pcmdf)
            f = open( pcmdf )

            # exclude the port
            content = f.readlines()
            logging.debug("Cmd: %s" % content[0])
            if not 'autossh' in content[0]:
                logging.warning("Tunnel not managed by autossh, ignore.")
                # FIXME display those hanging tunnels in some way.
                continue

            autohost = content[0].split(':')[1]
            f.close()
            logging.debug("Parsed cmd without port: %s" % autohost)

            # instanciation
            tunnels.append( SSHTunnel( local_addr, local_port, foreign_addr, foreign_port, autohost, status, sshpid, ppid ) )

        return tunnels


    def bind_tunnels(self, autosshs, tunnels):
        """Bind autossh process to the related ssh connections, according to the pid"""
        for t in tunnels:
            for i in autosshs:
                if i['pid'] == t['autossh_pid']:
                    # add to the list of tunnels of the AutoSSHprocess instance
                    i['tunnels'].append( t )

        return autosshs


#################################################################################################
# INTERFACES
#################################################################################################

import curses
import time
import signal

class monitorCurses:
    """Textual user interface to display up-to-date informations about current tunnels"""

    def __init__(self, scr):
        # curses screen
        self.scr = scr

        # tunnels monitor
        self.tm = AutoSSHTunnelMonitor()

        # selected line
        self.cur_line = -1

        # selected pid
        self.cur_pid = -1

        # switch to show only autoss processes (False) or ssh connections also (True)
        self.show_tunnels = False

        self.update_delay = 1 # seconds of delay between two updates
        self.ui_delay = 0.05 # seconds between two loops

        # colors
        self.colors_autossh = {'pid':0, 'local_port':3, 'via_host':2, 'target_host':2, 'foreign_port':3, 'tunnels_nb':4, 'tunnels_nb_none':1}
        self.colors_highlight = {'pid':9, 'local_port':9, 'via_host':9, 'target_host':9, 'foreign_port':9, 'tunnels_nb':9, 'tunnels_nb_none':9}
        self.colors_ssh = {'ssh_pid':0, 'status':4, 'status_out':1, 'local_address':2, 'local_port':3, 'foreign_address':2, 'foreign_port':3}


    def __call__(self):
        """Start the interface"""

        self.scr.clear() # clear all
        self.scr.nodelay(1) # non-bloking getch

        # first display
        self.display()

        # first update counter
        last_update = time.clock()
        last_state = None
        log_ticks = ""

        # infinite loop
        while(1):

            # wait some time
            # necessary to not overload the system with unnecessary calls
            time.sleep( self.ui_delay )

            # if its time to update
            if time.time() > last_update + self.update_delay:
                self.tm.update()
                # reset the counter
                last_update = time.time()

                state = "%s" % self.tm
                if state != last_state:
                    logging.debug("Waited: %s" % log_ticks)
                    log_ticks = ""
                    logging.debug("----- Time of screen update: %s -----" % time.time())
                    logging.debug("State of tunnels:\n%s" % self.tm)
                    last_state = state
                else:
                    log_ticks += "."


            kc = self.scr.getch() # keycode

            if kc != -1: # if keypress
                pass

            ch = chr(0)

            if 0 < kc < 256: # if ascii key
                # ascii character from the keycode
                ch = chr(kc)

            # Quit
            if ch in 'Qq':
                logging.debug("Waited: %s" % log_ticks)
                log_ticks = ""
                logging.debug("Key pushed: Q")
                break

            # Reload related autossh tunnels
            elif ch in 'rR':
                logging.debug("Waited: %s" % log_ticks)
                log_ticks = ""
                logging.debug("Key pushed: R")
                # if a pid is selected
                if self.cur_pid != -1:
                    # send the SIGUSR1 signal
                    # autossh performs a reload of existing tunnels that it manages
                    logging.debug("SIGUSR1 on PID: %i" % self.cur_pid)
                    os.kill( self.cur_pid, signal.SIGUSR1 )

            # Kill autossh process
            elif ch in 'kK':
                logging.debug("Waited: %s" % log_ticks)
                log_ticks = ""
                logging.debug("Key pushed: K")
                if self.cur_pid != -1:
                    # send a SIGKILL
                    # the related process is stopped
                    # FIXME SIGTERM or SIGKILL ?
                    logging.debug("SIGKILL on PID: %i" % self.cur_pid)
                    try:
                        os.kill( self.cur_pid, signal.SIGKILL )
                    except OSError:
                        logging.error("No such process: %i" % self.cur_pid)

            # Switch to show ssh connections
            # only available for root
            elif ch in 'tT' and os.getuid() == 0:
                logging.debug("Waited: %s" % log_ticks)
                log_ticks = ""
                logging.debug("Key pushed: T")
                self.show_tunnels = not self.show_tunnels

            # key pushed
            elif kc == curses.KEY_DOWN:
                logging.debug("Waited: %s" % log_ticks)
                log_ticks = ""
                logging.debug("Key pushed: down")
                # if not the end of the list
                if self.cur_line < len(self.tm)-1:
                    self.cur_line += 1
                    # get the pid
                    self.cur_pid = int(self.tm[self.cur_line]['pid'])

            # key up
            elif kc == curses.KEY_UP:
                logging.debug("Waited: %s" % log_ticks)
                log_ticks = ""
                logging.debug("Key pushed: up")
                if self.cur_line > -1:
                    self.cur_line -= 1
                    if self.cur_line > 0:
                        self.cur_pid = int(self.tm[self.cur_line]['pid'])

            else:
                # do nothing and wait until the next refresh
                pass

            # update the display
            self.display()

            # force a screen refresh
            self.scr.refresh()

        # end of the loop


    def display(self):
        """Generate the interface screen"""

        # First line: help
        help_msg = "[R]:reload autossh [K]:kill autossh [Q]:quit"
        if os.geteuid() == 0:
            help_msg += " [T]:show tunnels connections"
        help_msg += '\n'

        self.scr.addstr(0,0, help_msg, curses.color_pair(4) )
        self.scr.clrtoeol()

        # Second line
        self.scr.addstr( "Active AutoSSH instances: ", curses.color_pair(6) )
        self.scr.addstr( str( len(self.tm) ), curses.color_pair(1) )
        self.scr.addstr( " / Active connections: ", curses.color_pair(6) )
        self.scr.addstr( str( sum([len(i['tunnels']) for i in self.tm]) ), curses.color_pair(1) )
        self.scr.addstr( '\n', curses.color_pair(1) )
        self.scr.clrtoeol()

        # if no line is selected
        color = 0
        if self.cur_line==-1:
            # selected color for the header
            color = 9
            self.cur_pid = -1

        # header line
        header_msg = "PID \tINPORT\tVIAHOST              \tOUTHOST              \tOUTPORT"
        if os.geteuid() == 0:
            header_msg += "\tCONNECTIONS"
        self.scr.addstr( header_msg, curses.color_pair(color) )
        self.scr.clrtoeol()

        # for each autossh processes available in the monitor
        for l in range(len(self.tm)):
            # add a line for the l-th autossh process
            self.add_autossh( l )

            # if one want to show connections
            if self.show_tunnels and os.getuid() == 0:
                self.add_tunnel( l )

        self.scr.clrtobot()


    def add_tunnel(self, line ):
        """Add lines for each connections related to the l-th autossh process"""

        colors = self.colors_ssh

        # for each connections related to te line-th autossh process
        for t in self.tm[line]['tunnels']:
            # FIXME fail if the screen's height is too small.
            self.scr.addstr( '\n\t* ' )

            self.scr.addstr( str( t['ssh_pid'] ), curses.color_pair(colors['ssh_pid'] ) )
            self.scr.addstr( '\t' )
            self.scr.addstr( str( t['local_address'] ) , curses.color_pair(colors['local_address'] ))
            self.scr.addstr( ':' )
            self.scr.addstr( str( t['local_port'] ) , curses.color_pair(colors['local_port'] ))
            self.scr.addstr( '->' )
            self.scr.addstr( str( t['foreign_address'] ) , curses.color_pair(colors['foreign_address'] ))
            self.scr.addstr( ':' )
            self.scr.addstr( str( t['foreign_port'] ) , curses.color_pair(colors['foreign_port'] ))

            self.scr.addstr( '\t' )

            color = self.colors_ssh['status']
            # if the connections is established
            # TODO avoid hard-coded constants
            if t['status'].decode() != 'ESTABLISHED':
                color = self.colors_ssh['status_out']

            self.scr.addstr( t['status'].decode(), curses.color_pair( color ) )

            self.scr.clrtoeol()


    def add_autossh(self, line):
        """Add line corresponding to the line-th autossh process"""
        self.scr.addstr( '\n' )
        self.add_autossh_info('pid', line)
        self.add_autossh_info('local_port', line)
        self.add_autossh_info('via_host', line)
        self.add_autossh_info('target_host', line)
        self.add_autossh_info('foreign_port', line)

        nb = len(self.tm[line]['tunnels'] )
        if nb > 0:
            # for each connection related to this process
            for i in self.tm[line]['tunnels']:
                # add a vertical bar |
                # the color change according to the status of the connection
                if i['status'].decode() == 'ESTABLISHED':
                    self.scr.addstr( '|', curses.color_pair(self.colors_ssh['status']) )
                else:
                    self.scr.addstr( '|', curses.color_pair(self.colors_ssh['status_out']) )

        else:
            if os.geteuid() == 0:
                # if there is no connection, display a "None"
                self.scr.addstr( 'None', curses.color_pair(self.colors_autossh['tunnels_nb_none']) )

        self.scr.clrtoeol()

    def add_autossh_info( self, key, line ):
        """Add an information of an autossh process, in the configured color"""

        colors = self.colors_autossh
        # if the line is selected
        if self.cur_line == line:
            # set the color to the highlight one
            colors =  self.colors_highlight

        txt = str(self.tm[line][key])
        if key == 'target_host' or key == 'via_host':
            # limit the size of the line to 20
            # TODO avoid hard-coded constants
            txt = str(self.tm[line][key]).ljust(20)[:20]

        self.scr.addstr( txt, curses.color_pair(colors[key]) )
        self.scr.addstr( '\t', curses.color_pair(colors[key])  )



if __name__ == "__main__":
    import sys
    from optparse import OptionParser
    import configparser

    usage = """%prog [options]
    A user interface to monitor existing SSH tunnel that are managed with autossh.
    Called without options, ereshkigal displays a list of tunnels on the standard output.
    Note: Users other than root will not see tunnels connections.
    Version 0.3"""
    parser = OptionParser(usage=usage)

    parser.add_option("-c", "--curses",
        action="store_true", default=False,
        help="Start the user interface in text mode.")

    parser.add_option("-n", "--connections",
        action="store_true", default=False,
        help="Display only SSH connections related to a tunnel (only available as root).")

    parser.add_option("-a", "--autossh",
        action="store_true", default=False,
        help="Display only the list of autossh processes.")

    LOG_LEVELS = {'error'   : logging.ERROR,
                  'warning' : logging.WARNING,
                  'debug'   : logging.DEBUG}

    parser.add_option('-l', '--log-level', choices=list(LOG_LEVELS), default='error', metavar='LEVEL',
            help='Log level (%s), default: %s.' % (", ".join(LOG_LEVELS), 'error') )

    parser.add_option('-g', '--log-file', default=None, metavar='FILE',
            help="Log to this file, default to standard output. \
            If you use the curses interface, you may want to set this to actually see logs.")

    parser.add_option('-f', '--config-file', default=None, metavar='FILE',
            help="Use this configuration file (default: '~/.ereshkigal.conf')")

    (asked_for, args) = parser.parse_args()

    logmsg = "----- Started Ereshkigal -----"

    if asked_for.log_file:
        logfile = asked_for.log_file
        logging.basicConfig(filename=logfile, level=LOG_LEVELS[asked_for.log_level])
        logging.debug(logmsg)
        logging.debug("Log in %s" % logfile)
    else:
        if asked_for.curses:
            logging.warning("It's a bad idea to log to stdout while in the curses interface.")
        logging.basicConfig(level=LOG_LEVELS[asked_for.log_level])
        logging.debug(logmsg)
        logging.debug("Log to stdout")

    logging.debug("Asked for: %s" % asked_for)

    # unfortunately, asked_for class has no __len__ method in python 2.4.3 (bug?)
    #if len(asked_for) > 1:
    #    parser.error("asked_for are mutually exclusive")

    config = configparser.ConfigParser()
    if asked_for.config_file:
        try:
            config.read(asked_for.config_file)
        except configparser.MissingSectionHeaderError:
            logging.error("'%s' contains no known configuration" % asked_for.config_file)
    else:
        try:
            config.read('~/.ereshkigal.conf')
        except configparser.MissingSectionHeaderError:
            logging.error("'%s' contains no known configuration" % asked_for.config_file)

    # Load autossh instances by sections: [expected]
    # if config['expected']:



    if asked_for.curses:
        logging.debug("Entering curses mode")
        import curses
        import traceback

        try:
            scr = curses.initscr()
            curses.start_color()

            # 0:black, 1:red, 2:green, 3:yellow, 4:blue, 5:magenta, 6:cyan, 7:white
            curses.init_pair(1, curses.COLOR_RED, curses.COLOR_BLACK)
            curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)
            curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLACK)
            curses.init_pair(4, curses.COLOR_BLUE, curses.COLOR_BLACK)
            curses.init_pair(5, curses.COLOR_MAGENTA, curses.COLOR_BLACK)
            curses.init_pair(6, curses.COLOR_CYAN, curses.COLOR_BLACK)
            curses.init_pair(7, curses.COLOR_WHITE, curses.COLOR_BLACK)
            curses.init_pair(8, curses.COLOR_WHITE, curses.COLOR_GREEN)
            curses.init_pair(9, curses.COLOR_WHITE, curses.COLOR_BLUE)

            curses.noecho()
            curses.cbreak()
            scr.keypad(1)

            # create the monitor
            mc = monitorCurses( scr )
            # call the monitor
            mc()

            scr.keypad(0)
            curses.echo()
            curses.nocbreak()
            curses.endwin()

        except:
            # end cleanly
            scr.keypad(0)
            curses.echo()
            curses.nocbreak()
            curses.endwin()

            # print the traceback
            traceback.print_exc()


    elif asked_for.connections:
        logging.debug("Entering connections mode")
        tm = AutoSSHTunnelMonitor()
        # do not call update() but only get connections
        logging.debug("UID: %i." % os.geteuid())
        if os.geteuid() == 0:
            con = tm.get_connections()
            for c in con:
                print(con)
        else:
            logging.error("Only root can see SSH tunnels connections.")


    elif asked_for.autossh:
        logging.debug("Entering autossh mode")
        tm = AutoSSHTunnelMonitor()
        # do not call update() bu only get autossh processes
        auto = tm.get_autossh_instances()
        for i in auto:
            print(auto)


    else:
        logging.debug("Entering default mode")
        tm = AutoSSHTunnelMonitor()
        # call update
        tm.update()
        # call the default __repr__
        print(tm)


#
# In Mesopotamian mythology, Ereshkigal (lit. "great lady under earth")
# was the goddess of Irkalla, the land of the dead or underworld.
#
# Thus, she knows a lot about tunnels...
#
# http://en.wikipedia.org/wiki/Ereshkigal
#

