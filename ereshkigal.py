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
import psutil
import socket
import re
import collections


class Tunnel:
    def __init__(self, ssh_pid = None, in_port = None, via_host = None, target_host = None, out_port = None):
        # assert(ssh_pid != None)
        self.ssh_pid = ssh_pid
        assert(in_port!=None)
        self.in_port = in_port
        assert(via_host!=None)
        self.via_host = via_host
        assert(target_host!=None)
        self.target_host = target_host
        assert(out_port!=None)
        self.out_port = out_port

        self.connections = []

    def repr_tunnel(self):
        return "%i\t%i\t%s\t%s\t%i" % (
            self.ssh_pid,
            self.in_port,
            self.via_host,
            self.target_host,
            self.out_port)

    def repr_connections(self):
        # list of tunnels linked to this process
        rep = ""
        for c in self.connections:
            rep += "\n↳\t%s" % c
        return rep

    def __repr__(self):
        return self.repr_tunnel() + self.repr_connections()


class AutoTunnel(Tunnel):
    def __init__(self, autossh_pid = None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        assert(autossh_pid!=None)
        self.autossh_pid = autossh_pid

    def repr_tunnel(self):
        rep = super().repr_tunnel()
        return "auto\t" + rep


class RawTunnel(Tunnel):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def repr_tunnel(self):
        rep = super().repr_tunnel()
        return "ssh\t" + rep


class Connection:
    """A dictionary that stores an SSH connection related to a tunnel"""

    def __init__(self, local_address = None, in_port = None, foreign_address = None, out_port = None,
            status = None, family = None ):

        # informations available with netstat
        assert(local_address!=None)
        self.local_address = local_address
        assert(in_port!=None)
        self.in_port = in_port
        self.foreign_address = foreign_address
        self.out_port = out_port
        assert(status!=None)
        self.status = status
        assert(family!=None)
        self.family = family

        self.family_rep = {socket.AddressFamily.AF_INET:"INET", socket.AddressFamily.AF_INET6:"INET6", socket.AddressFamily.AF_UNIX:"UNIX"}

        # FIXME would be nice to have an estimation of the connections latency
        #self.latency = 0

    def __repr__(self):
        # do not logging.debug all the informations by default
        if self.foreign_address and self.out_port:
            return "%s:%i -> %s:%i\t%s\t%s" % (
                self.local_address,
                self.in_port,
                self.foreign_address,
                self.out_port,
                self.family_rep[self.family],
                self.status,
                )
        else:
            return "%s:%i\t%s\t%s" % (
                self.local_address,
                self.in_port,
                self.family_rep[self.family],
                self.status,
                )


class TunnelsParser:
    def __init__(self):
        """Warning: the initialization does not gather tunnels informations, use update() to do so"""

        # { ssh_pid : Tunnel }
        self.tunnels = collections.OrderedDict()

        # do not perform update by default
        # this is necessary because one may want
        # only a list of connections OR autossh processes
        #self.update()

        self.re_forwarding = re.compile(r"-L(\d+):(.+):(\d+)")

        self.header = 'TYPE\tPID\tIN_PORT\tVIA_HOST\tTARGET_HOST\tOUT_PORT'


    def get_tunnel(self, pos):
        pid = list(self.tunnels.keys())[pos]
        return self.tunnels[pid]


    def parse(self, cmd):
        cmdline = " ".join(cmd)

        logging.debug('autossh cmd line:', cmdline)
        logging.debug('forwarding regexp:', self.re_forwarding)
        match = self.re_forwarding.findall(cmdline)
        logging.debug(match)
        if match:
            assert(len(match)==1)
            in_port, target_host, out_port = match[0]
            logging.debug("matches: ", match)

        # Find the hostname on wich the tunnel is built.
        via_host = "unknown"
        # Search backward and take the first parameter argument.
        # FIXME this is an ugly hack
        for i in range( len(cmd)-1,0,-1 ):
            if cmd[i][0] != '-':
                via_host = cmd[i]
                break

        return (int(in_port), via_host, target_host, int(out_port))


    def update(self):
        """Gather and parse informations from the operating system"""

        self.tunnels.clear()

        # Browse the SSH processes handling a tunnel.
        for proc in psutil.process_iter():
            try:
                process = proc.as_dict(attrs=['pid','ppid','name','cmdline','connections'])
                cmd = process['cmdline']
            except psutil.NoSuchProcess:
                pass
            else:
                if process['name'] == 'ssh':
                    logging.debug(process)
                    in_port, via_host, target_host, out_port = self.parse(cmd)
                    logging.debug(in_port, via_host, target_host, out_port)

                    # Check if this ssh tunnel is managed by autossh.
                    parent = psutil.Process(process['ppid'])
                    if parent.name() == 'autossh':
                        # Add an autossh tunnel.
                        pid = parent.pid # autossh pid
                        self.tunnels[pid] = AutoTunnel(pid, process['pid'], in_port, via_host, target_host, out_port )
                    else:
                        # Add a raw tunnel.
                        pid = process['pid']
                        self.tunnels[pid] = RawTunnel(pid, in_port, via_host, target_host, out_port )

                    for c in process['connections']:
                        logging.debug(c)
                        laddr,lport = c.laddr
                        if c.raddr:
                            raddr,rport = c.raddr
                        else:
                            raddr,rport = (None,None)
                        connection = Connection(laddr,lport,raddr,rport,c.status,c.family)
                        logging.debug(connection)
                        self.tunnels[pid].connections.append(connection)

        logging.debug(self.tunnels)


    def __repr__(self):
        reps = [self.header]
        for t in self.tunnels:
            reps.append(str(self.tunnels[t]))
        return "\n".join(reps)




























#################################################################################################
# INTERFACES
#################################################################################################

import curses
import time
import signal

class CursesMonitor:
    """Textual user interface to display up-to-date informations about current tunnels"""

    def __init__(self, scr):
        # curses screen
        self.scr = scr

        # tunnels monitor
        self.tp = TunnelsParser()

        # selected line
        self.cur_line = -1

        # selected pid
        self.cur_pid = -1

        # switch to show only autoss processes (False) or ssh connections also (True)
        self.show_connections = False

        # FIXME pass as parameters+options
        self.update_delay = 1 # seconds of delay between two data updates
        self.ui_delay = 0.05 # seconds between two screen update

        # colors
        # FIXME different colors for different types of tunnels (auto or raw)
        self.colors_tunnel = {'kind':4, 'autossh_pid':0, 'in_port':3, 'via_host':2, 'target_host':2, 'out_port':3, 'tunnels_nb':4, 'tunnels_nb_none':1}
        self.colors_highlight = {'kind':9, 'autossh_pid':9, 'in_port':9, 'via_host':9, 'target_host':9, 'out_port':9, 'tunnels_nb':9, 'tunnels_nb_none':9}
        self.colors_connection = {'ssh_pid':0, 'autossh_pid':0, 'status':4, 'status_out':1, 'local_address':2, 'in_port':3, 'foreign_address':2, 'out_port':3}


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
                self.tp.update()
                # reset the counter
                last_update = time.time()

                state = "%s" % self.tp
                if state != last_state:
                    logging.debug("Waited: %s" % log_ticks)
                    log_ticks = ""
                    logging.debug("----- Time of screen update: %s -----" % time.time())
                    logging.debug("State of tunnels:\n%s" % self.tp)
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
                    if type(self.tp.get_tunnel(self.cur_line)) == AutoTunnel:
                        # autossh performs a reload of existing tunnels that it manages
                        logging.debug("SIGUSR1 on PID: %i" % self.cur_pid)
                        os.kill( self.cur_pid, signal.SIGUSR1 )
                    else:
                        logging.debug("Cannot reload a RAW tunnel")

            # Kill autossh process
            elif ch in 'kK':
                logging.debug("Waited: %s" % log_ticks)
                log_ticks = ""
                logging.debug("Key pushed: K")
                if self.cur_pid != -1:
                    # send a SIGKILL
                    # the related process is stopped
                    # FIXME SIGTERM or SIGKILL ?

                    tunnel = self.tp.get_tunnel(self.cur_line)
                    if type(tunnel) == AutoTunnel:
                        logging.debug("SIGKILL on autossh PID: %i" % self.cur_pid)
                        try:
                            os.kill( self.cur_pid, signal.SIGKILL )
                        except OSError:
                            logging.error("No such process: %i" % self.cur_pid)

                    logging.debug("SIGKILL on ssh PID: %i" % tunnel.ssh_pid)
                    try:
                        os.kill( tunnel.ssh_pid, signal.SIGKILL )
                    except OSError:
                        logging.error("No such process: %i" % tunnel.ssh_pid)
                # FIXME update cur_pid or get rid of it everywhere


            # Switch to show ssh connections
            # only available for root
            elif ch in 'tT':# and os.getuid() == 0:
                logging.debug("Waited: %s" % log_ticks)
                log_ticks = ""
                logging.debug("Key pushed: T")
                self.show_connections = not self.show_connections

            # key pushed
            elif kc == curses.KEY_DOWN:
                logging.debug("Waited: %s" % log_ticks)
                log_ticks = ""
                logging.debug("Key pushed: down")
                # if not the end of the list
                if self.cur_line < len(self.tp.tunnels)-1:
                    self.cur_line += 1
                    # get the pid
                    if type(self.tp.get_tunnel(self.cur_line)) == AutoTunnel:
                        self.cur_pid = self.tp.get_tunnel(self.cur_line).autossh_pid
                    else:
                        self.cur_pid = self.tp.get_tunnel(self.cur_line).ssh_pid

            # key up
            elif kc == curses.KEY_UP:
                logging.debug("Waited: %s" % log_ticks)
                log_ticks = ""
                logging.debug("Key pushed: up")
                if self.cur_line > -1:
                    self.cur_line -= 1
                    if self.cur_line > 0:
                        self.cur_pid = self.tp.get_tunnel(self.cur_line).pid

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
        help_msg = "[R]:reload autossh [K]:kill tunnel [Q]:quit"
        # if os.geteuid() == 0:
        help_msg += " [T]:show network connections"
        help_msg += '\n'

        self.scr.addstr(0,0, help_msg, curses.color_pair(4) )
        self.scr.clrtoeol()

        # Second line
        self.scr.addstr( "Active tunnels: ", curses.color_pair(6) )
        self.scr.addstr( str( len(self.tp.tunnels) ), curses.color_pair(1) )
        self.scr.addstr( " / Active connections: ", curses.color_pair(6) )
        self.scr.addstr( str( sum([len(self.tp.tunnels[t].connections) for t in self.tp.tunnels]) ), curses.color_pair(1) )
        self.scr.addstr( '\n', curses.color_pair(1) )
        self.scr.clrtoeol()

        # if no line is selected
        color = 0
        if self.cur_line==-1:
            # selected color for the header
            color = 9
            self.cur_pid = -1

        # header line
        header_msg = "TYPE\tPID \tINPORT\tVIA              \tTARGET              \tOUTPORT"
        # if os.geteuid() == 0:
        header_msg += "\tCONNECTIONS"
        self.scr.addstr( header_msg, curses.color_pair(color) )
        self.scr.clrtoeol()

        # for each autossh processes available in the monitor
        for l in range(len(self.tp.tunnels)):
            # add a line for the l-th autossh process
            self.add_autossh( l )

            # if one want to show connections
            if self.show_connections:# and os.getuid() == 0:
                self.add_connection( l )

        self.scr.clrtobot()


    def add_connection(self, line ):
        """Add lines for each connections related to the l-th autossh process"""

        colors = self.colors_connection

        # for each connections related to te line-th autossh process
        for t in self.tp.get_tunnel(line).connections:
            # FIXME fail if the screen's height is too small.
            self.scr.addstr( '\n\t+ ' )

            # self.scr.addstr( str( t['ssh_pid'] ), curses.color_pair(colors['ssh_pid'] ) )
            # self.scr.addstr( '\t' )
            self.scr.addstr( str( t.local_address ) , curses.color_pair(colors['local_address'] ))
            self.scr.addstr( ':' )
            self.scr.addstr( str( t.in_port ) , curses.color_pair(colors['in_port'] ))
            self.scr.addstr( ' -> ' )
            self.scr.addstr( str( t.foreign_address ) , curses.color_pair(colors['foreign_address'] ))
            self.scr.addstr( ':' )
            self.scr.addstr( str( t.out_port ) , curses.color_pair(colors['out_port'] ))

            self.scr.addstr( '\t' )

            color = self.colors_connection['status']
            # if the connections is established
            # TODO avoid hard-coded constants
            if t.status != 'ESTABLISHED':
                color = self.colors_connection['status_out']

            self.scr.addstr( t.status, curses.color_pair( color ) )

            self.scr.clrtoeol()


    def add_autossh(self, line):
        """Add line corresponding to the line-th autossh process"""
        self.scr.addstr( '\n' )

        if type(self.tp.get_tunnel(line)) == AutoTunnel:
            self.scr.addstr( 'auto', curses.color_pair(self.colors_tunnel['kind']) )
            self.scr.addstr( '\t',   curses.color_pair(self.colors_tunnel['kind'])  )
        else:
            self.scr.addstr( 'ssh',  curses.color_pair(self.colors_tunnel['kind']) )
            self.scr.addstr( '\t',   curses.color_pair(self.colors_tunnel['kind'])  )

        self.add_autossh_info('autossh_pid', line)
        self.add_autossh_info('in_port', line)
        self.add_autossh_info('via_host', line)
        self.add_autossh_info('target_host', line)
        self.add_autossh_info('out_port', line)

        nb = len(self.tp.get_tunnel(line).connections )
        if nb > 0:
            # for each connection related to this process
            for i in self.tp.get_tunnel(line).connections:
                # add a vertical bar |
                # the color change according to the status of the connection
                if i.status == 'ESTABLISHED':
                    self.scr.addstr( '|', curses.color_pair(self.colors_connection['status']) )
                else:
                    self.scr.addstr( '|', curses.color_pair(self.colors_connection['status_out']) )

        else:
            # if os.geteuid() == 0:
            # if there is no connection, display a "None"
            self.scr.addstr( 'None', curses.color_pair(self.colors_tunnel['tunnels_nb_none']) )

        self.scr.clrtoeol()

    def add_autossh_info( self, key, line ):
        """Add an information of an autossh process, in the configured color"""

        colors = self.colors_tunnel
        # if the line is selected
        if self.cur_line == line:
            # set the color to the highlight one
            colors =  self.colors_highlight

        txt = eval("str(self.tp.get_tunnel(line).%s)" % key)
        if key == 'target_host' or key == 'via_host':
            # limit the size of the line to 20
            # FIXME avoid hard-coded constants
            txt = eval("str(self.tp.get_tunnel(line).%s).ljust(20)[:20]" % key)

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
        help="Display only SSH connections related to a tunnel.")

    parser.add_option("-u", "--tunnels",
        action="store_true", default=False,
        help="Display only the list of tunnels processes.")

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
            mc = CursesMonitor( scr )
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
        tp = TunnelsParser()
        tp.update()
        # do not call update() but only get connections
        logging.debug("UID: %i." % os.geteuid())
        # if os.geteuid() == 0:
        for t in tp.tunnels:
            for c in tp.tunnels[t].connections:
                print(tp.tunnels[t].ssh_pid, c)

        # else:
        #     logging.error("Only root can see SSH tunnels connections.")


    elif asked_for.tunnels:
        logging.debug("Entering tunnel mode")
        tp = TunnelsParser()
        tp.update()
        # do not call update() bu only get autossh processes
        print(tp.header)
        for t in tp.tunnels:
            if type(tp.tunnels[t]) == AutoTunnel:
                print(tp.tunnels[t].repr_tunnel())


    else:
        logging.debug("Entering default mode")
        tp = TunnelsParser()
        # call update
        tp.update()
        # call the default __repr__
        print(tp)


#
# In Mesopotamian mythology, Ereshkigal (lit. "great lady under earth")
# was the goddess of Irkalla, the land of the dead or underworld.
#
# Thus, she knows a lot about tunnels...
#
# http://en.wikipedia.org/wiki/Ereshkigal
#

