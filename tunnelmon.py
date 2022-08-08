#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Tunnelmon is an AutoSSH tunnel monitor
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

import signal
import time
import curses
import os
import subprocess
import logging
import psutil
import socket
import re
import collections
import itertools


class Tunnel:
    def __init__(self, ssh_pid=None, in_port=None, via_host=None, target_host=None, out_port=None):
        # assert ssh_pid is not None
        self.ssh_pid = ssh_pid
        assert in_port is not None
        self.in_port = in_port
        assert via_host is not None
        self.via_host = via_host
        assert target_host is not None
        self.target_host = target_host
        assert out_port is not None
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
            rep += "\n\t↳ %s" % c
        return rep

    def __repr__(self):
        return self.repr_tunnel() + self.repr_connections()


class AutoTunnel(Tunnel):
    def __init__(self, autossh_pid=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        assert autossh_pid is not None
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

    def __init__(self, local_address=None, in_port=None, foreign_address=None, out_port=None,
                 status=None, family=None):

        # informations available with netstat
        assert local_address is not None
        self.local_address = local_address
        assert in_port is not None
        self.in_port = in_port
        self.foreign_address = foreign_address
        self.out_port = out_port
        assert status is not None
        self.status = status
        assert family is not None
        self.family = family

        self.family_rep = {socket.AddressFamily.AF_INET: "INET", socket.AddressFamily.AF_INET6: "INET6", socket.AddressFamily.AF_UNIX: "UNIX"}

        # FIXME would be nice to have an estimation of the connections latency
        #self.latency = 0

    def __repr__(self):
        # do not logging.debug all the informations by default
        if self.foreign_address and self.out_port:
            return "%s\t%s\t%s:%i → %s:%i" % (
                self.family_rep[self.family],
                self.status,
                self.local_address,
                self.in_port,
                self.foreign_address,
                self.out_port,
            )
        else:
            return "%s\t%s\t%s:%i" % (
                self.family_rep[self.family],
                self.status,
                self.local_address,
                self.in_port,
            )


class TunnelsParser:
    def __init__(self):
        """Warning: the initialization does not gather tunnels informations, use update() to do so"""

        # { ssh_pid : Tunnel }
        self.tunnels = collections.OrderedDict()

        # do not perform update by default
        # this is necessary because one may want
        # only a list of connections OR autossh processes
        # self.update()

        self.re_forwarding = re.compile(r"-\w*[LRD]\w*\s*(\d+):(.*):(\d+)")

        self.header = 'TYPE\tSSH_PID\tIN_PORT\tVIA_HOST\tTARGET_HOST\tOUT_PORT'

    def get_tunnel(self, pos):
        pid = list(self.tunnels.keys())[pos]
        return self.tunnels[pid]

    def parse(self, cmd):
        cmdline = " ".join(cmd)

        logging.debug('autossh cmd line: %s', cmdline)
        logging.debug('forwarding regexp: %s', self.re_forwarding)
        match = self.re_forwarding.findall(cmdline)
        logging.debug(match)
        if match:
            assert len(match) == 1
            in_port, target_host, out_port = match[0]
            logging.debug("matches: %s", match)
        else:
            raise ValueError("is not a ssh tunnel")

        # Find the hostname on wich the tunnel is built.
        via_host = "unknown"
        # Search backward and take the first parameter argument.
        # FIXME this is an ugly hack
        i = 1
        while i < len(cmd):
            logging.debug("ici: %i %s", i, cmd[i])
            if cmd[i][0] == '-':
                if cmd[i][1] in '46AaCfGgKkMNnqsTtVvXxYy':
                    # flag without argument
                    pass
                elif len(cmd[i]) == 2:  # the argument is likely the next one
                    if (i < len(cmd) - 1) and (cmd[i + 1][0] != '-'):  # not another flag (this should always be true)
                        i += 1  # skip the argument
                # skip the argument
                i += 1
            else:
                via_host = cmd[i]
                break

        return int(in_port), via_host, target_host, int(out_port)

    def update(self):
        """Gather and parse informations from the operating system"""

        self.tunnels.clear()

        # Browse the SSH processes handling a tunnel.
        for proc in psutil.process_iter():
            try:
                process = proc.as_dict(attrs=['pid', 'ppid', 'name', 'cmdline', 'connections'])
                cmd = process['cmdline']
            except psutil.NoSuchProcess:
                pass
            else:
                if process['name'] == 'ssh':
                    logging.debug(process)
                    try:
                        in_port, via_host, target_host, out_port = self.parse(cmd)
                    except ValueError:
                        continue
                    logging.debug("%s %s %s %s", in_port, via_host, target_host, out_port)

                    # Check if this ssh tunnel is managed by autossh.
                    parent = psutil.Process(process['ppid'])
                    if parent.name() == 'autossh':
                        # Add an autossh tunnel.
                        pid = parent.pid  # autossh pid
                        self.tunnels[pid] = AutoTunnel(pid, process['pid'], in_port, via_host, target_host, out_port)
                    else:
                        # Add a raw tunnel.
                        pid = process['pid']
                        self.tunnels[pid] = RawTunnel(pid, in_port, via_host, target_host, out_port)

                    for c in process['connections']:
                        logging.debug(c)
                        laddr, lport = c.laddr
                        if c.raddr:
                            raddr, rport = c.raddr
                        else:
                            raddr, rport = (None, None)
                        connection = Connection(laddr, lport, raddr, rport, c.status, c.family)
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
        self.update_delay = 1  # seconds of delay between two data updates
        self.ui_delay = 0.05  # seconds between two screen update

        # colors
        # FIXME different colors for different types of tunnels (auto or raw)
        self.colors_tunnel = {'kind_auto': 4, 'kind_raw': 5, 'ssh_pid': 0, 'in_port': 3,
                              'via_host': 2, 'target_host': 2, 'out_port': 3, 'tunnels_nb': 4, 'tunnels_nb_none': 1}
        self.colors_highlight = {'kind_auto': 9, 'kind_raw': 9, 'ssh_pid': 9, 'in_port': 9,
                                 'via_host': 9, 'target_host': 9, 'out_port': 9, 'tunnels_nb': 9, 'tunnels_nb_none': 9}
        self.colors_connection = {'ssh_pid': 0, 'autossh_pid': 0, 'status': 4, 'status_out': 1,
                                  'local_address': 2, 'in_port': 3, 'foreign_address': 2, 'out_port': 3}

        self.header = ("TYPE", "SSHPID", "INPORT", "VIA", "TARGET", "OUTPORT")

    def do_Q(self):
        """Quit"""
        logging.debug("Waited: %s" % self.log_ticks)
        self.log_ticks = ""
        logging.debug("Key pushed: Q")
        return False

    def do_R(self):
        """Reload autossh tunnel"""
        logging.debug("Waited: %s" % self.log_ticks)
        self.log_ticks = ""
        logging.debug("Key pushed: R")
        # if a pid is selected
        if self.cur_pid != -1:
            # send the SIGUSR1 signal
            if type(self.tp.get_tunnel(self.cur_line)) == AutoTunnel:
                # autossh performs a reload of existing tunnels that it manages
                logging.debug("SIGUSR1 on PID: %i" % self.cur_pid)
                os.kill(self.cur_pid, signal.SIGUSR1)
            else:
                logging.debug("Cannot reload a RAW tunnel")
        return True

    def do_C(self):
        """Close tunnel"""
        logging.debug("Waited: %s" % self.log_ticks)
        self.log_ticks = ""
        logging.debug("Key pushed: C")
        if self.cur_pid != -1:
            # send a SIGKILL
            # the related process is stopped
            # FIXME SIGTERM or SIGKILL ?

            tunnel = self.tp.get_tunnel(self.cur_line)
            if type(tunnel) == AutoTunnel:
                logging.debug("SIGKILL on autossh PID: %i" % self.cur_pid)
                try:
                    os.kill(self.cur_pid, signal.SIGKILL)
                except OSError:
                    logging.error("No such process: %i" % self.cur_pid)

            logging.debug("SIGKILL on ssh PID: %i" % tunnel.ssh_pid)
            try:
                os.kill(tunnel.ssh_pid, signal.SIGKILL)
            except OSError:
                logging.error("No such process: %i" % tunnel.ssh_pid)
        self.cur_line -= 1
        self.cur_pid = -1
        # FIXME update cur_pid or get rid of it everywhere
        return True

    def do_N(self):
        """Show connections"""
        logging.debug("Waited: %s" % self.log_ticks)
        self.log_ticks = ""
        logging.debug("Key pushed: N")
        self.show_connections = not self.show_connections
        return True

    def do_258(self):
        """Move down"""
        logging.debug("Waited: %s" % self.log_ticks)
        self.log_ticks = ""
        logging.debug("Key pushed: down")
        # if not the end of the list
        if self.cur_line < len(self.tp.tunnels)-1:
            self.cur_line += 1
            # get the pid
            if type(self.tp.get_tunnel(self.cur_line)) == AutoTunnel:
                self.cur_pid = self.tp.get_tunnel(self.cur_line).autossh_pid
            else:
                self.cur_pid = self.tp.get_tunnel(self.cur_line).ssh_pid
        return True

    def do_259(self):
        """Move up"""
        logging.debug("Waited: %s" % self.log_ticks)
        self.log_ticks = ""
        logging.debug("Key pushed: up")
        if self.cur_line > -1:
            self.cur_line -= 1
            if self.cur_line > 0:
                self.cur_pid = self.tp.get_tunnel(self.cur_line).ssh_pid
        return True

    def __call__(self):
        """Start the interface"""

        self.scr.clear()  # clear all
        self.scr.nodelay(1)  # non-bloking getch

        # first display
        self.display()

        # first update counter
        self.last_update = time.perf_counter()
        self.last_state = None
        self.log_ticks = ""

        # infinite loop
        notquit = True
        while(notquit):

            # wait some time
            # necessary to not overload the system with unnecessary calls
            time.sleep(self.ui_delay)

            # if its time to update
            if time.time() > self.last_update + self.update_delay:
                self.tp.update()
                # reset the counter
                self.last_update = time.time()

                state = "%s" % self.tp
                if state != self.last_state:
                    logging.debug("Waited: %s" % self.log_ticks)
                    self.log_ticks = ""
                    logging.debug("----- Time of screen update: %s -----" % time.time())
                    logging.debug("State of tunnels:\n%s" % self.tp)
                    self.last_state = state
                else:
                    self.log_ticks += "."

            kc = self.scr.getch()  # keycode

            if kc != -1:  # if keypress
                pass

            ch = chr(0)

            if 0 < kc < 256:  # if ascii key
                # ascii character from the keycode
                ch = chr(kc)

            # Call the do_* handler.
            fch = "do_%s" % ch.capitalize()
            fkc = "do_%i" % kc
            logging.debug("key func: %s / %s" % (fch, fkc))
            if fch in dir(self):
                notquit = eval("self."+fch+"()")
            elif fkc in dir(self):
                notquit = eval("self."+fkc+"()")
            logging.debug("notquit = %s" % notquit)

            # update the display
            self.display()

            # force a screen refresh
            self.scr.refresh()

        # end of the loop

    def format(self):
        reps = [self.tp.tunnels[t].repr_tunnel() for t in self.tp.tunnels]
        tuns = [t.split() for t in reps]
        tuns.append(self.header)
        cols = itertools.zip_longest(*tuns, fillvalue='')
        widths = [max(len(s) for s in col) for col in cols]
        logging.debug(widths)
        fmt = ['{{: <{}}}'.format(w) for w in widths]
        logging.debug(fmt)
        return fmt

    def display(self):
        """Generate the interface screen"""

        # Automagically format help line with available do_* handlers.
        h = []
        for f in dir(self):
            if "do_" in f:
                key = f.replace("do_", "")
                if key.isalpha():  # We do not want arrows.
                    msg = "[%s] %s" % (key, eval("self.%s.__doc__" % f))
                    h.append(msg)
        help_msg = ", ".join(h)
        help_msg += "\n"

        self.scr.addstr(0, 0, help_msg, curses.color_pair(4))
        self.scr.clrtoeol()

        # Second line
        self.scr.addstr("Active tunnels: ", curses.color_pair(6))
        self.scr.addstr(str(len(self.tp.tunnels)), curses.color_pair(1))
        self.scr.addstr(" / Active connections: ", curses.color_pair(6))
        self.scr.addstr(str(sum([len(self.tp.tunnels[t].connections) for t in self.tp.tunnels])), curses.color_pair(1))
        self.scr.addstr('\n', curses.color_pair(1))
        self.scr.clrtoeol()

        # if no line is selected
        color = 0
        if self.cur_line == -1:
            # selected color for the header
            color = 9
            self.cur_pid = -1

        # header line
        # header_msg = "TYPE\tINPORT\tVIA              \tTARGET              \tOUTPORT"
        # if os.geteuid() == 0:
        header_msg = " ".join(self.format()).format(*self.header)
        header_msg += " CONNECTIONS"
        self.scr.addstr(header_msg, curses.color_pair(color))
        self.scr.clrtoeol()

        # for each tunnel processes available in the monitor
        for l in range(len(self.tp.tunnels)):
            # add a line for the l-th autossh process
            self.add_tunnel(l)

            # if one want to show connections
            if self.show_connections:  # and os.getuid() == 0:
                self.add_connection(l)

        self.scr.clrtobot()

    def add_connection(self, line):
        """Add lines for each connections related to the l-th autossh process"""

        colors = self.colors_connection

        # for each connections related to te line-th autossh process
        for t in sorted(self.tp.get_tunnel(line).connections, key=lambda c: c.status):

            # FIXME fail if the screen's height is too small.
            self.scr.addstr('\n\t+ ')

            color = self.colors_connection['status']
            # if the connections is established
            # TODO avoid hard-coded constants
            if t.status != 'ESTABLISHED' and t.status != 'LISTEN':
                color = self.colors_connection['status_out']

            self.scr.addstr(t.status, curses.color_pair(color))

            self.scr.addstr('\t')

            # self.scr.addstr( str( t['ssh_pid'] ), curses.color_pair(colors['ssh_pid'] ) )
            # self.scr.addstr( '\t' )
            self.scr.addstr(str(t.local_address), curses.color_pair(colors['local_address']))
            self.scr.addstr(':')
            self.scr.addstr(str(t.in_port), curses.color_pair(colors['in_port']))
            if t.foreign_address and t.out_port:
                self.scr.addstr(' -> ')
                self.scr.addstr(str(t.foreign_address), curses.color_pair(colors['foreign_address']))
                self.scr.addstr(':')
                self.scr.addstr(str(t.out_port), curses.color_pair(colors['out_port']))

            self.scr.clrtoeol()

    def add_tunnel(self, line):
        """Add line corresponding to the line-th autossh process"""
        self.scr.addstr('\n')

        colors = self.colors_tunnel
        if self.cur_line == line:
            colors = self.colors_highlight

        if type(self.tp.get_tunnel(line)) == AutoTunnel:
            self.scr.addstr(self.format()[0].format('auto'), curses.color_pair(colors['kind_auto']))
            self.scr.addstr(' ',   curses.color_pair(colors['kind_auto']))
        else:
            self.scr.addstr(self.format()[0].format('ssh'),  curses.color_pair(colors['kind_raw']))
            self.scr.addstr(' ',   curses.color_pair(colors['kind_raw']))

        # self.add_tunnel_info('ssh_pid', line)
        self.add_tunnel_info('ssh_pid', line, 1)
        self.add_tunnel_info('in_port', line, 2)
        self.add_tunnel_info('via_host', line, 3)
        self.add_tunnel_info('target_host', line, 4)
        self.add_tunnel_info('out_port', line, 5)

        nb = len(self.tp.get_tunnel(line).connections)
        if nb > 0:
            # for each connection related to this process
            for i in self.tp.get_tunnel(line).connections:
                # add a vertical bar |
                # the color change according to the status of the connection
                if i.status == 'ESTABLISHED' or i.status == 'LISTEN':
                    self.scr.addstr('|', curses.color_pair(self.colors_connection['status']))
                else:
                    self.scr.addstr('|', curses.color_pair(self.colors_connection['status_out']))

        else:
            # if os.geteuid() == 0:
            # if there is no connection, display a "None"
            self.scr.addstr('None', curses.color_pair(self.colors_tunnel['tunnels_nb_none']))

        self.scr.clrtoeol()

    def add_tunnel_info(self, key, line, col):
        """Add an information of an autossh process, in the configured color"""

        colors = self.colors_tunnel
        # if the line is selected
        if self.cur_line == line:
            # set the color to the highlight one
            colors = self.colors_highlight

        txt = eval("str(self.tp.get_tunnel(line).%s)" % key)
        if key == 'target_host' or key == 'via_host':
            txt = eval("str(self.tp.get_tunnel(line).%s)" % key)

        self.scr.addstr(self.format()[col].format(txt), curses.color_pair(colors[key]))
        self.scr.addstr(' ', curses.color_pair(colors[key]))


if __name__ == "__main__":
    import sys
    from optparse import OptionParser
    import configparser

    usage = """%prog [options]
    A user interface to monitor existing SSH tunnel that are managed with autossh.
    Called without options, Tunnelmon displays a list of tunnels on the standard output.
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

    LOG_LEVELS = {'error': logging.ERROR,
                  'warning': logging.WARNING,
                  'debug': logging.DEBUG}

    parser.add_option('-l', '--log-level', choices=list(LOG_LEVELS), default='error', metavar='LEVEL',
                      help='Log level (%s), default: %s.' % (", ".join(LOG_LEVELS), 'error'))

    parser.add_option('-g', '--log-file', default=None, metavar='FILE',
                      help="Log to this file, default to standard output. \
            If you use the curses interface, you may want to set this to actually see logs.")

    parser.add_option('-f', '--config-file', default=None, metavar='FILE',
                      help="Use this configuration file (default: '~/.tunnelmon.conf')")

    (asked_for, args) = parser.parse_args()

    logmsg = "----- Started Tunnelmon -----"

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

    logging.debug("Asked for: %s", asked_for)

    # unfortunately, asked_for class has no __len__ method in python 2.4.3 (bug?)
    # if len(asked_for) > 1:
    #    parser.error("asked_for are mutually exclusive")

    config = configparser.ConfigParser()
    if asked_for.config_file:
        try:
            config.read(asked_for.config_file)
        except configparser.MissingSectionHeaderError:
            logging.error("'%s' contains no known configuration", asked_for.config_file)
    else:
        try:
            config.read('~/.tunnelmon.conf')
        except configparser.MissingSectionHeaderError:
            logging.error("'%s' contains no known configuration", asked_for.config_file)

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
            mc = CursesMonitor(scr)
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
        logging.debug("UID: %i.", os.geteuid())
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
            print(tp.tunnels[t].repr_tunnel())

    else:
        logging.debug("Entering default mode")
        tp = TunnelsParser()
        # call update
        tp.update()
        # call the default __repr__
        print(tp)

