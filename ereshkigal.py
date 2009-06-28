#!/usr/bin/python
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
# Author : Johann "nojhan" Dréo <nojhan@gmail.com>
#

#################################################################################################
# CORE
#################################################################################################

import os

# fort sorting dictionaries easily
from operator import itemgetter

class SSHTunnel(dict):
    """A dictionary that stores an SSH connection related to a tunnel"""

    def __init__(self, 
	    local_address = '1.1.1.1',
	    local_port = 0,
	    foreign_address = '1.1.1.1',
	    foreign_port = 0,
	    target_host = "Unknown",
	    status = 'UNKNOWN',
	    ssh_pid = 0,
	    autossh_pid = 0
	    ):

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
	return "%i %i %s %s" % (
		self['autossh_pid'],
		self['local_port'], 
		self['target_host'], 
		self['status']
		)


class AutoSSHInstance(dict):
    """A dictionary that stores an autossh process"""

    def __init__(self, pid = 0, local_port = 0, target_host = "Unknown",foreign_port = 0):

	# some informations available on /proc
	self['pid'] = pid
	self['local_port'] = local_port
	self['target_host'] = target_host
	self['foreign_port'] = foreign_port
	self['tunnels'] = []

    def __repr__(self):
	# single informations
	repr = "%i %i %s %i" % ( 
		self['pid'], 
		self['local_port'], 
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

	# ssh connections related to a tunnel
	connections = self.get_connections()

	# bind existing connections to autossh processes
	self[:] = self.bind_tunnels(autosshs, connections)

	# sort on a given key
	self.sort_on( 'local_port')


    def __repr__(self):
	repr = "PID PORT HOST PORT TUNNELS\n"
	
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
	status = os.popen3( self.ps_cmd )

	# list of processes with the "autossh" string
	status_list = [ps for ps in status[1].readlines() if "autossh" in ps]

	# split the process line if it contains a "-L"
	list = [i.split() for i in status_list if '-L' in i]

	autosshs = []

	for cmd in list:
	    
	    # split the command in order to obtain arguments to the -L option
	    args = [i.strip('-').strip('-').strip('L') for i in cmd if '-L' in i][0].split(':')

	    pid = int(cmd[0])
	    local_port = int(args[0])
	    target_host = args[1]
	    foreign_port = int(args[2])

	    auto = AutoSSHInstance( pid, local_port, target_host, foreign_port )

	    autosshs += [auto]

	return autosshs


    def get_connections(self):
	"""Gather and parse ssh connections related to a tunnel"""

	status = os.popen3( self.network_cmd )
	
	status_list = status[1].readlines()
	
	list = [i.split() for i in status_list if 'ssh' in i]
	
	tunnels = []
	
	for con in list:

	    # local infos
	    local = con[3].split(':')
	    local_addr = local[0] 
	    local_port = int(local[1])

	    # foreign infos
	    foreign = con[4].split(':')
	    foreign_addr = foreign[0]
	    foreign_port = int(foreign[1])

	    status = con[5]

	    sshpid = int( con[6].split('/')[0] )

	    # ssh cmd line, got from /proc
	    f = open( '/proc/' + str(sshpid) + '/cmdline' )
	    cmd = f.readlines()[0]

	    # if not an ssh tunnel command
	    if ('-L' not in cmd) and (':' not in cmd):
		# do not list it
		continue

	    f.close()

	    # autossh parent process
	    f = open( '/proc/' + str(sshpid) + '/status' )

	    # filter the parent pid
	    lpid = [i for i in f.readlines() if 'PPid' in i]

	    f.close()

	    # parsing
	    ppid = int(lpid[0].split(':')[1].strip())

	    # command line of the parent process
	    f = open( '/proc/' + str(ppid) + '/cmdline' )

	    # exclude the port
	    autohost = f.readlines()[0].split(':')[1]

	    f.close()

	    # instanciation
	    tunnels += [ SSHTunnel( local_addr, local_port, foreign_addr, foreign_port, autohost, status, sshpid, ppid ) ]

	return tunnels


    def bind_tunnels(self, autosshs, tunnels):
	"""Bind autossh process to the related ssh connections, according to the pid"""
	for t in tunnels:
	    for i in autosshs:
		if i['pid'] == ppid:
		    # add to the list of tunnels of the AutoSSHInstance instance
		    i['tunnels'] += [t]

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
	self.colors_autossh = {'pid':0, 'local_port':3, 'target_host':2, 'foreign_port':3, 'tunnels_nb':4, 'tunnels_nb_none':1}
	self.colors_highlight = {'pid':9, 'local_port':9, 'target_host':9, 'foreign_port':9, 'tunnels_nb':9, 'tunnels_nb_none':9}
	self.colors_ssh = {'ssh_pid':0, 'status':4, 'status_out':1, 'local_address':2, 'local_port':3, 'foreign_address':2, 'foreign_port':3}


    def __call__(self):
	"""Start the interface"""

	self.scr.clear() # clear all
	self.scr.nodelay(1) # non-bloking getch

	# first display
	self.display()

	# first update counter
	last_update = time.clock()

	# infinit loop
	while(1):

	    # wait some time
	    # necessary to not overload the system with unnecessary calls
	    time.sleep( self.ui_delay )

	    # if its time to update
	    if time.time() > last_update + self.update_delay:
		self.tm.update()
		# reset the counter
		last_update = time.time()
	    
	    kc = self.scr.getch() # keycode
		    
	    if kc != -1: # if keypress
		pass

	    if 0 < kc < 256: # if ascii key
		# ascii character from the keycode
		ch = chr(kc)

		# Quit
		if ch in 'Qq':
		    break

		# Reload related autossh tunnels
		elif ch in 'rR':
		    # if a pid is selected
		    if self.cur_pid != -1:
			# send the SIGUSR1 signal
			# autossh performs a reload of existing tunnels that it manages
			os.kill( self.cur_pid, signal.SIGUSR1 )

		# Kill autossh process
		elif ch in 'kK':
		    if self.cur_pid != -1:
			# send a SIGKILL
			# the related process is stopped
			# FIXME SIGTERM or SIGKILL ?
			os.kill( self.cur_pid, signal.SIGKILL )

		# Switch to show ssh connections
		elif ch in 'tT':
		    self.show_tunnels = not self.show_tunnels

	    # key down
	    elif kc == curses.KEY_DOWN:
		# if not the end of the list
		if self.cur_line < len(self.tm)-1:
		    self.cur_line += 1
		    # get the pid
		    self.cur_pid = int(self.tm[self.cur_line]['pid'])

	    # key up
	    elif kc == curses.KEY_UP:
		if self.cur_line > -1:
		    self.cur_line -= 1
		    self.cur_pid = int(self.tm[self.cur_line]['pid'])

	    else:
		# do nothing and wait until the next refresh
		pass

	    # update the display
	    self.display()

	    # force a screen refresh
	    self.scr.refresh()


    def display(self):
	"""Generate the interface screen"""

	# First line: help
	self.scr.addstr(0,0, "[R]:reload autossh [K]:kill autossh [Q]:quit [T]:show tunnels connections\n", curses.color_pair(4) )
	self.scr.clrtoeol()

	# Second line
	self.scr.addstr( "Active AutoSSH instances: ", curses.color_pair(6) )
	self.scr.addstr( str( len(self.tm) ), curses.color_pair(1) )
	self.scr.addstr( '\n', curses.color_pair(1) )
	self.scr.clrtoeol()

	# if no line is selected
	color = 0
	if self.cur_line==-1:
	    # selected color for the header
	    color = 9
	    self.cur_pid = -1

	# header line
	self.scr.addstr( "PID \tINPORT\tHOST              \tOUTPORT\tCONNECTIONS", curses.color_pair(color) )
	self.scr.clrtoeol()

	# for each autossh processes available in the monitor
	for l in xrange(len(self.tm)):
	    # add a line for the l-th autossh process
	    self.add_autossh( l )
	    
	    # if one want to show connections
	    if self.show_tunnels:
		self.add_tunnel( l )

	self.scr.clrtobot()


    def add_tunnel(self, line ):
	"""Add lines for each connections related to the l-th autossh process"""

	colors = self.colors_ssh

	# for each connections related to te line-th autossh process
	for t in self.tm[line]['tunnels']:
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
	    if t['status'] != 'ESTABLISHED':
		color = self.colors_ssh['status_out']

	    self.scr.addstr( str( t['status'] ), curses.color_pair( color ) )

	    self.scr.clrtoeol()


    def add_autossh(self, line):
	"""Add line corresponding to the line-th autossh process"""
	self.scr.addstr( '\n' )
	self.add_autossh_info('pid', line)
	self.add_autossh_info('local_port', line)
	self.add_autossh_info('target_host', line)
	self.add_autossh_info('foreign_port', line)
	
	nb = len(self.tm[line]['tunnels'] )
	if nb > 0:
	    # for each connection related to this process
	    for i in self.tm[line]['tunnels']:
		# add a vertical bar |
		# the color change according to the status of the connection
		if i['status'] == 'ESTABLISHED':
		    self.scr.addstr( '|', curses.color_pair(self.colors_ssh['status']) )
		else:
		    self.scr.addstr( '|', curses.color_pair(self.colors_ssh['status_out']) )

	else:
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
	if key == 'target_host':
	    # limit the size of the line to 20
	    # TODO avoid hard-coded constants
	    txt = str(self.tm[line][key]).ljust(20)[:20]

	self.scr.addstr( txt, curses.color_pair(colors[key]) )
	self.scr.addstr( '\t', curses.color_pair(colors[key])  )


if __name__ == "__main__":
    import sys
    from optparse import OptionParser

    usage = """%prog [options]
A user interface to monitor existing SSH tunnel that are managed with autossh.
Called without options, ereshkigal displays a list of tunnels on the standard output."""
    parser = OptionParser(usage=usage)

    parser.add_option("-c", "--curses", action="store_true", dest="curses", default=False,
	    help="start the user interface in text mode")
    parser.add_option("-n", "--connections", action="store_true", dest="connections", default=False,
	    help="display only SSH connections related to a tunnel")
    parser.add_option("-a", "--autossh", action="store_true", dest="autossh", default=False,
	    help="display only the list of autossh processes")

    (options, args) = parser.parse_args()

    # unfortunately, options class has no __len__ method in python 2.4.3 (bug?)
    #if len(options) > 1:
    #	parser.error("options are mutually exclusive")


    if  options.curses:
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


    elif options.connections:
	    tm = AutoSSHTunnelMonitor()
	    # do not call update() but only get connections
	    con = tm.get_connections()
	    for c in con:
		    print con


    elif options.autossh:
	    tm = AutoSSHTunnelMonitor()
	    # do not call update() bu only get autossh processes
	    auto = tm.get_autossh_instances()
	    for i in auto:
		    print auto


    else:
	tm = AutoSSHTunnelMonitor()
	# call update
	tm.update()
	# call the default __repr__
	print tm


#
# In Mesopotamian mythology, Ereshkigal (lit. "great lady under earth")
# was the goddess of Irkalla, the land of the dead or underworld.
#
# Thus, she knows a lot about tunnels...
#
# http://en.wikipedia.org/wiki/Ereshkigal
#

