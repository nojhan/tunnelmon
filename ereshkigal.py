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

# Google's ipaddr module
# standard in Python 3
import ipaddr

import os
from operator import itemgetter

class SSHTunnel(dict):
    def __init__(self, 
	    _local_address = ipaddr.IPv4('1.1.1.1'),
	    _local_port = 0,
	    #_local_host = "Unknown",
	    _foreign_address = ipaddr.IPv4('1.1.1.1'),
	    _foreign_port = 0,
	    _target_host = "Unknown",
	    _status = 'UNKNOWN',
	    _ssh_pid = 0,
	    _autossh_pid = 0
	    ):

	self.stats = [
		'ESTABLISHED',
		'SYN_SENT',
		'SYN_RECV',
		'FIN_WAIT1',
		'FIN_WAIT2',
		'TIME_WAIT',
		'CLOSED',
		'CLOSE_WAIT',
		'LAST_ACK',
		'LISTEN',
		'CLOSING',
		'UNKNOWN'
		]

	self['local_address'] = _local_address
	self['local_port'] = _local_port
	#self['local_host'] = _local_host
	self['foreign_address'] = _foreign_address
	self['foreign_port'] = _foreign_port
	self['target_host'] = _target_host
	self['status'] = _status
	self['ssh_pid'] = _ssh_pid
	self['autossh_pid'] = _autossh_pid

	#self.latency = 0
	
    def __repr__(self):

	return "%i %i %s %s" % (
		self['autossh_pid'],
		self['local_port'], 
		self['target_host'], 
		self['status']
		)

class AutoSSHInstance(dict):
    def __init__(self, pid = 0, local_port = 0, target_host = "Unknown",foreign_port = 0):
	self['pid'] = pid
	self['local_port'] = local_port
	self['target_host'] = target_host
	self['foreign_port'] = foreign_port
	self['tunnels'] = []

    def __repr__(self):
	repr = "%i %i %s %i" % ( 
		self['pid'], 
		self['local_port'], 
		self['target_host'], 
		self['foreign_port'])

	for t in self['tunnels']:
	    repr += "\n\t↳ %s" % t
	
	return repr



class AutoSSHTunnelMonitor(list):
    def __init__(self):
	self.network_cmd = "netstat -ntp"
	self.ps_cmd = "ps ax"
	self.update()


    def update(self):
	self[:] = self.__get_tunnels()
	self.sort_on( 'local_port')


    def __repr__(self):
	repr = "PID PORT HOST PORT TUNNELS\n"
	
	for t in self:
	    repr += "%s\n" % t
	return repr
    

    def sort_on(self, key = 'autossh_pid' ):
	self[:] = sorted( self, key=itemgetter( key ) )


    def __get_tunnels(self):
	status = os.popen3( self.ps_cmd )

	status_list = [ps for ps in status[1].readlines() if "autossh" in ps]

	list = [i.split() for i in status_list if '-L' in i]

	autosshs = []

	for cmd in list:

	    args = [i.strip('-').strip('-').strip('L') for i in cmd if '-L' in i][0].split(':')

	    pid = int(cmd[0])
	    local_port = int(args[0])
	    target_host = args[1]
	    foreign_port = int(args[2])

	    auto = AutoSSHInstance( pid, local_port, target_host, foreign_port )

	    autosshs += [auto]


	status = os.popen3( self.network_cmd )
	
	status_list = status[1].readlines()
	
	list = [i.split() for i in status_list if 'ssh' in i]
	
	tunnels = []
	
	for con in list:

	    # tcp connections
	    local = con[3].split(':')
	    local_addr = ipaddr.IPv4( local[0] )
	    local_port = int(local[1])

	    foreign = con[4].split(':')
	    foreign_addr = ipaddr.IPv4( foreign[0] )
	    foreign_port = int(foreign[1])

	    status = con[5]

	    sshpid = int( con[6].split('/')[0] )

	    # ssh cmd line
	    f = open( '/proc/' + str(sshpid) + '/cmdline' )
	    cmd = f.readlines()[0]
	    # not an ssh tunnel command
	    if ('-L' not in cmd) and (':' not in cmd):
		# do not list it
		#print cmd
		continue
	    else:
		sshhost = cmd.split(':')[1]
	    f.close()

	    # autossh parent
	    f = open( '/proc/' + str(sshpid) + '/status' )
	    lpid = [i for i in f.readlines() if 'PPid' in i]
	    f.close()

	    ppid = int(lpid[0].split(':')[1].strip())

	    f = open( '/proc/' + str(ppid) + '/cmdline' )
	    autohost = f.readlines()[0].split(':')[1]
	    f.close()

	    # instanciation
	    t = SSHTunnel( local_addr, local_port, foreign_addr, foreign_port, autohost, status, sshpid, ppid )

	    for i in autosshs:
		if i['pid'] == ppid:
		    i['tunnels'] += [t]

	    #tunnels += [ t ]

	#print autosshs
	return autosshs


#################################################################################################
# INTERFACES
#################################################################################################

import curses
import time
import signal

class monitorCurses:
    def __init__(self, scr):
	self.scr = scr
	self.tm = AutoSSHTunnelMonitor()

	self.cur_line = -1
	self.cur_pid = -1
	self.show_tunnels = False

	self.update_delay = 1 # seconds of delay between two updates
	self.ui_delay = 0.05 # seconds between two loops
	
	self.colors_autossh = {'pid':0, 'local_port':3, 'target_host':2, 'foreign_port':3, 'tunnels_nb':4, 'tunnels_nb_none':1}
	self.colors_highlight = {'pid':9, 'local_port':9, 'target_host':9, 'foreign_port':9, 'tunnels_nb':9, 'tunnels_nb_none':9}
	self.colors_ssh = {'ssh_pid':0, 'status':4, 'status_out':1, 'local_address':2, 'local_port':3, 'foreign_address':2, 'foreign_port':3}


    def __call__(self):

	self.scr.clear()
	self.scr.nodelay(1) # non-bloking getch

	self.display()

	last_update = time.clock()

	while(1):

	    time.sleep( self.ui_delay )

	    # if its time to update
	    if time.time() > last_update + self.update_delay:
		self.tm.update()
		last_update = time.time()
	    

	    kc = self.scr.getch() # keycode
		    
	    if kc != -1: # if keypress
		pass

	    if 0 < kc < 256: # if ascii key
		ch = chr(kc)

		if ch in 'Qq':
		    break
		elif ch in 'rR':
		    if self.cur_pid != -1:
			os.kill( self.cur_pid, signal.SIGUSR1 )

		elif ch in 'kK':
		    if self.cur_pid != -1:
			os.kill( self.cur_pid, signal.SIGKILL )
		elif ch in 'tT':
		    self.show_tunnels = not self.show_tunnels


	    elif kc == curses.KEY_DOWN:
		if self.cur_line < len(self.tm)-1:
		    self.cur_line += 1
		    self.cur_pid = int(self.tm[self.cur_line]['pid'])

	    elif kc == curses.KEY_UP:
		if self.cur_line > -1:
		    self.cur_line -= 1
		    self.cur_pid = int(self.tm[self.cur_line]['pid'])

	    else:
		pass

	    self.display()
	    self.scr.refresh()


    def display(self):
	self.scr.addstr(0,0, "[R]:reload autossh [K]:kill autossh [Q]:quit [T]:show tunnels connections\n", curses.color_pair(4) )
	self.scr.addstr( "Active AutoSSH instances: ", curses.color_pair(6) )
	self.scr.addstr( str( len(self.tm) ), curses.color_pair(1) )
	self.scr.addstr( '\n', curses.color_pair(1) )
	self.scr.clrtoeol()

	color = 0
	if self.cur_line==-1:
	    color = 9
	    self.cur_pid = -1

	self.scr.addstr( "PID \tINPORT\tHOST              \tOUTPORT\tCONNECTIONS", curses.color_pair(color) )
	self.scr.clrtoeol()

	for l in xrange(len(self.tm)):
	    self.add_autossh( l )
	    
	    if self.show_tunnels:
		self.add_tunnel( l )

	self.scr.clrtobot()


    def add_tunnel(self, line ):
	colors = self.colors_ssh

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
	    if t['status'] != 'ESTABLISHED':
		color = self.colors_ssh['status_out']

	    self.scr.addstr( str( t['status'] ), curses.color_pair( color ) )

	    self.scr.clrtoeol()


    def add_autossh(self, line):
	self.scr.addstr( '\n' )
	#self.scr.addstr( l+2, 0, '' )
	self.add_autossh_info('pid', line)
	self.add_autossh_info('local_port', line)
	self.add_autossh_info('target_host', line)
	self.add_autossh_info('foreign_port', line)
	
	nb = len(self.tm[line]['tunnels'] )
	if nb > 0:
	    #self.scr.addstr( "%i:" % nb, curses.color_pair(self.colors_autossh['tunnels_nb']) )
	    for i in self.tm[line]['tunnels']:
		if i['status'] == 'ESTABLISHED':
		    self.scr.addstr( '|', curses.color_pair(self.colors_ssh['status']) )
		else:
		    self.scr.addstr( '|', curses.color_pair(self.colors_ssh['status_out']) )

	else:
	    self.scr.addstr( 'None', curses.color_pair(self.colors_autossh['tunnels_nb_none']) )

	self.scr.clrtoeol()


    def add_autossh_info( self, key, line ):
	colors = self.colors_autossh
	if self.cur_line == line:
	    colors =  self.colors_highlight

	txt = str(self.tm[line][key])
	if key == 'target_host':
	    txt = str(self.tm[line][key]).ljust(20)[:20]

	self.scr.addstr( txt, curses.color_pair(colors[key]) )
	self.scr.addstr( '\t', curses.color_pair(colors[key])  )



if __name__ == "__main__":
    import sys

    # CURSES
    if len(sys.argv) > 1 and sys.argv[1] == "--curses":
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

	    mc = monitorCurses( scr )
	    mc()

	    scr.keypad(0)
	    curses.echo()
	    curses.nocbreak()
	    curses.endwin()

	except:
	    scr.keypad(0)
	    curses.echo()
	    curses.nocbreak()
	    curses.endwin()
	    traceback.print_exc()

    # CLI
    else:
	tm = AutoSSHTunnelMonitor()
	print tm

